"""Application service adapting the SCM review engine to its HTTP contract."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.orm import Session, sessionmaker

from plaidnox_sast.redaction import redact

from . import attempts, context_store
from .api_models import (
    FindingEvidence,
    PolicyAction,
    PromoteBaselineResponse,
    ReviewAttemptStatus,
    ReviewFinding,
    ReviewRequest,
    ReviewResponse,
)
from .assets import load_json
from .baseline_models import BaselineFinding
from .evidence import EvidenceRole
from .production import ReviewDependencies
from .review import ReviewResult, review_pull_request
from .source_broker import SourceBroker

DependenciesFactory = Callable[[], ReviewDependencies]


class ReviewNotCompletedError(RuntimeError):
    """Raised when baseline promotion is requested for an attempt that never reached `"completed"`."""


class _LeaseHeartbeat:
    """Renews a review attempt's lease while a scan is still running.

    A single fixed lease long enough to cover the slowest possible scan
    would also be slow to reclaim from a genuinely dead worker. Renewing a
    short lease on a heartbeat gets both: fast reclaim on a crash, and no
    ceiling on how long a healthy scan may run.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        tenant_id: str,
        review_id: str,
        lease_owner: str,
        lease_seconds: int,
        heartbeat_seconds: float,
    ) -> None:
        self._session_factory = session_factory
        self._tenant_id = tenant_id
        self._review_id = review_id
        self._lease_owner = lease_owner
        self._lease_seconds = lease_seconds
        self._heartbeat_seconds = heartbeat_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()

    def _run(self) -> None:
        while not self._stop.wait(self._heartbeat_seconds):
            with attempts.unit_of_work(self._session_factory, self._tenant_id) as repository:
                repository.renew(self._review_id, self._lease_owner, self._lease_seconds)

_COUNTER_FIELDS = (
    "candidates_generated",
    "evaluated",
    "verified",
    "rejected",
    "unresolved",
    "introduced",
    "regressed",
    "modified_existing",
    "existing",
    "resolved",
    "in_triage",
    "blocking",
)


@dataclass(frozen=True, slots=True)
class ReviewService:
    source_broker: SourceBroker
    session_factory: sessionmaker[Session]
    dependencies_factory: DependenciesFactory

    def run(self, request: ReviewRequest) -> ReviewResponse:
        review_id = _review_id(request)
        tenant_id = _tenant_id(request)
        codebase_id = f"{request.provider}:repository:{request.repository_id}"
        runtime = load_json("runtime/review.json")
        lease_owner = uuid4().hex

        with attempts.unit_of_work(self.session_factory, tenant_id) as repository:
            attempt = repository.claim(
                review_id,
                codebase_id,
                provider=request.provider,
                repository_id=request.repository_id,
                review_number=request.review_number,
                base_sha=request.base_sha,
                head_sha=request.head_sha,
                delivery_id=request.delivery_id,
                lease_owner=lease_owner,
                lease_seconds=int(runtime["review_attempt_lease_seconds"]),
                max_attempts=int(runtime["review_attempt_max_attempts"]),
            )
        if attempt.state == "completed":
            return _replay_response(attempt)

        heartbeat = _LeaseHeartbeat(
            self.session_factory,
            tenant_id,
            review_id,
            lease_owner,
            int(runtime["review_attempt_lease_seconds"]),
            float(runtime["review_attempt_heartbeat_seconds"]),
        )
        heartbeat.start()
        try:
            try:
                with self.source_broker.materialize(request) as source:
                    result = review_pull_request(
                        source.repo_path,
                        source.base_revision,
                        source.head_revision,
                        codebase_id,
                        tenant_id,
                        self.session_factory,
                    )
                    if result.outcome == "configuration_required":
                        dependencies = self.dependencies_factory()
                        result = review_pull_request(
                            source.repo_path,
                            source.base_revision,
                            source.head_revision,
                            codebase_id,
                            tenant_id,
                            self.session_factory,
                            context_builder=dependencies.context_builder,
                            l1_reviewer=dependencies.l1_reviewer,
                            candidate_verifier=dependencies.candidate_verifier,
                        )
            except Exception as exc:
                with attempts.unit_of_work(self.session_factory, tenant_id) as repository:
                    repository.fail(
                        review_id,
                        lease_owner,
                        error_type=type(exc).__name__,
                        error_message=redact(str(exc)),
                    )
                raise
        finally:
            heartbeat.stop()

        response = _response(request, result)
        with attempts.unit_of_work(self.session_factory, tenant_id) as repository:
            completed = repository.complete(
                review_id,
                lease_owner,
                outcome=result.outcome,
                action=response.action.value,
                summary=response.summary,
                incomplete_reason=response.incomplete_reason,
                counters=_counters_dict(result.counters),
                findings=[finding.model_dump(mode="json") for finding in response.findings],
            )
        if not completed:
            # Another worker's reclaim already won the lease -- e.g. this one
            # stalled past its lease and a duplicate delivery took over. That
            # worker's result is the one of record; this result must not be
            # published, so surface it as the same 409 a live conflict gets.
            raise attempts.ReviewAttemptConflictError(
                f"review {review_id} lease was lost before completion"
            )
        return response

    def promote_to_baseline(self, review_id: str, merge_revision: str) -> PromoteBaselineResponse | None:
        """Promotes a merged review's still-open findings into the persistent baseline.

        Called once the reviewed pull/merge request has actually merged (a
        provider webhook adapter reacting to a "merged" event), so a later
        review with `base_sha == merge_revision` sees these findings as
        already `existing` instead of re-flagging them as newly
        `introduced`. `attempt.findings` already excludes anything
        `review.py`'s baseline classification resolved to `RESOLVED` --
        `_response()` only ever appends `verification_state == "verified"`
        findings -- so nothing here needs to re-filter by relationship or
        carry resolved findings forward.
        """

        with attempts.unit_of_work(self.session_factory, tenant_id="") as repository:
            attempt = repository.get(review_id)
        if attempt is None:
            return None
        if attempt.state != "completed":
            raise ReviewNotCompletedError(f"review {review_id} has not completed yet")

        with context_store.unit_of_work(self.session_factory, attempt.tenant_id) as repository:
            for finding in attempt.findings:
                repository.upsert_baseline_finding(
                    BaselineFinding(
                        codebase_id=attempt.codebase_id,
                        baseline_revision=merge_revision,
                        root_cause_fingerprint=finding["root_cause_fingerprint"],
                        finding_fingerprint=finding["finding_id"],
                        lifecycle_state="open",
                        root_cause_path=finding["root_cause_path"],
                        root_cause_symbol=finding["root_cause_symbol"],
                        vulnerability_class=finding["category"] or "",
                        title=finding["title"],
                        severity=finding["severity"],
                        confidence=finding["confidence"],
                    )
                )

        return PromoteBaselineResponse(
            review_id=review_id,
            codebase_id=attempt.codebase_id,
            baseline_revision=merge_revision,
            promoted_count=len(attempt.findings),
        )

    def get_status(self, review_id: str) -> ReviewAttemptStatus | None:
        with attempts.unit_of_work(self.session_factory, tenant_id="") as repository:
            attempt = repository.get(review_id)
        if attempt is None:
            return None
        return ReviewAttemptStatus(
            review_id=attempt.review_id,
            state=attempt.state,
            outcome=attempt.outcome,
            action=attempt.action,
            summary=attempt.summary,
            counters=attempt.counters,
            attempt_count=attempt.attempt_count,
            started_at=attempt.started_at,
            completed_at=attempt.completed_at,
        )


def _counters_dict(counters: object) -> dict[str, int]:
    return {name: int(getattr(counters, name, 0)) for name in _COUNTER_FIELDS}


def _replay_response(attempt: attempts.ReviewAttempt) -> ReviewResponse:
    return ReviewResponse(
        review_id=attempt.review_id,
        head_sha=attempt.head_sha,
        action=PolicyAction(attempt.action),
        summary=attempt.summary or "",
        findings=[ReviewFinding.model_validate(item) for item in attempt.findings],
        incomplete_reason=attempt.incomplete_reason,
        counters=attempt.counters,
    )


def _response(request: ReviewRequest, result: ReviewResult) -> ReviewResponse:
    candidate_by_id = {item.candidate_id: item for item in result.candidates}
    verification_by_id = {item.candidate_id: item for item in result.verifications}
    findings: list[ReviewFinding] = []
    for classification in result.baseline_classifications:
        if classification.verification_state != "verified" or classification.candidate_id is None:
            continue
        candidate = candidate_by_id.get(classification.candidate_id)
        verification = verification_by_id.get(classification.candidate_id)
        if candidate is None or verification is None:
            continue
        findings.append(
            ReviewFinding(
                finding_id=classification.finding_fingerprint,
                root_cause_fingerprint=classification.root_cause_fingerprint,
                title=redact(classification.title),
                severity=classification.severity.lower(),
                confidence=classification.confidence,
                description=redact(verification.message.strip()),
                impact=redact(verification.business_impact.strip()) or None,
                root_cause_path=classification.root_cause_path,
                root_cause_symbol=classification.root_cause_symbol,
                root_cause_start_line=candidate.changed_lines.start,
                root_cause_end_line=candidate.changed_lines.end,
                root_cause_changed_in_pr=classification.root_cause_changed_in_review,
                proof_of_concept=None,
                remediation=redact(verification.remediation.strip()) or None,
                remediation_invariant=redact(verification.security_invariant.strip()) or None,
                proof_plan=redact(verification.proof_plan.strip()) or None,
                regression_test_expectation=redact(verification.regression_test.strip()) or None,
                category=classification.vulnerability_class,
                baseline_relationship=classification.relationship.lower(),
                tenant_id=_tenant_id(request),
                repository_id=request.repository_id,
                base_revision=request.base_sha,
                head_revision=request.head_sha,
                attacker_origin=_evidence_summary(verification.evidence, EvidenceRole.ATTACKER_ORIGIN),
                security_boundary=_evidence_summary(verification.evidence, EvidenceRole.SECURITY_BOUNDARY),
                defense_removed_or_bypassed=_evidence_summary(
                    verification.evidence, EvidenceRole.DEFENSE_REMOVED_OR_BYPASSED
                ),
                downstream_trust=_evidence_summary(verification.evidence, EvidenceRole.DOWNSTREAM_TRUST),
                sensitive_effects=[
                    redact(item.summary.strip())
                    for item in verification.evidence
                    if item.role == EvidenceRole.SENSITIVE_EFFECT and item.summary.strip()
                ],
                capabilities=_capabilities(candidate, verification),
                evidence=[
                    FindingEvidence(
                        role=item.role.value,
                        source=item.source,
                        path=item.path,
                        start_line=item.start_line,
                        end_line=item.end_line,
                        summary=redact(item.summary),
                    )
                    for item in verification.evidence
                ],
                context_facts=[redact(fact) for fact in candidate.context_facts_used],
                evidence_gaps=[redact(gap) for gap in verification.evidence_gaps],
                verified_at=datetime.now(UTC),
            )
        )

    action = {
        "PASS": PolicyAction.ALLOW,
        "WARN": PolicyAction.WARN,
        "BLOCK": PolicyAction.BLOCK,
        "REQUIRE_SECURITY_APPROVAL": PolicyAction.REQUIRE_SECURITY_APPROVAL,
        "INCOMPLETE": PolicyAction.INCOMPLETE,
    }[result.policy.decision]
    incomplete_reason = None
    if action is PolicyAction.INCOMPLETE:
        reasons = (*result.coverage_gaps, *result.policy.reasons)
        incomplete_reason = " ".join(dict.fromkeys(value.strip() for value in reasons if value.strip())) or result.detail
    return ReviewResponse(
        review_id=_review_id(request),
        head_sha=request.head_sha,
        action=action,
        summary=_summary(result, len(findings)),
        findings=findings,
        incomplete_reason=incomplete_reason,
        counters=_counters_dict(result.counters),
    )


def _tenant_id(request: ReviewRequest) -> str:
    return f"{request.provider}:installation:{request.installation_id}"


def _evidence_summary(evidence: object, role: EvidenceRole) -> str | None:
    for item in evidence:
        if item.role == role and item.summary.strip():
            return redact(item.summary.strip())
    return None


def _capabilities(candidate: object, verification: object) -> list[str]:
    raw = (verification.gained_capability, candidate.provisional_attacker_capability)
    return list(dict.fromkeys(redact(value.strip()) for value in raw if value and value.strip()))


def _review_id(request: ReviewRequest) -> str:
    # `base_sha` is part of the identity, not just `head_sha`: if the target
    # branch advances while the same PR head is still open, `base...head`
    # names a different diff and must get its own review, not a replay of
    # the review completed against the old base.
    identity = ":".join(
        (
            request.provider,
            str(request.installation_id),
            str(request.repository_id),
            str(request.review_number),
            request.base_sha.lower(),
            request.head_sha.lower(),
        )
    )
    return f"review_{hashlib.sha256(identity.encode()).hexdigest()[:24]}"


def _summary(result: ReviewResult, finding_count: int) -> str:
    decision = result.policy.decision
    counts = result.counters
    if decision == "INCOMPLETE":
        return "PlaidNox Security review is incomplete. No PASS was issued."
    if finding_count:
        return (
            f"{finding_count} verified finding(s): {counts.blocking} blocking, "
            f"{counts.in_triage} requiring triage. Policy decision: {decision}."
        )
    return f"No new verified finding requires merge action. Policy decision: {decision}."
