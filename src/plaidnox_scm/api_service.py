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

from . import attempts, context_store, triage
from .api_models import (
    FindingEvidence,
    PolicyAction,
    PromoteBaselineResponse,
    ReviewAttemptStatus,
    ReviewFinding,
    ReviewRequest,
    ReviewResponse,
    TriageResponse,
    TriageStatus,
)
from .assets import load_json
from .baseline import FindingBaselineClassification
from .baseline_models import BaselineFinding
from .evidence import EvidenceRole
from .policy import evaluate_merge_policy
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

_POLICY_ACTIONS = {
    "PASS": PolicyAction.ALLOW,
    "WARN": PolicyAction.WARN,
    "BLOCK": PolicyAction.BLOCK,
    "REQUIRE_SECURITY_APPROVAL": PolicyAction.REQUIRE_SECURITY_APPROVAL,
    "INCOMPLETE": PolicyAction.INCOMPLETE,
}

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
        if completed:
            self._record_fix_validations(tenant_id, review_id, result)
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

    def apply_triage_command(
        self,
        review_id: str,
        finding_id: str,
        command: str,
        *,
        actor: str,
        reason: str | None,
    ) -> TriageResponse | None:
        """Applies one triage command, keyed on the finding rather than this review.

        `finding_id` is deliberately not checked against this `review_id`'s
        own persisted `attempt.findings`: `baseline.py`'s
        `classify_against_baseline()` can leave a still-open finding at
        `verification_state == "baseline"` when a review's coverage did not
        happen to re-verify it, and `_response()` only ever appends
        `"verified"` findings to `attempt.findings` -- so a real, previously
        established finding can legitimately be absent from one review's
        list while still needing to be triageable against it.
        """

        with attempts.unit_of_work(self.session_factory, tenant_id="") as repository:
            attempt = repository.get(review_id)
        if attempt is None:
            return None

        with triage.unit_of_work(self.session_factory, attempt.tenant_id) as repository:
            outcome = repository.apply_command(finding_id, review_id, command, actor=actor, reason=reason)
        reevaluated = self._reevaluate_policy(attempt)
        return TriageResponse(
            finding_id=finding_id,
            review_id=review_id,
            state=outcome.triage.state,
            previous_state=outcome.previous_state,
            actor=outcome.triage.actor,
            reason=outcome.triage.reason,
            applied=outcome.applied,
            updated_at=outcome.triage.updated_at,
            review_action=reevaluated[0] if reevaluated else None,
            review_summary=reevaluated[1] if reevaluated else None,
        )

    def _reevaluate_policy(self, attempt: attempts.ReviewAttempt) -> tuple[PolicyAction, str] | None:
        """Recomputes a completed review's merge action against current triage states.

        Only the persisted verified findings can carry a non-PASS decision
        (baseline-only and unverified classifications always PASS), so the
        policy over `attempt.findings` reproduces the original decision
        exactly, now with triage applied. An INCOMPLETE review is left alone:
        triage never substitutes for missing coverage.
        """

        if attempt.state != "completed" or attempt.action in (None, PolicyAction.INCOMPLETE.value):
            return None
        classifications = tuple(_classification_from_finding(item) for item in attempt.findings)
        with triage.unit_of_work(self.session_factory, attempt.tenant_id) as repository:
            states = repository.get_states(item.finding_fingerprint for item in classifications)
        policy = evaluate_merge_policy(classifications, coverage_complete=True, triage_states=states)
        action = _POLICY_ACTIONS[policy.decision]
        counters = {**(attempt.counters or {}), "blocking": policy.blocking_count, "in_triage": policy.in_triage_count}
        summary = _summary_text(policy.decision, len(attempt.findings), policy.blocking_count, policy.in_triage_count)
        with attempts.unit_of_work(self.session_factory, attempt.tenant_id) as repository:
            repository.update_policy(attempt.review_id, action=action.value, summary=summary, counters=counters)
        return action, summary

    def _record_fix_validations(self, tenant_id: str, review_id: str, result: ReviewResult) -> None:
        """A later review's independent classification is the only fix validation.

        `RESOLVED` proves the root cause is gone at this revision; a finding
        re-verified while `fix_pending` proves the claimed fix did not land.
        """

        with triage.unit_of_work(self.session_factory, tenant_id) as repository:
            for item in result.baseline_classifications:
                if item.relationship == "RESOLVED":
                    repository.record_fix_validation(item.finding_fingerprint, review_id, resolved=True)
                elif item.verification_state == "verified":
                    repository.record_fix_validation(item.finding_fingerprint, review_id, resolved=False)

    def get_triage(self, review_id: str, finding_id: str) -> TriageStatus | None:
        with attempts.unit_of_work(self.session_factory, tenant_id="") as repository:
            attempt = repository.get(review_id)
        if attempt is None:
            return None

        with triage.unit_of_work(self.session_factory, attempt.tenant_id) as repository:
            current = repository.get(finding_id)
        if current is None:
            return TriageStatus(finding_id=finding_id, review_id=review_id, state=triage.OPEN)
        return TriageStatus(
            finding_id=finding_id,
            review_id=review_id,
            state=current.state,
            actor=current.actor,
            reason=current.reason,
            updated_at=current.updated_at,
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

    action = _POLICY_ACTIONS[result.policy.decision]
    incomplete_reason = None
    if action is PolicyAction.INCOMPLETE:
        reasons = (*result.coverage_gaps, *result.policy.reasons)
        incomplete_reason = " ".join(dict.fromkeys(value.strip() for value in reasons if value.strip())) or result.detail
    return ReviewResponse(
        review_id=_review_id(request),
        head_sha=request.head_sha,
        action=action,
        summary=_summary_text(
            result.policy.decision, len(findings), result.counters.blocking, result.counters.in_triage
        ),
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


def _classification_from_finding(finding: dict[str, object]) -> FindingBaselineClassification:
    return FindingBaselineClassification(
        relationship=str(finding["baseline_relationship"]).upper(),  # type: ignore[arg-type]
        root_cause_fingerprint=str(finding["root_cause_fingerprint"]),
        finding_fingerprint=str(finding["finding_id"]),
        candidate_id=None,
        verification_state="verified",
        baseline_state=None,
        root_cause_path=str(finding["root_cause_path"]),
        root_cause_symbol=str(finding["root_cause_symbol"]),
        vulnerability_class=str(finding.get("category") or ""),
        title=str(finding["title"]),
        severity=str(finding["severity"]),
        confidence=float(finding["confidence"]),  # type: ignore[arg-type]
        root_cause_changed_in_review=bool(finding["root_cause_changed_in_pr"]),
        reason="Rebuilt from the persisted verified finding for triage re-evaluation.",
    )


def _summary_text(decision: str, finding_count: int, blocking: int, in_triage: int) -> str:
    if decision == "INCOMPLETE":
        return "Security review could not be completed with full confidence in the available context."
    if not finding_count:
        return "No security findings found."
    if blocking or in_triage:
        return f"{finding_count} verified finding(s): {blocking} blocking, {in_triage} requiring triage."
    return f"{finding_count} verified finding(s) reported; none require merge action."
