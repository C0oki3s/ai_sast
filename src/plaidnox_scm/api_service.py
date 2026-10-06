"""Application service adapting the SCM review engine to its HTTP contract."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from plaidnox_sast.redaction import redact
from plaidnox_sast.llm import tenant_cache_namespace

from . import attempts, context_store, triage
from .api_models import (
    FindingEvidence,
    FindingReproduction,
    FindingRootCause,
    FindingTrace,
    FindingTraceEdge,
    FindingTraceNode,
    PolicyAction,
    PromoteBaselineResponse,
    ReviewAttemptStatus,
    ReviewFinding,
    ReviewRequest,
    ReviewResponse,
    TriageResponse,
    TriageStatus,
    VulnerableSnippet,
)
from .assets import load_json
from .baseline import FindingBaselineClassification
from .baseline_models import BaselineFinding
from .evidence import EvidenceRole
from .models import ActivityEventRecord, InstallationTenantRecord, WebhookDeliveryRecord
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
        tenant_id = self.resolve_tenant(request.provider, request.installation_id)
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

        _record_review_activity(
            self.session_factory,
            tenant_id=tenant_id,
            request=request,
            review_id=review_id,
            event_type="review_started",
            idempotency_key=f"{review_id}:attempt:{attempt.attempt_count}:started",
        )

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
                with (
                    tenant_cache_namespace(tenant_id),
                    self.source_broker.materialize(request) as source,
                ):
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
                _record_review_activity(
                    self.session_factory,
                    tenant_id=tenant_id,
                    request=request,
                    review_id=review_id,
                    event_type="review_failed",
                    idempotency_key=f"{review_id}:attempt:{attempt.attempt_count}:failed",
                )
                raise
        finally:
            heartbeat.stop()

        response = _response(request, result, tenant_id)
        application_context = getattr(result, "application_context", None)
        if application_context is not None:
            _record_review_activity(
                self.session_factory,
                tenant_id=tenant_id,
                request=request,
                review_id=review_id,
                event_type="context_indexed",
                idempotency_key=(
                    f"context:{codebase_id}:{application_context.baseline_revision}:"
                    f"{application_context.source_tree_hash}"
                ),
            )
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
            event_type = "review_incomplete" if response.action is PolicyAction.INCOMPLETE else "review_completed"
            _record_review_activity(
                self.session_factory,
                tenant_id=tenant_id,
                request=request,
                review_id=review_id,
                event_type=event_type,
                idempotency_key=f"{review_id}:attempt:{attempt.attempt_count}:{event_type}",
            )
        if not completed:
            raise attempts.ReviewAttemptConflictError(
                f"review {review_id} lease was lost before completion"
            )
        return response

    def claim_webhook_delivery(
        self,
        *,
        delivery_id: str,
        provider: str,
        installation_id: int,
        repository_id: int,
        event_name: str,
        action: str | None,
        pull_number: int | None = None,
        head_sha: str | None = None,
    ) -> tuple[bool, str]:
        """Persist a verified delivery before the bot acknowledges it to GitHub."""
        tenant_id = self.resolve_tenant(provider, installation_id)
        with self.session_factory.begin() as session:
            inserted = False
            try:
                with session.begin_nested():
                    session.add(
                        WebhookDeliveryRecord(
                            delivery_id=delivery_id,
                            provider=provider,
                            installation_id=installation_id,
                            repository_id=repository_id,
                            event_name=event_name,
                            action=action,
                            tenant_id=tenant_id,
                            state="accepted",
                        )
                    )
                    session.flush()
                inserted = True
            except IntegrityError:
                session.expire_all()

            existing = session.scalar(
                select(WebhookDeliveryRecord)
                .where(WebhookDeliveryRecord.delivery_id == delivery_id)
                .with_for_update()
            )
            if existing is None:
                raise RuntimeError("webhook delivery claim disappeared during insert")
            identity = (
                existing.provider,
                existing.installation_id,
                existing.repository_id,
                existing.event_name,
                existing.action,
                existing.tenant_id,
            )
            expected_identity = (
                provider,
                installation_id,
                repository_id,
                event_name,
                action,
                tenant_id,
            )
            if identity != expected_identity:
                raise PermissionError("delivery identifier is already bound to a different event")

            if inserted and event_name == "pull_request":
                event_type = _pr_activity_type(action)
                if event_type:
                    session.add(
                        _activity_record(
                            tenant_id=tenant_id,
                            provider=provider,
                            repository_id=repository_id,
                            installation_id=installation_id,
                            pull_number=pull_number,
                            head_sha=head_sha,
                            event_type=event_type,
                            idempotency_key=f"github:{delivery_id}:{event_type}",
                        )
                    )
            accepted = inserted or existing.state != "queued"
        return accepted, tenant_id

    def mark_webhook_delivery_queued(self, delivery_id: str) -> bool:
        with self.session_factory.begin() as session:
            row = session.get(WebhookDeliveryRecord, delivery_id)
            if row is None:
                return False
            row.state = "queued"
            if row.event_name == "pull_request" and row.action in {
                "opened",
                "reopened",
                "ready_for_review",
                "synchronize",
            }:
                source = session.scalar(
                    select(ActivityEventRecord)
                    .where(
                        ActivityEventRecord.idempotency_key.in_(
                            [
                                f"github:{delivery_id}:pr_opened",
                                f"github:{delivery_id}:pr_updated",
                            ]
                        )
                    )
                    .limit(1)
                )
                session.add(
                    _activity_record(
                        tenant_id=row.tenant_id,
                        provider=row.provider,
                        repository_id=row.repository_id,
                        installation_id=row.installation_id,
                        pull_number=source.pull_number if source else None,
                        head_sha=source.head_sha if source else None,
                        event_type="review_queued",
                        idempotency_key=f"github:{delivery_id}:review_queued",
                    )
                )
        return True

    def update_installation_status(self, *, provider: str, installation_id: int, active: bool) -> bool:
        with self.session_factory.begin() as session:
            mapping = session.get(InstallationTenantRecord, (provider, installation_id))
            if mapping is None:
                return False
            mapping.active = active
        return True

    def record_review_superseded(
        self,
        *,
        provider: str,
        installation_id: int,
        repository_id: int,
        review_number: int,
        review_id: str,
        head_sha: str,
    ) -> None:
        tenant_id = self.resolve_tenant(provider, installation_id)
        with self.session_factory.begin() as session:
            session.merge(
                _activity_record(
                    tenant_id=tenant_id,
                    provider=provider,
                    repository_id=repository_id,
                    installation_id=installation_id,
                    pull_number=review_number,
                    review_id=review_id,
                    head_sha=head_sha,
                    event_type="review_superseded",
                    idempotency_key=f"{review_id}:superseded",
                )
            )

    def record_review_failed(self, request: ReviewRequest) -> None:
        tenant_id = self.resolve_tenant(request.provider, request.installation_id)
        review_id = _review_id(request)
        with self.session_factory.begin() as session:
            session.merge(
                _activity_record(
                    tenant_id=tenant_id,
                    provider=request.provider,
                    repository_id=request.repository_id,
                    installation_id=request.installation_id,
                    pull_number=request.review_number,
                    review_id=review_id,
                    head_sha=request.head_sha,
                    event_type="review_failed",
                    idempotency_key=f"{review_id}:failed",
                )
            )

    def resolve_tenant(self, provider: str, installation_id: int) -> str:
        with self.session_factory() as session:
            mapping = session.get(InstallationTenantRecord, (provider, installation_id))
        if mapping is None or not mapping.active:
            raise PermissionError("GitHub installation is not linked to an active product organization")
        return mapping.tenant_id

    def promote_to_baseline(self, review_id: str, merge_revision: str) -> PromoteBaselineResponse | None:
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
        if attempt.state != "completed" or attempt.action in (None, PolicyAction.INCOMPLETE.value):
            return None
        classifications = tuple(_classification_from_finding(item) for item in attempt.findings)
        with triage.unit_of_work(self.session_factory, attempt.tenant_id) as repository:
            states = repository.get_states(item.finding_fingerprint for item in classifications)
        policy = evaluate_merge_policy(classifications, coverage_complete=True, triage_states=states)
        action = _POLICY_ACTIONS[policy.decision]
        counters = {
            **(attempt.counters or {}),
            "blocking": policy.blocking_count,
            "in_triage": policy.in_triage_count,
        }
        summary = _summary_text(
            policy.decision,
            len(attempt.findings),
            policy.blocking_count,
            policy.in_triage_count,
        )
        with attempts.unit_of_work(self.session_factory, attempt.tenant_id) as repository:
            repository.update_policy(
                attempt.review_id,
                action=action.value,
                summary=summary,
                counters=counters,
            )
        return action, summary

    def _record_fix_validations(self, tenant_id: str, review_id: str, result: ReviewResult) -> None:
        with triage.unit_of_work(self.session_factory, tenant_id) as repository:
            for item in result.baseline_classifications:
                if item.relationship == "RESOLVED":
                    repository.record_fix_validation(
                        item.finding_fingerprint,
                        review_id,
                        resolved=True,
                    )
                elif item.verification_state == "verified":
                    repository.record_fix_validation(
                        item.finding_fingerprint,
                        review_id,
                        resolved=False,
                    )

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


def _response(request: ReviewRequest, result: ReviewResult, tenant_id: str) -> ReviewResponse:
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

        proof_plan = _optional_verification_text(verification, "proof_plan")
        regression_test = _optional_verification_text(verification, "regression_test")
        security_invariant = _optional_verification_text(verification, "security_invariant")
        gained_capability = _optional_verification_text(verification, "gained_capability")
        attack_path = _optional_verification_text(verification, "attack_path")
        vulnerable_snippet = _api_vulnerable_snippet(
            getattr(verification, "vulnerable_snippet", None)
        )
        evidence_trace = _api_evidence_trace(getattr(verification, "evidence_trace", None))
        rich_evidence = vulnerable_snippet is not None or evidence_trace is not None

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
                root_cause=(
                    FindingRootCause(
                        path=classification.root_cause_path,
                        symbol=classification.root_cause_symbol,
                        start_line=candidate.changed_lines.start,
                        end_line=candidate.changed_lines.end,
                        changed_in_pr=classification.root_cause_changed_in_review,
                    )
                    if rich_evidence
                    else None
                ),
                vulnerable_snippet=vulnerable_snippet,
                evidence_trace=evidence_trace,
                attack_path=attack_path if rich_evidence else None,
                security_invariant=security_invariant if rich_evidence else None,
                gained_capability=gained_capability if rich_evidence else None,
                reproduction=(
                    FindingReproduction(
                        proof_plan=proof_plan,
                        regression_test_expectation=regression_test,
                    )
                    if rich_evidence and (proof_plan or regression_test)
                    else None
                ),
                proof_of_concept=None,
                remediation=redact(verification.remediation.strip()) or None,
                remediation_invariant=security_invariant,
                proof_plan=proof_plan,
                regression_test_expectation=regression_test,
                category=classification.vulnerability_class,
                baseline_relationship=classification.relationship.lower(),
                tenant_id=tenant_id,
                repository_id=request.repository_id,
                base_revision=request.base_sha,
                head_revision=request.head_sha,
                attacker_origin=_evidence_summary(
                    verification.evidence,
                    EvidenceRole.ATTACKER_ORIGIN,
                ),
                security_boundary=_evidence_summary(
                    verification.evidence,
                    EvidenceRole.SECURITY_BOUNDARY,
                ),
                defense_removed_or_bypassed=_evidence_summary(
                    verification.evidence,
                    EvidenceRole.DEFENSE_REMOVED_OR_BYPASSED,
                ),
                downstream_trust=_evidence_summary(
                    verification.evidence,
                    EvidenceRole.DOWNSTREAM_TRUST,
                ),
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
        incomplete_reason = (
            " ".join(dict.fromkeys(value.strip() for value in reasons if value.strip()))
            or result.detail
        )
    return ReviewResponse(
        review_id=_review_id(request),
        head_sha=request.head_sha,
        action=action,
        summary=_summary_text(
            result.policy.decision,
            len(findings),
            result.counters.blocking,
            result.counters.in_triage,
        ),
        findings=findings,
        incomplete_reason=incomplete_reason,
        counters=_counters_dict(result.counters),
    )


def _tenant_id(request: ReviewRequest) -> str:
    return f"{request.provider}:installation:{request.installation_id}"


def _pr_activity_type(action: str | None) -> str | None:
    if action == "opened":
        return "pr_opened"
    if action == "merged":
        return "pr_merged"
    if action == "closed":
        return "pr_closed"
    if action in {"reopened", "ready_for_review", "synchronize", "edited", "converted_to_draft"}:
        return "pr_updated"
    return None


def _activity_record(
    *,
    tenant_id: str,
    provider: str,
    repository_id: int,
    installation_id: int,
    event_type: str,
    idempotency_key: str,
    pull_number: int | None = None,
    review_id: str | None = None,
    head_sha: str | None = None,
) -> ActivityEventRecord:
    labels = {
        "pr_opened": "Pull request opened",
        "pr_updated": "Pull request updated",
        "pr_closed": "Pull request closed",
        "pr_merged": "Pull request merged",
        "review_queued": "Security review queued",
        "review_started": "Security review started",
        "review_completed": "Security review completed",
        "review_incomplete": "Security review incomplete",
        "review_superseded": "Security review superseded",
        "review_failed": "Security review failed",
        "context_indexed": "Application context indexed",
    }
    summary = labels[event_type]
    if pull_number is not None:
        summary = f"{summary} for PR #{pull_number}"
    return ActivityEventRecord(
        event_id=hashlib.sha256(idempotency_key.encode()).hexdigest()[:32],
        tenant_id=tenant_id,
        codebase_id=f"{provider}:repository:{repository_id}",
        provider=provider,
        repository_id=repository_id,
        installation_id=installation_id,
        pull_number=pull_number,
        review_id=review_id,
        head_sha=head_sha,
        event_type=event_type,
        summary=summary,
        metadata_json={},
        idempotency_key=idempotency_key[:255],
    )


def _record_review_activity(
    factory: sessionmaker[Session],
    *,
    tenant_id: str,
    request: ReviewRequest,
    review_id: str,
    event_type: str,
    idempotency_key: str,
) -> None:
    with factory.begin() as session:
        session.merge(
            _activity_record(
                tenant_id=tenant_id,
                provider=request.provider,
                repository_id=request.repository_id,
                installation_id=request.installation_id,
                pull_number=request.review_number,
                review_id=review_id,
                head_sha=request.head_sha,
                event_type=event_type,
                idempotency_key=idempotency_key,
            )
        )


def _optional_verification_text(verification: object, attribute: str) -> str | None:
    value = getattr(verification, attribute, "")
    if value is None:
        return None
    text = str(value).strip()
    return redact(text) or None if text else None


def _evidence_summary(evidence: object, role: EvidenceRole) -> str | None:
    for item in evidence:
        if item.role == role and item.summary.strip():
            return redact(item.summary.strip())
    return None


def _capabilities(candidate: object, verification: object) -> list[str]:
    raw = (getattr(verification, "gained_capability", ""), candidate.provisional_attacker_capability)
    return list(
        dict.fromkeys(redact(value.strip()) for value in raw if value and value.strip())
    )


def _api_vulnerable_snippet(value: object) -> VulnerableSnippet | None:
    if value is None:
        return None
    try:
        code = redact(str(value.content))
        return VulnerableSnippet(
            path=str(value.path),
            start_line=int(value.start_line),
            end_line=int(value.end_line),
            code=code,
            content=code,
        )
    except (AttributeError, TypeError, ValueError):
        return None


def _api_evidence_trace(value: object) -> FindingTrace | None:
    if value is None:
        return None
    try:
        nodes = [
            FindingTraceNode(
                node_id=str(item.node_id),
                role=getattr(item.role, "value", str(item.role)),
                kind=str(item.kind),
                path=str(item.path),
                start_line=item.start_line,
                end_line=item.end_line,
                symbol=redact(str(item.symbol)),
                expression=redact(str(item.expression)),
                label=redact(str(item.label)),
                summary=redact(str(item.summary)),
                provenance=redact(str(item.provenance)),
            )
            for item in value.nodes
        ]
        edges = [
            FindingTraceEdge(
                source=str(item.source),
                target=str(item.target),
                relation=str(item.relation),
                via=redact(str(item.via)),
            )
            for item in value.edges
        ]
        return FindingTrace(
            trace_type=str(getattr(value, "trace_type", "taint_and_trust")),
            step_count=int(getattr(value, "step_count", len(nodes))),
            file_count=int(getattr(value, "file_count", len({item.path for item in nodes}))),
            nodes=nodes,
            edges=edges,
            entry_nodes=[str(item) for item in value.entry_nodes],
            terminal_nodes=[str(item) for item in value.terminal_nodes],
            attack_path=redact(str(value.attack_path)),
            gained_capability=redact(str(value.gained_capability)),
            complete=bool(getattr(value, "complete", True)),
            evidence_gaps=[
                redact(str(item))
                for item in getattr(value, "evidence_gaps", ())
                if str(item).strip()
            ],
        )
    except (AttributeError, TypeError, ValueError):
        return None


def _review_id(request: ReviewRequest) -> str:
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
