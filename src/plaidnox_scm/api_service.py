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

from . import attempts, context_store, occurrences, triage
from .api_models import (
    ClassificationReference,
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
from .baseline import FindingBaselineClassification, prior_findings_from_stored
from .lifecycle import CARRIED_OUTCOMES, FIXED_OUTCOMES, KnownFinding, KnownOutcome, known_from_stored
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
    "duplicates_merged",
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
                base_ref=request.base_ref,
                head_ref=request.head_ref,
                repository_full_name=request.repository_full_name,
                author_login=request.author_login,
                lease_owner=lease_owner,
                lease_seconds=int(runtime["review_attempt_lease_seconds"]),
                max_attempts=int(runtime["review_attempt_max_attempts"]),
            )
        if attempt.state == "completed":
            return _replay_response(attempt)

        with attempts.unit_of_work(self.session_factory, tenant_id) as repository:
            prior_findings = prior_findings_from_stored(
                repository.previous_findings(codebase_id, request.review_number, exclude_review_id=review_id)
            )
        known_findings = self._known_findings(tenant_id, codebase_id, request.review_number, review_id)

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
                def on_stage(name: str, metadata: dict[str, str | int | float | bool]) -> None:
                    _record_review_activity(
                        self.session_factory,
                        tenant_id=tenant_id,
                        request=request,
                        review_id=review_id,
                        event_type=name,
                        idempotency_key=f"{review_id}:attempt:{attempt.attempt_count}:stage:{name}",
                        metadata=metadata,
                    )

                with (
                    tenant_cache_namespace(tenant_id),
                    self.source_broker.materialize(request) as source,
                ):
                    on_stage("snapshot_ready", {
                        "base": source.base_revision[:12],
                        "head": source.head_revision[:12],
                        "head_ref": request.head_ref,
                        "base_ref": request.base_ref,
                    })
                    result = review_pull_request(
                        source.repo_path,
                        source.base_revision,
                        source.head_revision,
                        codebase_id,
                        tenant_id,
                        self.session_factory,
                        on_stage=on_stage,
                        prior_findings=prior_findings,
                        known_findings=known_findings,
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
                            on_stage=on_stage,
                            prior_findings=prior_findings,
                        known_findings=known_findings,
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
        try:
            completed = self._complete_review(
                tenant_id, codebase_id, request, review_id, lease_owner, response, result, attempt.started_at
            )
        except Exception as exc:
            # Nothing was committed: neither the completion nor the finding statuses. Fail the
            # attempt so a retry runs the review again and writes both together.
            with attempts.unit_of_work(self.session_factory, tenant_id) as repository:
                repository.fail(
                    review_id, lease_owner, error_type=type(exc).__name__, error_message=redact(str(exc))
                )
            raise
        if completed:
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
            if inserted and event_name == "pull_request" and action in {"merged", "closed"} and pull_number:
                # Same transaction as the delivery record: if the lifecycle update fails, the
                # delivery is not recorded either, so GitHub's redelivery applies it again.
                _apply_pull_request_close(
                    session,
                    tenant_id,
                    f"{provider}:repository:{repository_id}",
                    pull_number,
                    merged=action == "merged",
                    head_sha=head_sha,
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

    def _known_findings(
        self, tenant_id: str, codebase_id: str, review_number: int, review_id: str
    ) -> tuple[KnownFinding, ...]:
        """Open findings of this PR (from earlier runs) and of the default branch."""

        scope = occurrences.pr_scope(review_number)
        with occurrences.unit_of_work(self.session_factory, tenant_id) as repository:
            pr_known = repository.known(codebase_id, scope)
            tracked = repository.has_scope(codebase_id, scope)
            branch_known = repository.known(codebase_id, occurrences.BRANCH)
        if not tracked:
            # PR reviewed before lifecycle tracking existed: seed from its earlier runs.
            with attempts.unit_of_work(self.session_factory, tenant_id) as repository:
                pr_known = known_from_stored(
                    "pr", list(repository.previous_runs(codebase_id, review_number, exclude_review_id=review_id))
                )
        return (*pr_known, *branch_known)

    def _complete_review(
        self,
        tenant_id: str,
        codebase_id: str,
        request: ReviewRequest,
        review_id: str,
        lease_owner: str,
        response: ReviewResponse,
        result: ReviewResult,
        run_started_at: datetime | None,
    ) -> bool:
        """Completion, triage changes and finding statuses commit together or not at all.

        A completed attempt is replayed as-is on retry, so anything written after the
        completion commit could be lost for good if it failed.
        """

        with self.session_factory.begin() as session:
            completed = attempts.ReviewAttemptRepository(session, tenant_id).complete(
                review_id,
                lease_owner,
                outcome=result.outcome,
                action=response.action.value,
                summary=response.summary,
                incomplete_reason=response.incomplete_reason,
                counters=_counters_dict(result.counters),
                findings=[_stored_finding(finding) for finding in response.findings],
            )
            if completed:
                fix_triage = triage.FindingTriageRepository(session, tenant_id)
                _apply_fix_validations(fix_triage, review_id, result)
                _apply_occurrences(
                    occurrences.FindingOccurrenceRepository(session, tenant_id),
                    fix_triage,
                    codebase_id,
                    request,
                    review_id,
                    response,
                    result,
                    run_started_at,
                )
        return completed

    def _record_fix_validations(self, tenant_id: str, review_id: str, result: ReviewResult) -> None:
        with self.session_factory.begin() as session:
            _apply_fix_validations(triage.FindingTriageRepository(session, tenant_id), review_id, result)

    def _record_occurrences(
        self,
        tenant_id: str,
        codebase_id: str,
        request: ReviewRequest,
        review_id: str,
        response: ReviewResponse,
        result: ReviewResult,
        run_started_at: datetime | None = None,
    ) -> None:
        with self.session_factory.begin() as session:
            _apply_occurrences(
                occurrences.FindingOccurrenceRepository(session, tenant_id),
                triage.FindingTriageRepository(session, tenant_id),
                codebase_id, request, review_id, response, result, run_started_at,
            )

    def close_pull_request(
        self, tenant_id: str, codebase_id: str, review_number: int, *, merged: bool, head_sha: str | None
    ) -> occurrences.MergeOutcome:
        """PR merged: its open findings become default-branch findings and its fixes close them."""

        with self.session_factory.begin() as session:
            return _apply_pull_request_close(
                session, tenant_id, codebase_id, review_number, merged=merged, head_sha=head_sha
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


def _apply_fix_validations(
    repository: triage.FindingTriageRepository, review_id: str, result: ReviewResult
) -> None:
    for item in result.baseline_classifications:
        if item.relationship == "RESOLVED":
            # A default-branch finding fixed in a PR is only fixed on the branch once the PR
            # merges (see _apply_pull_request_close); nothing changes at review time.
            continue
        if item.verification_state == "verified":
            repository.record_fix_validation(item.finding_fingerprint, review_id, resolved=False)


def _apply_occurrences(
    repository: occurrences.FindingOccurrenceRepository,
    fix_triage: triage.FindingTriageRepository,
    codebase_id: str,
    request: ReviewRequest,
    review_id: str,
    response: ReviewResponse,
    result: ReviewResult,
    run_started_at: datetime | None,
) -> None:
    known_outcomes = tuple(getattr(result, "known_outcomes", ()))
    accounted = {item.finding_id for item in known_outcomes}
    # A default-branch finding resolved through the classic baseline path (a matching
    # candidate verified as gone) is recorded the same way, so the merge closes it.
    known_outcomes += tuple(
        KnownOutcome(
            item.finding_fingerprint, "branch", "fixed_verified", item.reason,
            {
                "finding_id": item.finding_fingerprint,
                "root_cause_fingerprint": item.root_cause_fingerprint,
                "root_cause_path": item.root_cause_path,
                "root_cause_symbol": item.root_cause_symbol,
                "title": item.title,
                "severity": item.severity,
                "category": item.vulnerability_class,
            },
        )
        for item in result.baseline_classifications
        if item.relationship == "RESOLVED" and item.finding_fingerprint not in accounted
    )
    carried = {
        item.finding_id for item in known_outcomes
        if item.outcome in CARRIED_OUTCOMES and item.scope == "pr"
    }
    observed = [_stored_finding(finding) for finding in response.findings if finding.finding_id not in carried]
    repository.record_run(
        codebase_id,
        request.review_number,
        review_id=review_id,
        head=request.head_sha,
        observed=observed,
        outcomes=known_outcomes,
        run_started_at=run_started_at,
    )
    for finding in observed:
        # Reported again: a finding resolved earlier has regressed.
        fix_triage.record_regression(str(finding["finding_id"]), review_id)
    for item in known_outcomes:
        # A finding introduced and fixed inside the same PR never reached the default
        # branch, so the PR's own fix settles a `!fixed` claim on it. Otherwise the
        # lifecycle status ("fixed in PR #n") carries the fix.
        if item.scope == "pr" and item.outcome in FIXED_OUTCOMES:
            fix_triage.confirm_claimed_fix(item.finding_id, review_id)


def _apply_pull_request_close(
    session: Session,
    tenant_id: str,
    codebase_id: str,
    review_number: int,
    *,
    merged: bool,
    head_sha: str | None,
) -> occurrences.MergeOutcome:
    outcome = occurrences.FindingOccurrenceRepository(session, tenant_id).close_pull_request(
        codebase_id, review_number, merged=merged, head=head_sha
    )
    if merged:
        fix_triage = triage.FindingTriageRepository(session, tenant_id)
        for finding_id in outcome.resolved:
            fix_triage.confirm_claimed_fix(finding_id, f"merge:pr:{review_number}")
    return outcome


def _response(request: ReviewRequest, result: ReviewResult, tenant_id: str) -> ReviewResponse:
    candidate_by_id = {item.candidate_id: item for item in result.candidates}
    verification_by_id = {item.candidate_id: item for item in result.verifications}
    findings: list[ReviewFinding] = []
    emitted: set[str] = set()
    for classification in result.baseline_classifications:
        if classification.verification_state != "verified" or classification.candidate_id is None:
            continue
        if classification.finding_fingerprint in emitted:
            continue
        candidate = candidate_by_id.get(classification.candidate_id)
        verification = verification_by_id.get(classification.candidate_id)
        if candidate is None or verification is None:
            continue
        emitted.add(classification.finding_fingerprint)

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
                proof_of_concept=_client_proof_of_concept(
                    proof_plan,
                    redact(str(getattr(verification, "proof_of_concept", "")).strip()) or None,
                ),
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
                classification_references=_classification_references(verification),
                verified_at=datetime.now(UTC),
            )
        )

    # Still-open findings from earlier commits of this PR whose code is unchanged (or could
    # not be re-verified) stay in the result: absence from one LLM run is not a fix.
    for outcome in getattr(result, "known_outcomes", ()):
        if outcome.scope != "pr" or outcome.outcome not in CARRIED_OUTCOMES or outcome.finding_id in emitted:
            continue
        try:
            carried = ReviewFinding.model_validate({**outcome.finding, "lifecycle": "carried_forward"})
        except ValueError:
            continue
        emitted.add(outcome.finding_id)
        findings.append(carried)

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
    metadata: dict[str, str | int | float | bool] | None = None,
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
        **_STAGE_LABELS,
    }
    summary = labels[event_type]
    if pull_number is not None and event_type not in _STAGE_LABELS:
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
        metadata_json=_safe_metadata(metadata or {}),
        idempotency_key=idempotency_key[:255],
    )


# Per-run review stages, recorded with the run's review_id so the dashboard can
# draw one run's timeline without mixing in other runs of the same pull request.
_STAGE_LABELS = {
    "snapshot_ready": "Repository snapshot ready",
    "changes_analyzed": "Changed files analyzed",
    "review_skipped": "AI review skipped",
    "context_ready": "Application context ready",
    "candidates_generated": "Changed-code review complete",
    "verification_complete": "Independent verification complete",
    "known_findings_checked": "Earlier findings re-checked",
    "baseline_compared": "Compared against the default branch",
    "policy_evaluated": "Merge policy evaluated",
}


def _safe_metadata(metadata: dict[str, object]) -> dict[str, str | int | float | bool]:
    safe: dict[str, str | int | float | bool] = {}
    for key, value in list(metadata.items())[:24]:
        if isinstance(value, bool | int | float):
            safe[str(key)[:64]] = value
        elif value is not None:
            safe[str(key)[:64]] = redact(str(value))[:500]
    return safe


def _record_review_activity(
    factory: sessionmaker[Session],
    *,
    tenant_id: str,
    request: ReviewRequest,
    review_id: str,
    event_type: str,
    idempotency_key: str,
    metadata: dict[str, str | int | float | bool] | None = None,
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
                metadata=metadata,
            )
        )


def _optional_verification_text(verification: object, attribute: str) -> str | None:
    value = getattr(verification, attribute, "")
    if value is None:
        return None
    text = str(value).strip()
    return redact(text) or None if text else None


def _client_proof_of_concept(proof_plan: str | None, script: str | None) -> str | None:
    """Build one display-ready PoC without asking the model to repeat itself.

    A verified finding always carries a proof plan, so it always gets a PoC: the
    numbered steps, plus the runnable script when the verifier produced one. The
    stored finding drops the separate ``proof_plan`` key, so returning ``None``
    here would lose the reproduction from the database entirely.
    """

    steps_text = proof_plan.strip() if proof_plan and proof_plan.strip() else ""
    if not script or not script.strip():
        return f"### Steps to Reproduce\n\n{steps_text}" if steps_text else None
    lines = script.strip().splitlines()
    if len(lines) >= 2 and lines[0].strip().startswith("```") and lines[-1].strip() == "```":
        lines = lines[1:-1]
    fenced = "\n".join(lines).strip()
    steps = f"{proof_plan.strip()}\n\n" if proof_plan and proof_plan.strip() else ""
    return f"### Steps to Reproduce\n\n{steps}```bash\n{fenced}\n```"


_REDUNDANT_STORED_FINDING_KEYS = frozenset({
    "root_cause",
    "reproduction",
    "proof_plan",
    "security_invariant",
    "gained_capability",
})


def _compact_json(value: object) -> object:
    """Remove JSONB noise while preserving meaningful false and zero values."""

    if isinstance(value, dict):
        compacted: dict[str, object] = {}
        for key, item in value.items():
            if item is None:
                continue
            compact = _compact_json(item)
            if compact not in ([], {}):
                compacted[key] = compact
        return compacted
    if isinstance(value, list):
        return [_compact_json(item) for item in value if item is not None]
    return value


def _stored_finding(finding: ReviewFinding) -> dict[str, object]:
    """Canonical compact payload persisted in ``scm_review_attempts.findings``."""

    payload = finding.model_dump(mode="json")
    for key in _REDUNDANT_STORED_FINDING_KEYS:
        payload.pop(key, None)
    snippet = payload.get("vulnerable_snippet")
    if isinstance(snippet, dict) and snippet.get("content") == snippet.get("code"):
        snippet.pop("content", None)
    return dict(_compact_json(payload))


def _classification_references(verification: object) -> list[ClassificationReference]:
    references: list[ClassificationReference] = []
    for item in getattr(verification, "classification_references", ()) or ():
        if not isinstance(item, dict):
            continue
        namespace = str(item.get("namespace", "")).strip()
        identifier = str(item.get("identifier", "")).strip()
        if not namespace or not identifier:
            continue
        references.append(
            ClassificationReference(
                namespace=redact(namespace),
                identifier=redact(identifier),
                name=redact(str(item.get("name", "")).strip()) or None,
                source_url=str(item.get("source_url", "")).strip() or None,
            )
        )
    return references


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
                code=redact(str(getattr(item, "code", "") or "")) or None,
                code_start_line=getattr(item, "code_start_line", None) or None,
                code_end_line=getattr(item, "code_end_line", None) or None,
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
