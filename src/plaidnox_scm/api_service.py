"""Application service adapting the SCM review engine to its HTTP contract."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy.orm import Session, sessionmaker

from plaidnox_sast.redaction import redact

from . import attempts
from .api_models import PolicyAction, ReviewAttemptStatus, ReviewFinding, ReviewRequest, ReviewResponse
from .assets import load_json
from .production import ReviewDependencies
from .review import ReviewResult, review_pull_request
from .source_broker import SourceBroker


DependenciesFactory = Callable[[], ReviewDependencies]

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
        tenant_id = f"{request.provider}:installation:{request.installation_id}"
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

        response = _response(request, result)
        with attempts.unit_of_work(self.session_factory, tenant_id) as repository:
            repository.complete(
                review_id,
                lease_owner,
                outcome=result.outcome,
                action=response.action.value,
                summary=response.summary,
                incomplete_reason=response.incomplete_reason,
                counters=_counters_dict(result.counters),
                findings=[finding.model_dump(mode="json") for finding in response.findings],
            )
        return response

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
        description = redact(verification.message.strip())
        if verification.business_impact.strip():
            description = f"{description}\n\nImpact: {redact(verification.business_impact.strip())}"
        findings.append(
            ReviewFinding(
                finding_id=classification.finding_fingerprint,
                title=redact(classification.title),
                severity=classification.severity.lower(),
                confidence=classification.confidence,
                description=description,
                root_cause_path=classification.root_cause_path,
                root_cause_start_line=candidate.changed_lines.start,
                root_cause_end_line=candidate.changed_lines.end,
                root_cause_changed_in_pr=classification.root_cause_changed_in_review,
                proof_of_concept=None,
                remediation=redact(verification.remediation.strip()) or None,
                category=classification.vulnerability_class,
                baseline_relationship=classification.relationship.lower(),
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
    )


def _review_id(request: ReviewRequest) -> str:
    identity = ":".join(
        (
            request.provider,
            str(request.installation_id),
            str(request.repository_id),
            str(request.review_number),
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
