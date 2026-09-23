"""Application service adapting the SCM review engine to its HTTP contract."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session, sessionmaker

from plaidnox_sast.redaction import redact

from .api_models import PolicyAction, ReviewFinding, ReviewRequest, ReviewResponse
from .production import ReviewDependencies
from .review import ReviewResult, review_pull_request
from .source_broker import SourceBroker


DependenciesFactory = Callable[[], ReviewDependencies]


@dataclass(frozen=True, slots=True)
class ReviewService:
    source_broker: SourceBroker
    session_factory: sessionmaker[Session]
    dependencies_factory: DependenciesFactory

    def run(self, request: ReviewRequest) -> ReviewResponse:
        with self.source_broker.materialize(request) as source:
            tenant_id = f"{request.provider}:installation:{request.installation_id}"
            codebase_id = f"{request.provider}:repository:{request.repository_id}"
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
        return _response(request, result)


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
