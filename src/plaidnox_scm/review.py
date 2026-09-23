"""Changed-file-first PR/MR review orchestration.

This module owns SCM sequencing only. Application context computation, L1
hypothesis discovery, and independent verification are injected boundaries;
Code Scanning remains an immutable-snapshot library.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from sqlalchemy.orm import Session, sessionmaker

from .application_context import ApplicationContextBuilder
from .assets import load_json
from .baseline import FindingBaselineClassification, classify_against_baseline
from .baseline_models import BaselineFinding
from .change_relevance import ChangeRelevance, classify
from .context_store import ApplicationContext, unit_of_work
from .diffing import Diff, compute_diff
from .l1_review import ChangedFileReviewer, L1Candidate, L1ReviewBatch
from .policy import MergePolicyResult, evaluate_merge_policy
from .snapshots import resolve_revision
from .verification import CandidateVerification, CandidateVerifier

ReviewOutcome = Literal[
    "pass_fast_exit",
    "pass_no_verified_finding",
    "findings_verified",
    "review_incomplete",
    "configuration_required",
]


@dataclass(frozen=True, slots=True)
class ReviewCounters:
    candidates_generated: int = 0
    evaluated: int = 0
    verified: int = 0
    rejected: int = 0
    unresolved: int = 0
    introduced: int = 0
    regressed: int = 0
    modified_existing: int = 0
    existing: int = 0
    resolved: int = 0
    in_triage: int = 0
    blocking: int = 0


@dataclass(frozen=True, slots=True)
class ReviewResult:
    outcome: ReviewOutcome
    relevance: ChangeRelevance
    diff: Diff
    candidate_count: int
    ai_review_invoked: bool
    application_context: ApplicationContext | None
    candidates: tuple[L1Candidate, ...]
    verifications: tuple[CandidateVerification, ...]
    counters: ReviewCounters
    coverage_complete: bool
    coverage_gaps: tuple[str, ...]
    baseline_classifications: tuple[FindingBaselineClassification, ...]
    policy: MergePolicyResult
    detail: str


def review_pull_request(
    repo_path: Path,
    base_ref: str,
    head_ref: str,
    codebase_id: str,
    tenant_id: str,
    session_factory: sessionmaker[Session],
    *,
    context_builder: ApplicationContextBuilder | None = None,
    l1_reviewer: ChangedFileReviewer | None = None,
    candidate_verifier: CandidateVerifier | None = None,
) -> ReviewResult:
    base_revision = resolve_revision(repo_path, base_ref)
    head_revision = resolve_revision(repo_path, head_ref)
    diff = compute_diff(repo_path, base_revision, head_revision)
    relevance = classify(diff)

    is_fast_exit = relevance.minimum_review_depth == "FAST" and (
        not diff.files or relevance.docs_only or relevance.generated_only
    )
    if is_fast_exit:
        with unit_of_work(session_factory, tenant_id) as repository:
            application_context = repository.get_context(codebase_id, base_revision)
            baseline_findings = repository.list_baseline_findings(codebase_id, base_revision)
        baseline_classifications = classify_against_baseline(
            codebase_id,
            diff,
            (),
            (),
            baseline_findings,
            application_context.security_controls if application_context is not None else (),
            coverage_complete=True,
        )
        policy = evaluate_merge_policy(baseline_classifications, coverage_complete=True)
        return ReviewResult(
            outcome="pass_fast_exit",
            relevance=relevance,
            diff=diff,
            candidate_count=0,
            ai_review_invoked=False,
            application_context=application_context,
            candidates=(),
            verifications=(),
            counters=_counters(
                L1ReviewBatch((), (), True, (), 0),
                (),
                baseline_classifications,
                policy,
            ),
            coverage_complete=True,
            coverage_gaps=(),
            baseline_classifications=baseline_classifications,
            policy=policy,
            detail="Documentation/generated-only change; AI review skipped.",
        )

    missing = [
        name
        for name, value in (
            ("context_builder", context_builder),
            ("l1_reviewer", l1_reviewer),
            ("candidate_verifier", candidate_verifier),
        )
        if value is None
    ]
    if missing:
        with unit_of_work(session_factory, tenant_id) as repository:
            baseline_findings = repository.list_baseline_findings(codebase_id, base_revision)
        baseline_classifications = classify_against_baseline(
            codebase_id,
            diff,
            (),
            (),
            baseline_findings,
            (),
            coverage_complete=False,
        )
        policy = evaluate_merge_policy(
            baseline_classifications,
            coverage_complete=False,
            configuration_complete=False,
        )
        gaps = tuple(f"Missing review dependency: {name}" for name in missing)
        return ReviewResult(
            outcome="configuration_required",
            relevance=relevance,
            diff=diff,
            candidate_count=0,
            ai_review_invoked=False,
            application_context=None,
            candidates=(),
            verifications=(),
            counters=replace(
                _counters(
                    L1ReviewBatch((), (), False, gaps, 0),
                    (),
                    baseline_classifications,
                    policy,
                ),
                unresolved=1,
            ),
            coverage_complete=False,
            coverage_gaps=gaps,
            baseline_classifications=baseline_classifications,
            policy=policy,
            detail=f"Security-relevant change requires configured review dependencies: {', '.join(missing)}.",
        )

    assert context_builder is not None and l1_reviewer is not None and candidate_verifier is not None
    runtime = load_json("runtime/review.json")
    with unit_of_work(session_factory, tenant_id) as repository:
        application_context = repository.get_or_compute(
            codebase_id,
            base_revision,
            lambda: context_builder.build(repo_path, base_revision, codebase_id, tenant_id),
            builder_version=str(runtime["context_builder_version"]),
            context_version=str(runtime["context_version"]),
        )
        baseline_findings: tuple[BaselineFinding, ...] = repository.list_baseline_findings(
            codebase_id,
            base_revision,
        )
    if baseline_findings:
        application_context = replace(
            application_context,
            prior_finding_refs=tuple(
                dict.fromkeys(
                    (
                        *application_context.prior_finding_refs,
                        *(item.finding_fingerprint for item in baseline_findings),
                    )
                )
            ),
        )

    batch: L1ReviewBatch = l1_reviewer.review(repo_path, diff, relevance, application_context)
    verifications = (
        candidate_verifier.verify(
            repo_path,
            head_revision,
            codebase_id,
            application_context,
            batch.candidates,
            relevance.minimum_review_depth,
        )
        if batch.candidates
        else ()
    )
    provisional_coverage_complete = batch.coverage_complete and not any(
        item.state == "unresolved" for item in verifications
    )
    baseline_classifications = classify_against_baseline(
        codebase_id,
        diff,
        batch.candidates,
        verifications,
        baseline_findings,
        application_context.security_controls,
        coverage_complete=provisional_coverage_complete,
    )
    policy = evaluate_merge_policy(
        baseline_classifications,
        coverage_complete=provisional_coverage_complete,
    )
    counters = _counters(batch, verifications, baseline_classifications, policy)
    coverage_gaps = tuple(batch.coverage_gaps) + tuple(
        gap for result in verifications if result.state == "unresolved" for gap in result.evidence_gaps
    )
    coverage_complete = batch.coverage_complete and counters.unresolved == 0
    if counters.verified:
        outcome: ReviewOutcome = "findings_verified"
        detail = f"Independent Deep Hunt verified {counters.verified} changed-code finding(s)."
    elif not coverage_complete:
        outcome = "review_incomplete"
        detail = "No finding was verified, but changed-surface coverage or required evidence remains unresolved."
    else:
        outcome = "pass_no_verified_finding"
        detail = "Changed-file review completed with no independently verified finding."

    return ReviewResult(
        outcome=outcome,
        relevance=relevance,
        diff=diff,
        candidate_count=len(batch.candidates),
        ai_review_invoked=batch.model_calls > 0,
        application_context=application_context,
        candidates=batch.candidates,
        verifications=verifications,
        counters=counters,
        coverage_complete=coverage_complete,
        coverage_gaps=coverage_gaps,
        baseline_classifications=baseline_classifications,
        policy=policy,
        detail=detail,
    )


def _counters(
    batch: L1ReviewBatch,
    verifications: tuple[CandidateVerification, ...],
    baseline_classifications: tuple[FindingBaselineClassification, ...],
    policy: MergePolicyResult,
) -> ReviewCounters:
    return ReviewCounters(
        candidates_generated=len(batch.candidates),
        evaluated=len(verifications),
        verified=sum(item.state == "verified" for item in verifications),
        rejected=sum(item.state == "rejected" for item in verifications),
        unresolved=sum(item.state == "unresolved" for item in verifications),
        introduced=sum(item.relationship == "INTRODUCED" for item in baseline_classifications),
        regressed=sum(item.relationship == "REGRESSED" for item in baseline_classifications),
        modified_existing=sum(
            item.relationship == "MODIFIED_EXISTING" for item in baseline_classifications
        ),
        existing=sum(item.relationship == "EXISTING" for item in baseline_classifications),
        resolved=sum(item.relationship == "RESOLVED" for item in baseline_classifications),
        in_triage=sum(
            item.verification_state == "verified"
            and item.relationship not in {"EXISTING", "RESOLVED"}
            for item in baseline_classifications
        ),
        blocking=policy.blocking_count,
    )
