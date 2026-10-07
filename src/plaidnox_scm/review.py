"""Changed-file-first PR/MR review orchestration.

This module owns SCM sequencing only. Application context computation, L1
hypothesis discovery, and independent verification are injected boundaries;
Code Scanning remains an immutable-snapshot library.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from sqlalchemy.orm import Session, sessionmaker

from plaidnox_sast.ai import AIResponseError

from .application_context import ApplicationContextBuilder
from .assets import load_json
from .baseline import (
    FindingBaselineClassification,
    PriorFinding,
    classify_against_baseline,
    prior_findings_from_stored,
)
from .dedupe import IssueSignature, consolidate_verified, same_issue, verification_signature
from .lifecycle import (
    CARRIED_OUTCOMES,
    FIXED_OUTCOMES,
    KnownFinding,
    KnownOutcome,
    file_change,
    recheck_candidate,
)
from .baseline_models import BaselineFinding
from .change_relevance import ChangeRelevance, classify
from .context_store import ApplicationContext, unit_of_work
from .diffing import Diff, compute_diff
from .l1_review import ChangedFileReviewer, L1Candidate, L1ReviewBatch
from .policy import MergePolicyResult, evaluate_merge_policy
from . import triage
from .snapshots import resolve_revision
from .verification import CandidateVerification, CandidateVerifier

_LOG = logging.getLogger(__name__)

# Called once per completed review stage with a small, primitive-valued metadata
# map. Used to record a per-run timeline; it must never affect the review result.
StageCallback = Callable[[str, dict[str, str | int | float | bool]], None]

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
    duplicates_merged: int = 0
    rechecked: int = 0
    fixed: int = 0
    carried_forward: int = 0


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
    # What happened to findings already open on this PR or the default branch.
    known_outcomes: tuple[KnownOutcome, ...] = ()


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
    on_stage: StageCallback | None = None,
    known_findings: tuple[KnownFinding, ...] = (),
    prior_findings: tuple[PriorFinding, ...] = (),
) -> ReviewResult:
    def stage(name: str, **metadata: str | int | float | bool | None) -> None:
        if on_stage is None:
            return
        try:
            on_stage(name, {key: value for key, value in metadata.items() if value is not None})
        except Exception:  # noqa: BLE001 - the timeline is diagnostic only
            _LOG.warning("review stage callback failed for %s", name, exc_info=True)

    base_revision = resolve_revision(repo_path, base_ref)
    head_revision = resolve_revision(repo_path, head_ref)
    diff = compute_diff(repo_path, base_revision, head_revision)
    relevance = classify(diff)
    statuses = [item.status for item in diff.files]
    stage(
        "changes_analyzed",
        files_changed=len(diff.files),
        added=statuses.count("added"),
        modified=statuses.count("modified"),
        deleted=statuses.count("deleted"),
        renamed=statuses.count("renamed") + statuses.count("copied"),
        changed_symbols=len(relevance.changed_symbols),
        review_depth=relevance.minimum_review_depth,
        runtime_changed=relevance.runtime_changed,
        security_control_changed=relevance.security_control_changed,
        config_changed=relevance.config_changed,
        dependency_or_build_changed=relevance.dependency_or_build_changed,
        docs_only=relevance.docs_only,
        test_only=relevance.test_only,
    )

    is_fast_exit = relevance.minimum_review_depth == "FAST" and (
        not diff.files or relevance.docs_only or relevance.generated_only
    )
    if is_fast_exit:
        with unit_of_work(session_factory, tenant_id) as repository:
            application_context = repository.get_context(codebase_id, base_revision)
            baseline_findings = repository.list_baseline_findings(codebase_id, base_revision)
        baseline_findings = _with_branch_baselines(baseline_findings, known_findings, codebase_id, base_revision)
        baseline_classifications = classify_against_baseline(
            codebase_id,
            diff,
            (),
            (),
            baseline_findings,
            application_context.security_controls if application_context is not None else (),
            coverage_complete=True,
        )
        known_outcomes = _passive_outcomes(repo_path, base_revision, head_revision, diff, known_findings, complete=True)
        baseline_classifications = _apply_lifecycle(baseline_classifications, known_outcomes)
        policy = evaluate_merge_policy(
            baseline_classifications,
            coverage_complete=True,
            triage_states=_triage_states(session_factory, tenant_id, baseline_classifications),
        )
        stage("review_skipped", reason="Documentation or generated files only; AI review not required")
        stage("policy_evaluated", decision=policy.decision, blocking=policy.blocking_count, in_triage=policy.in_triage_count)
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
            known_outcomes=known_outcomes,
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
        baseline_findings = _with_branch_baselines(baseline_findings, known_findings, codebase_id, base_revision)
        baseline_classifications = classify_against_baseline(
            codebase_id,
            diff,
            (),
            (),
            baseline_findings,
            (),
            coverage_complete=False,
        )
        known_outcomes = _hold_fixes(
            _passive_outcomes(repo_path, base_revision, head_revision, diff, known_findings, complete=False)
        )
        baseline_classifications = _apply_lifecycle(baseline_classifications, known_outcomes)
        policy = evaluate_merge_policy(
            baseline_classifications,
            coverage_complete=False,
            configuration_complete=False,
            triage_states=_triage_states(session_factory, tenant_id, baseline_classifications),
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
            known_outcomes=known_outcomes,
        )

    assert context_builder is not None and l1_reviewer is not None and candidate_verifier is not None
    runtime = load_json("runtime/review.json")
    try:
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
    except AIResponseError as exc:
        with unit_of_work(session_factory, tenant_id) as repository:
            baseline_findings = repository.list_baseline_findings(codebase_id, base_revision)
        gap = f"Application context generation failed after bounded retries: {type(exc).__name__}."
        baseline_findings = _with_branch_baselines(baseline_findings, known_findings, codebase_id, base_revision)
        baseline_classifications = classify_against_baseline(
            codebase_id,
            diff,
            (),
            (),
            baseline_findings,
            (),
            coverage_complete=False,
        )
        known_outcomes = _hold_fixes(
            _passive_outcomes(repo_path, base_revision, head_revision, diff, known_findings, complete=False)
        )
        baseline_classifications = _apply_lifecycle(baseline_classifications, known_outcomes)
        policy = evaluate_merge_policy(
            baseline_classifications,
            coverage_complete=False,
            triage_states=_triage_states(session_factory, tenant_id, baseline_classifications),
        )
        return ReviewResult(
            outcome="review_incomplete",
            relevance=relevance,
            diff=diff,
            candidate_count=0,
            ai_review_invoked=True,
            application_context=None,
            candidates=(),
            verifications=(),
            counters=replace(
                _counters(
                    L1ReviewBatch((), (), False, (gap,), 1),
                    (),
                    baseline_classifications,
                    policy,
                ),
                unresolved=1,
            ),
            coverage_complete=False,
            coverage_gaps=(gap,),
            baseline_classifications=baseline_classifications,
            policy=policy,
            detail=gap,
            known_outcomes=known_outcomes,
        )
    stage(
        "context_ready",
        application_type=(application_context.application_type or "")[:300] or None,
        baseline_revision=application_context.baseline_revision[:12],
        entry_points=len(application_context.entry_points),
        routes=len(application_context.routes),
        components=len(application_context.components),
        security_controls=len(application_context.security_controls),
        sensitive_effects=len(application_context.sensitive_effects),
        identity_provider=application_context.identity_provider,
        confidence=round(float(application_context.confidence), 2),
        baseline_findings=len(baseline_findings),
    )
    baseline_findings = _with_branch_baselines(baseline_findings, known_findings, codebase_id, base_revision)
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
    stage(
        "candidates_generated",
        candidates=len(batch.candidates),
        files_reviewed=len(batch.reviewed_paths),
        model_calls=batch.model_calls,
        coverage_complete=batch.coverage_complete,
        coverage_gaps=len(batch.coverage_gaps),
    )
    decided, rechecks = _plan_known(repo_path, base_revision, head_revision, diff, known_findings, runtime)
    recheck_candidates = tuple(candidate for _, candidate in rechecks.values())
    all_candidates = (*batch.candidates, *recheck_candidates)
    all_verifications = (
        candidate_verifier.verify(
            repo_path,
            head_revision,
            codebase_id,
            application_context,
            all_candidates,
            relevance.minimum_review_depth,
        )
        if all_candidates
        else ()
    )
    recheck_results = {item.candidate_id: item for item in all_verifications if item.candidate_id in rechecks}
    # A recheck only joins the finding list when it re-confirmed the finding; a rejected or
    # inconclusive recheck says nothing about this PR's own changed-surface coverage.
    verifications = tuple(
        item for item in all_verifications
        if item.candidate_id not in rechecks or item.state == "verified"
    )
    verified_reports = sum(item.state == "verified" for item in verifications)
    consolidation = consolidate_verified(all_candidates, verifications)
    verifications = consolidation.verifications
    duplicates_merged = len(consolidation.merged_into)
    stage(
        "verification_complete",
        evaluated=verified_reports + sum(item.state != "verified" for item in verifications),
        verified=verified_reports - duplicates_merged,
        rejected=sum(item.state == "rejected" for item in verifications),
        unresolved=sum(item.state == "unresolved" for item in verifications),
        duplicates_merged=duplicates_merged,
    )
    provisional_coverage_complete = batch.coverage_complete and not any(
        item.state == "unresolved" for item in verifications
    )
    pr_known = tuple(item for item in known_findings if item.scope == "pr")
    branch_known = tuple(item for item in known_findings if item.scope == "branch")
    candidate_by_id = {item.candidate_id: item for item in all_candidates}
    baseline_classifications = classify_against_baseline(
        codebase_id,
        diff,
        all_candidates,
        verifications,
        baseline_findings,
        application_context.security_controls,
        coverage_complete=provisional_coverage_complete,
        prior_findings=_merge_prior(prior_findings_from_stored([item.finding for item in pr_known]), prior_findings),
        forced_identities=_known_identities(
            rechecks, decided, known_findings, consolidation.merged_into, verifications, candidate_by_id,
        ),
        baseline_signatures=prior_findings_from_stored([item.finding for item in branch_known]),
    )
    finding_by_candidate = {
        item.candidate_id: item.finding_fingerprint
        for item in baseline_classifications
        if item.verification_state == "verified" and item.candidate_id
    }
    current = tuple(
        (finding_by_candidate[item.candidate_id], verification_signature(candidate_by_id[item.candidate_id], item))
        for item in verifications
        if item.state == "verified" and item.candidate_id in finding_by_candidate and item.candidate_id in candidate_by_id
    )
    known_outcomes = _resolve_known(
        known_findings, decided, rechecks, recheck_results, consolidation.merged_into, baseline_classifications, current,
    )
    if not provisional_coverage_complete:
        # The stated rule: an incomplete run never changes a finding to fixed.
        known_outcomes = _hold_fixes(known_outcomes)
    baseline_classifications = _apply_lifecycle(baseline_classifications, known_outcomes)
    stage(
        "known_findings_checked",
        known=len(known_findings),
        reobserved=sum(item.outcome == "reobserved" for item in known_outcomes),
        rechecked=len(rechecks),
        fixed=sum(item.outcome in FIXED_OUTCOMES for item in known_outcomes),
        carried_forward=sum(item.outcome in CARRIED_OUTCOMES and item.scope == "pr" for item in known_outcomes),
    )
    policy = evaluate_merge_policy(
        baseline_classifications,
        coverage_complete=provisional_coverage_complete,
        triage_states=_triage_states(session_factory, tenant_id, baseline_classifications),
    )
    counters = replace(
        _counters(batch, verifications, baseline_classifications, policy),
        evaluated=len(verifications) + duplicates_merged,
        duplicates_merged=duplicates_merged,
        rechecked=len(rechecks),
        fixed=sum(item.outcome in FIXED_OUTCOMES for item in known_outcomes),
        carried_forward=sum(item.outcome in CARRIED_OUTCOMES and item.scope == "pr" for item in known_outcomes),
    )
    stage(
        "baseline_compared",
        introduced=counters.introduced,
        regressed=counters.regressed,
        modified_existing=counters.modified_existing,
        existing=counters.existing,
        resolved=counters.resolved,
    )
    stage(
        "policy_evaluated",
        decision=policy.decision,
        blocking=policy.blocking_count,
        in_triage=policy.in_triage_count,
        coverage_complete=provisional_coverage_complete,
    )
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
        # Re-checks of earlier findings are candidates too: a re-confirmed finding is
        # reported from its re-check verification.
        candidates=all_candidates,
        verifications=verifications,
        counters=counters,
        coverage_complete=coverage_complete,
        coverage_gaps=coverage_gaps,
        baseline_classifications=baseline_classifications,
        policy=policy,
        detail=detail,
        known_outcomes=known_outcomes,
    )


def _merge_prior(*groups: tuple[PriorFinding, ...]) -> tuple[PriorFinding, ...]:
    seen: set[str] = set()
    merged: list[PriorFinding] = []
    for group in groups:
        for item in group:
            if item.finding_fingerprint not in seen:
                seen.add(item.finding_fingerprint)
                merged.append(item)
    return tuple(merged)


def _known_identities(
    rechecks: dict[str, tuple[KnownFinding, L1Candidate]],
    decided: dict[str, KnownOutcome],
    known_findings: tuple[KnownFinding, ...],
    merged_into: dict[str, str],
    verifications: tuple[CandidateVerification, ...],
    candidate_by_id: dict[str, L1Candidate],
) -> dict[str, tuple[str, str]]:
    """Candidates that are a tracked finding seen again keep that finding's identity.

    * A re-check is the question "is this finding still here?", so a confirmed re-check
      keeps the finding's id. If consolidation merged the re-check with another report of
      the same bug, the report that was kept inherits the id.
    * A fresh report of a tracked PR finding whose file is byte-identical since it was
      verified is the same code, so it keeps the id too (the evidence trace the model
      picks can differ between runs even when the code does not).
    """

    forced: dict[str, tuple[str, str]] = {}
    claimed: set[str] = set()
    for candidate_id, (known, _) in rechecks.items():
        kept = merged_into.get(candidate_id, candidate_id)
        if kept not in forced and known.finding_id not in claimed:
            forced[kept] = (known.root_cause_fingerprint, known.finding_id)
            claimed.add(known.finding_id)
    unchanged = [
        known for known in known_findings
        if known.scope == "pr"
        and getattr(decided.get(known.finding_id), "outcome", None) == "carried_unchanged"
    ]
    for item in verifications:
        if item.state != "verified" or item.candidate_id in forced or item.candidate_id not in candidate_by_id:
            continue
        current = verification_signature(candidate_by_id[item.candidate_id], item)
        match = next(
            (known for known in unchanged if known.finding_id not in claimed and same_issue(known.signature, current)),
            None,
        )
        if match is not None:
            forced[item.candidate_id] = (match.root_cause_fingerprint, match.finding_id)
            claimed.add(match.finding_id)
    return forced


def _hold_fixes(outcomes: tuple[KnownOutcome, ...]) -> tuple[KnownOutcome, ...]:
    """An incomplete run leaves findings as they were: no fix is recorded, even for a deleted file."""

    return tuple(
        KnownOutcome(
            item.finding_id, item.scope, "carried_incomplete",
            f"This run was incomplete, so the finding stays open until a complete run confirms it. ({item.reason})",
            item.finding,
        )
        if item.outcome in FIXED_OUTCOMES else item
        for item in outcomes
    )


def _with_branch_baselines(
    baseline_findings: tuple[BaselineFinding, ...],
    known_findings: tuple[KnownFinding, ...],
    codebase_id: str,
    base_revision: str,
) -> tuple[BaselineFinding, ...]:
    """Open default-branch findings act as the baseline, whatever exact commit the PR is based on."""

    present = {item.root_cause_fingerprint for item in baseline_findings}
    extra: list[BaselineFinding] = []
    for known in known_findings:
        if known.scope != "branch" or not known.root_cause_fingerprint or known.root_cause_fingerprint in present:
            continue
        present.add(known.root_cause_fingerprint)
        finding = known.finding
        extra.append(
            BaselineFinding(
                codebase_id=codebase_id,
                baseline_revision=base_revision,
                root_cause_fingerprint=known.root_cause_fingerprint,
                finding_fingerprint=known.finding_id,
                lifecycle_state="open",
                root_cause_path=known.path,
                root_cause_symbol=str(finding.get("root_cause_symbol") or ""),
                vulnerability_class=str(finding.get("category") or ""),
                title=str(finding.get("title") or ""),
                severity=str(finding.get("severity") or "info"),
                confidence=float(finding.get("confidence") or 0.0),
            )
        )
    return (*baseline_findings, *extra)


def _relevant(known: KnownFinding, diff: Diff) -> bool:
    """PR findings are always tracked; a branch finding only when this PR touches its file."""

    if known.scope == "pr":
        return True
    return any(known.path in {item.path, item.old_path} for item in diff.files)


def _plan_known(
    repo_path: Path,
    base_revision: str,
    head_revision: str,
    diff: Diff,
    known_findings: tuple[KnownFinding, ...],
    runtime: dict[str, object],
) -> tuple[dict[str, KnownOutcome], dict[str, tuple[KnownFinding, L1Candidate]]]:
    limit = int(runtime.get("known_finding_recheck_limit", 10))  # type: ignore[call-overload]
    decided: dict[str, KnownOutcome] = {}
    rechecks: dict[str, tuple[KnownFinding, L1Candidate]] = {}
    # Collapse tracked findings that are the same bug under different ids (findings stored
    # before identities were stable): the default-branch one, else the newest, is kept.
    kept: list[KnownFinding] = []
    for known in sorted(known_findings, key=lambda item: item.scope != "branch"):
        original = next(
            (item for item in kept if item.finding_id != known.finding_id and same_issue(item.signature, known.signature)),
            None,
        )
        if original is not None and known.scope == "pr":
            decided[known.finding_id] = KnownOutcome(
                known.finding_id, known.scope, "duplicate", f"Same issue as finding {original.finding_id}.", known.finding,
            )
        elif original is None:
            kept.append(known)
    for known in known_findings:
        if not _relevant(known, diff) or known.finding_id in decided:
            continue
        since = known.last_seen_head if known.scope == "pr" else base_revision
        change = file_change(repo_path, since, head_revision, known)
        if change.status == "deleted":
            decided[known.finding_id] = KnownOutcome(
                known.finding_id, known.scope, "fixed_removed",
                f"Root-cause file {known.path} was deleted at {head_revision[:12]}.", known.finding,
            )
        elif change.status == "unchanged" and known.scope == "pr":
            decided[known.finding_id] = KnownOutcome(
                known.finding_id, known.scope, "carried_unchanged",
                f"{known.path} is unchanged since {since[:12]}; the verified finding is still present.", known.finding,
            )
        elif len(rechecks) < limit:
            candidate = recheck_candidate(known, change)
            rechecks[candidate.candidate_id] = (known, candidate)
        else:
            decided[known.finding_id] = KnownOutcome(
                known.finding_id, known.scope, "carried_incomplete",
                "Re-check budget for this run was used; the finding stays open until it is re-verified.",
                known.finding,
            )
    return decided, rechecks


def _passive_outcomes(
    repo_path: Path,
    base_revision: str,
    head_revision: str,
    diff: Diff,
    known_findings: tuple[KnownFinding, ...],
    *,
    complete: bool,
) -> tuple[KnownOutcome, ...]:
    """Outcomes when this run cannot re-verify anything: only deletion or identical code count."""

    decided, rechecks = _plan_known(repo_path, base_revision, head_revision, diff, known_findings, {"known_finding_recheck_limit": 10**6})
    outcomes = list(decided.values())
    for known, _ in rechecks.values():
        reason = (
            "The root-cause code changed but this run did not re-verify it; the finding stays open."
            if complete else "This run was incomplete; the finding stays open until it is re-verified."
        )
        outcomes.append(KnownOutcome(known.finding_id, known.scope, "carried_incomplete", reason, known.finding))
    return tuple(outcomes)


def _resolve_known(
    known_findings: tuple[KnownFinding, ...],
    decided: dict[str, KnownOutcome],
    rechecks: dict[str, tuple[KnownFinding, L1Candidate]],
    recheck_results: dict[str, CandidateVerification],
    merged_into: dict[str, str],
    classifications: tuple[FindingBaselineClassification, ...],
    current: tuple[tuple[str, IssueSignature], ...] = (),
) -> tuple[KnownOutcome, ...]:
    verified_ids = {
        item.finding_fingerprint for item in classifications if item.verification_state == "verified"
    }
    outcomes: dict[str, KnownOutcome] = {}
    for known in known_findings:
        if known.finding_id in outcomes:
            continue
        if known.finding_id in verified_ids:
            outcomes[known.finding_id] = KnownOutcome(
                known.finding_id, known.scope, "reobserved", "Verified again in this run.", known.finding,
            )
        elif known.finding_id in decided:
            outcomes[known.finding_id] = decided[known.finding_id]
    for candidate_id, (known, _) in rechecks.items():
        if known.finding_id in outcomes:
            continue
        result = recheck_results.get(candidate_id)
        if candidate_id in merged_into or (result is not None and result.state == "verified"):
            outcome = KnownOutcome(known.finding_id, known.scope, "reobserved", "Re-verified at this commit.", known.finding)
        elif result is not None and result.state == "rejected":
            why = (result.rejection_reason or result.reasoning or "re-verification rejected the finding").strip()
            outcome = KnownOutcome(known.finding_id, known.scope, "fixed_verified", f"Re-verified as fixed: {why}", known.finding)
        else:
            why = (result.reasoning if result is not None else "no verification result").strip()
            outcome = KnownOutcome(
                known.finding_id, known.scope, "recheck_unresolved",
                f"Code changed but re-verification was inconclusive ({why}); the finding stays open.", known.finding,
            )
        outcomes[known.finding_id] = outcome
    # A still-open tracked finding that is the same bug as one reported now under another id
    # (only possible for ids minted before identities were stable) is folded into it.
    for finding_id, outcome in list(outcomes.items()):
        if outcome.scope != "pr" or outcome.outcome not in CARRIED_OUTCOMES:
            continue
        known = next(item for item in known_findings if item.finding_id == finding_id)
        twin = next(
            (other for other, sig in current if other != finding_id and same_issue(sig, known.signature)),
            None,
        )
        if twin is not None:
            outcomes[finding_id] = KnownOutcome(
                finding_id, outcome.scope, "duplicate", f"Same issue as finding {twin}.", known.finding,
            )
    return tuple(outcomes.values())


def _apply_lifecycle(
    classifications: tuple[FindingBaselineClassification, ...],
    outcomes: tuple[KnownOutcome, ...],
) -> tuple[FindingBaselineClassification, ...]:
    """Carried PR findings still count for policy; a branch finding fixed here becomes RESOLVED."""

    present = {item.finding_fingerprint for item in classifications}
    by_id = {item.finding_id: item for item in outcomes}
    result: list[FindingBaselineClassification] = []
    for item in classifications:
        outcome = by_id.get(item.finding_fingerprint)
        if outcome is not None and outcome.scope == "branch" and outcome.outcome in FIXED_OUTCOMES:
            result.append(replace(
                item, relationship="RESOLVED", verification_state="rejected",
                reason=f"Default-branch finding fixed by this pull request. {outcome.reason}",
            ))
        else:
            result.append(item)
    for outcome in outcomes:
        if outcome.scope != "pr" or outcome.outcome not in CARRIED_OUTCOMES or outcome.finding_id in present:
            continue
        result.append(carried_classification(outcome))
    return tuple(result)


def carried_classification(outcome: KnownOutcome) -> FindingBaselineClassification:
    finding = outcome.finding
    return FindingBaselineClassification(
        relationship=str(finding.get("baseline_relationship") or "introduced").upper(),  # type: ignore[arg-type]
        root_cause_fingerprint=str(finding.get("root_cause_fingerprint") or ""),
        finding_fingerprint=outcome.finding_id,
        candidate_id=None,
        verification_state="verified",
        baseline_state=None,
        root_cause_path=str(finding.get("root_cause_path") or ""),
        root_cause_symbol=str(finding.get("root_cause_symbol") or ""),
        vulnerability_class=str(finding.get("category") or ""),
        title=str(finding.get("title") or ""),
        severity=str(finding.get("severity") or "info"),
        confidence=float(finding.get("confidence") or 0.0),
        root_cause_changed_in_review=bool(finding.get("root_cause_changed_in_pr", True)),
        reason=f"Carried forward: {outcome.reason}",
    )


def _triage_states(
    session_factory: sessionmaker[Session],
    tenant_id: str,
    classifications: tuple[FindingBaselineClassification, ...],
) -> dict[str, str]:
    if not classifications:
        return {}
    with triage.unit_of_work(session_factory, tenant_id) as repository:
        return repository.get_states(item.finding_fingerprint for item in classifications)


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
        in_triage=policy.in_triage_count,
        blocking=policy.blocking_count,
    )
