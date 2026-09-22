from __future__ import annotations

import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.models import Depth, ModelTier, RouteDecision
from plaidnox_scm.baseline import classify_against_baseline, root_cause_fingerprint
from plaidnox_scm.baseline_models import BaselineFinding
from plaidnox_scm.context_store import ApplicationContext, unit_of_work
from plaidnox_scm.diffing import ChangedFile, Diff, DiffHunk
from plaidnox_scm.l1_review import ChangedLines, L1Candidate, L1ReviewBatch
from plaidnox_scm.models import Base
from plaidnox_scm.review import review_pull_request
from plaidnox_scm.verification import CandidateVerification


def _candidate(path: str = "middleware/ValidateToken.js", symbol: str = "ValidateToken") -> L1Candidate:
    return L1Candidate(
        candidate_id="candidate-1",
        changed_path=path,
        changed_symbol=symbol,
        changed_lines=ChangedLines(1, 1),
        behavior_before="The boundary verified the presented identity token.",
        behavior_after="The boundary trusts decoded claims without authenticity verification.",
        security_role="Authentication boundary.",
        suspected_broken_invariant="Only authentic claims establish identity.",
        provisional_attacker_capability="Forge privileged identity claims.",
        context_facts_used=(),
        context_gaps=(),
        requested_expansion=(),
    )


def _verification(state: Literal["verified", "rejected"] = "verified") -> CandidateVerification:
    return CandidateVerification(
        candidate_id="candidate-1",
        state=state,
        confidence=0.97,
        title="Protected routes accept forged identity claims",
        vulnerability_class="authentication bypass",
        severity="high",
        message="The changed boundary no longer verifies token authenticity.",
        business_impact="An attacker can impersonate a privileged user.",
        remediation="Restore cryptographic verification.",
        reasoning="Independent verification completed.",
        attack_path="token -> decoded claims -> trusted identity",
        security_invariant="Only authentic claims establish identity.",
        gained_capability="impersonate privileged user",
        rejection_reason="Control remains effective." if state == "rejected" else "",
        evidence_locations=(),
        classification_references=(),
        evidence_gaps=(),
        route=RouteDecision(Depth.DEEP, "fixture", model_tier=ModelTier.DEEP),
    )


def _diff(path: str = "middleware/ValidateToken.js") -> Diff:
    return Diff(
        "base",
        "head",
        (ChangedFile(path, "modified", None, (DiffHunk(1, 1, 1, 1, ""),)),),
    )


def _baseline(
    codebase_id: str,
    candidate: L1Candidate,
    *,
    state: str = "open",
) -> BaselineFinding:
    root = root_cause_fingerprint(
        codebase_id,
        candidate.changed_path,
        candidate.changed_symbol,
        "authentication bypass",
    )
    return BaselineFinding(
        codebase_id=codebase_id,
        baseline_revision="base",
        root_cause_fingerprint=root,
        finding_fingerprint=f"finding-{root}",
        lifecycle_state=state,
        root_cause_path=candidate.changed_path,
        root_cause_symbol=candidate.changed_symbol,
        vulnerability_class="authentication bypass",
        title="Protected routes accept forged identity claims",
        severity="high",
        confidence=0.97,
    )


def test_verified_change_to_a_cached_security_control_is_regressed() -> None:
    candidate = _candidate()
    result = classify_against_baseline(
        "codebase-1",
        _diff(),
        (candidate,),
        (_verification(),),
        (),
        ({"kind": "authentication", "location": candidate.changed_path},),
        coverage_complete=True,
    )

    assert result[0].relationship == "REGRESSED"


def test_verified_changed_root_without_baseline_relationship_is_introduced() -> None:
    candidate = _candidate("services/payment.py", "charge")
    verification = _verification()

    result = classify_against_baseline(
        "codebase-1",
        _diff(candidate.changed_path),
        (candidate,),
        (verification,),
        (),
        (),
        coverage_complete=True,
    )

    assert result[0].relationship == "INTRODUCED"


def test_verified_changed_baseline_finding_is_modified_existing() -> None:
    candidate = _candidate()
    baseline = _baseline("codebase-1", candidate)

    result = classify_against_baseline(
        "codebase-1",
        _diff(),
        (candidate,),
        (_verification(),),
        (baseline,),
        (),
        coverage_complete=True,
    )

    assert result[0].relationship == "MODIFIED_EXISTING"


def test_verified_resolved_baseline_finding_is_regressed() -> None:
    candidate = _candidate()

    result = classify_against_baseline(
        "codebase-1",
        _diff(),
        (candidate,),
        (_verification(),),
        (_baseline("codebase-1", candidate, state="resolved"),),
        (),
        coverage_complete=True,
    )

    assert result[0].relationship == "REGRESSED"


def test_affected_baseline_finding_requires_complete_independent_rejection_to_be_resolved() -> None:
    candidate = _candidate()
    baseline = _baseline("codebase-1", candidate)

    resolved = classify_against_baseline(
        "codebase-1",
        _diff(),
        (candidate,),
        (_verification("rejected"),),
        (baseline,),
        (),
        coverage_complete=True,
    )
    incomplete = classify_against_baseline(
        "codebase-1",
        _diff(),
        (candidate,),
        (_verification("rejected"),),
        (baseline,),
        (),
        coverage_complete=False,
    )

    assert resolved[0].relationship == "RESOLVED"
    assert incomplete[0].relationship == "EXISTING"


def test_unaffected_baseline_finding_remains_existing() -> None:
    baseline_candidate = _candidate("legacy.py", "legacy_handler")
    baseline = _baseline("codebase-1", baseline_candidate)

    result = classify_against_baseline(
        "codebase-1",
        _diff("app.py"),
        (),
        (),
        (baseline,),
        (),
        coverage_complete=True,
    )

    assert result[0].relationship == "EXISTING"
    assert result[0].root_cause_changed_in_review is False


def test_baseline_store_is_revision_and_tenant_scoped() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    candidate = _candidate()
    finding = _baseline("codebase-1", candidate)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.upsert_baseline_finding(finding)
        repository.upsert_baseline_finding(finding)
    with unit_of_work(factory, "tenant-a") as repository:
        assert repository.list_baseline_findings("codebase-1", "base") == (finding,)
        assert repository.list_baseline_findings("codebase-1", "other") == ()
    with unit_of_work(factory, "tenant-b") as repository:
        assert repository.list_baseline_findings("codebase-1", "base") == ()


class _Builder:
    def build(self, repo_path, baseline_revision, codebase_id, tenant_id):
        return ApplicationContext(
            codebase_id=codebase_id,
            tenant_id=tenant_id,
            baseline_revision=baseline_revision,
            source_tree_hash="tree",
            builder_version="fixture",
            application_type="service",
            entry_points=(),
            components=(),
            security_controls=(),
            routes=(),
            sensitive_effects=(),
            environment_metadata={},
            identity_provider=None,
            prior_finding_refs=(),
            confidence=1.0,
            context_version="2",
            computed_at=datetime.now(UTC),
        )


class _CompleteNoCandidateReviewer:
    def review(self, repo_path, diff, relevance, application_context):
        return L1ReviewBatch((), tuple(item.path for item in diff.files), True, (), 1)


class _VerifierMustNotRun:
    def verify(self, *args, **kwargs):
        raise AssertionError("no candidate requires verification")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def test_fixture_d_existing_unrelated_finding_is_visible_but_not_new_pr_risk(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "tests@plaidnox.local")
    _git(repo, "config", "user.name", "PlaidNox Tests")
    (repo / "legacy.py").write_text("def legacy_handler(value):\n    return value\n")
    (repo / "app.py").write_text("def run():\n    return 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("def run():\n    return 2\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    baseline_candidate = _candidate("legacy.py", "legacy_handler")
    finding = _baseline("codebase-1", baseline_candidate)
    finding = replace(finding, baseline_revision=base)
    with unit_of_work(factory, "tenant-a") as repository:
        repository.upsert_baseline_finding(finding)

    result = review_pull_request(
        repo,
        base,
        head,
        "codebase-1",
        "tenant-a",
        factory,
        context_builder=_Builder(),
        l1_reviewer=_CompleteNoCandidateReviewer(),
        candidate_verifier=_VerifierMustNotRun(),
    )

    assert result.outcome == "pass_no_verified_finding"
    assert result.counters.existing == 1
    assert result.counters.introduced == 0
    assert result.counters.regressed == 0
    assert result.baseline_classifications[0].relationship == "EXISTING"
