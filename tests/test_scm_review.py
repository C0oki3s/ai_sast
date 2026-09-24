from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.models import Depth, ModelTier, RouteDecision
from plaidnox_scm import triage
from plaidnox_scm.cli import main as scm_main
from plaidnox_scm.context_store import ApplicationContext, unit_of_work
from plaidnox_scm.l1_review import (
    ChangedLines,
    L1Candidate,
    L1ReviewBatch,
)
from plaidnox_scm.models import Base
from plaidnox_scm.review import review_pull_request
from plaidnox_scm.verification import CandidateVerification


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def _init_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "tests@plaidnox.local")
    _git(repo, "config", "user.name", "PlaidNox Tests")


def _factory():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _context(codebase_id: str, tenant_id: str, baseline_revision: str) -> ApplicationContext:
    return ApplicationContext(
        codebase_id=codebase_id,
        tenant_id=tenant_id,
        baseline_revision=baseline_revision,
        source_tree_hash=f"tree-{baseline_revision}",
        builder_version="fixture",
        application_type="node-api",
        entry_points=({"location": "routes/reports.js"},),
        components=({"name": "api"},),
        security_controls=({"kind": "authentication", "location": "middleware/ValidateToken.js"},),
        routes=({"path": "/reports", "middleware": "ValidateToken"},),
        sensitive_effects=({"operation": "manager report"},),
        environment_metadata={},
        identity_provider=None,
        prior_finding_refs=(),
        confidence=1.0,
        context_version="2",
        computed_at=datetime.now(UTC),
    )


class _ContextBuilder:
    def __init__(self) -> None:
        self.calls = 0

    def build(self, repo_path, baseline_revision, codebase_id, tenant_id):
        self.calls += 1
        return _context(codebase_id, tenant_id, baseline_revision)


class _L1Reviewer:
    def __init__(self, candidate: L1Candidate) -> None:
        self.candidate = candidate
        self.calls = 0

    def review(self, repo_path, diff, relevance, application_context):
        self.calls += 1
        return L1ReviewBatch(
            candidates=(self.candidate,),
            reviewed_paths=(self.candidate.changed_path,),
            coverage_complete=True,
            coverage_gaps=(),
            model_calls=1,
        )


class _Verifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, repo_path, head_revision, repository_name, application_context, candidates, minimum_depth):
        self.calls += 1
        route = RouteDecision(
            depth=Depth.DEEP,
            reason="fixture",
            model_tier=ModelTier.DEEP,
        )
        return (
            CandidateVerification(
                candidate_id=candidates[0].candidate_id,
                state="verified",
                confidence=0.98,
                title="JWT claims accepted without signature verification",
                vulnerability_class="authentication bypass",
                severity="high",
                message="Unsigned claims become trusted identity.",
                business_impact="An attacker can impersonate a manager.",
                remediation="Restore cryptographic verification.",
                reasoning="The changed security boundary accepts decoded claims.",
                attack_path="token -> decode -> trusted claims",
                security_invariant="Only verified claims establish identity.",
                gained_capability="impersonate privileged user",
                rejection_reason="",
                evidence_locations=(),
                classification_references=(),
                evidence_gaps=(),
                route=route,
            ),
        )


class _IncompleteReviewer:
    def review(self, repo_path, diff, relevance, application_context):
        return L1ReviewBatch(
            candidates=(),
            reviewed_paths=tuple(file.path for file in diff.files),
            coverage_complete=False,
            coverage_gaps=("Required cross-file control relationship was unavailable.",),
            model_calls=1,
        )


class _VerifierMustNotRun:
    def verify(self, *args, **kwargs):
        raise AssertionError("Verifier must not run when L1 produced no candidates")


def test_fixture_a_documentation_only_pr_is_fast_exit_with_zero_ai_calls(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "README.md").write_text("# Project\n")
    (repo / "app.py").write_text("x = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    (repo / "README.md").write_text("# Project\n\nNew section.\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "docs update")
    head = _git(repo, "rev-parse", "HEAD")

    result = review_pull_request(repo, base, head, "codebase-1", "tenant-a", _factory())

    assert result.outcome == "pass_fast_exit"
    assert result.candidate_count == 0
    assert result.ai_review_invoked is False
    assert result.relevance.docs_only is True
    assert result.application_context is None


def test_fixture_a_reuses_cached_application_context_on_second_pass(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "README.md").write_text("# Project\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    (repo / "README.md").write_text("# Project\n\nMore docs.\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "docs update")
    head = _git(repo, "rev-parse", "HEAD")

    factory = _factory()
    with unit_of_work(factory, "tenant-a") as repository:
        repository.upsert_context(_context("codebase-1", "tenant-a", base))
    first = review_pull_request(repo, base, head, "codebase-1", "tenant-a", factory)
    second = review_pull_request(repo, base, head, "codebase-1", "tenant-a", factory)

    assert first.application_context is not None
    assert second.application_context is not None
    # SQLite drops tzinfo on round-trip; compare naive timestamps to confirm the same
    # cached row was reused rather than recomputed.
    assert first.application_context.computed_at.replace(tzinfo=None) == second.application_context.computed_at.replace(
        tzinfo=None
    )


def test_jwt_verification_removal_runs_l1_and_independent_verification(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "middleware").mkdir()
    (repo / "middleware" / "ValidateToken.js").write_text(
        "const claims = verifier.verify(token);\nmodule.exports = claims;\n"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    (repo / "middleware" / "ValidateToken.js").write_text(
        "const claims = jwt.decode(token);\nmodule.exports = claims;\n"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "regression")
    head = _git(repo, "rev-parse", "HEAD")

    hypothesis = L1Candidate(
        candidate_id="jwt-regression",
        changed_path="middleware/ValidateToken.js",
        changed_symbol="ValidateToken",
        changed_lines=ChangedLines(1, 1),
        behavior_before="The token signature was verified.",
        behavior_after="Claims are decoded without authenticity verification.",
        security_role="Authentication middleware for protected routes.",
        suspected_broken_invariant="Only authentic tokens establish identity.",
        provisional_attacker_capability="Supply forged identity claims.",
        context_facts_used=("Protected routes trust this middleware.",),
        context_gaps=(),
        requested_expansion=(),
    )
    builder = _ContextBuilder()
    reviewer = _L1Reviewer(hypothesis)
    verifier = _Verifier()
    result = review_pull_request(
        repo,
        base,
        head,
        "codebase-1",
        "tenant-a",
        _factory(),
        context_builder=builder,
        l1_reviewer=reviewer,
        candidate_verifier=verifier,
    )

    assert result.outcome == "findings_verified"
    assert result.relevance.security_control_changed is True
    assert result.relevance.minimum_review_depth == "DEEP"
    assert result.ai_review_invoked is True
    assert result.application_context is not None
    assert result.application_context.baseline_revision == base
    assert result.counters.candidates_generated == 1
    assert result.counters.evaluated == 1
    assert result.counters.verified == 1
    assert result.counters.regressed == 1
    assert result.counters.blocking == 1
    assert result.baseline_classifications[0].relationship == "REGRESSED"
    assert result.policy.decision == "BLOCK"
    assert builder.calls == reviewer.calls == verifier.calls == 1



def test_false_positive_triage_is_honoured_by_the_next_review(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "middleware").mkdir()
    (repo / "middleware" / "ValidateToken.js").write_text(
        "const claims = verifier.verify(token);\nmodule.exports = claims;\n"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "middleware" / "ValidateToken.js").write_text(
        "const claims = jwt.decode(token);\nmodule.exports = claims;\n"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "regression")
    head = _git(repo, "rev-parse", "HEAD")
    hypothesis = L1Candidate(
        candidate_id="jwt-regression",
        changed_path="middleware/ValidateToken.js",
        changed_symbol="ValidateToken",
        changed_lines=ChangedLines(1, 1),
        behavior_before="The token signature was verified.",
        behavior_after="Claims are decoded without authenticity verification.",
        security_role="Authentication middleware for protected routes.",
        suspected_broken_invariant="Only authentic tokens establish identity.",
        provisional_attacker_capability="Supply forged identity claims.",
        context_facts_used=("Protected routes trust this middleware.",),
        context_gaps=(),
        requested_expansion=(),
    )
    factory = _factory()

    def run():
        return review_pull_request(
            repo,
            base,
            head,
            "codebase-1",
            "tenant-a",
            factory,
            context_builder=_ContextBuilder(),
            l1_reviewer=_L1Reviewer(hypothesis),
            candidate_verifier=_Verifier(),
        )

    first = run()
    assert first.policy.decision == "BLOCK"
    finding_id = first.baseline_classifications[0].finding_fingerprint
    with triage.unit_of_work(factory, "tenant-a") as repository:
        repository.apply_command(finding_id, "review-1", "fp", actor="reviewer", reason="not reachable")

    second = run()

    assert second.baseline_classifications[0].finding_fingerprint == finding_id
    assert second.policy.decision == "PASS"
    assert second.policy.triaged_count == 1
    assert second.counters.blocking == 0
    assert second.counters.in_triage == 0
    assert second.counters.verified == 1

def test_zero_verified_is_incomplete_when_l1_coverage_is_unresolved(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "app.py").write_text("def run():\n    return 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("def run():\n    return request.value\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")

    result = review_pull_request(
        repo,
        base,
        head,
        "codebase-1",
        "tenant-a",
        _factory(),
        context_builder=_ContextBuilder(),
        l1_reviewer=_IncompleteReviewer(),
        candidate_verifier=_VerifierMustNotRun(),
    )

    assert result.outcome == "review_incomplete"
    assert result.counters.verified == 0
    assert result.coverage_complete is False
    assert result.coverage_gaps


def test_cli_reports_configuration_required_without_litellm_instead_of_crashing(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "app.py").write_text("def run():\n    return 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("def run():\n    return request.value\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    for name in ("PLAIDNOX_DATABASE_URL", "LITELLM_API_BASE", "LITELLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    exit_code = scm_main(
        [
            "review",
            "--repo",
            str(repo),
            "--base",
            base,
            "--head",
            head,
            "--codebase",
            "codebase-1",
            "--tenant",
            "tenant-a",
            "--context-store",
            str(tmp_path / "context.sqlite"),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert payload["outcome"] == "configuration_required"
    assert payload["policy"]["decision"] == "INCOMPLETE"
    assert payload["ai_review_invoked"] is False
