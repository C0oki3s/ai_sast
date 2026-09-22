from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from plaidnox_sast.ai import DeepHuntResult
from plaidnox_sast.models import Depth, ModelTier, RouteDecision
from plaidnox_scm.context_store import ApplicationContext
from plaidnox_scm.evidence import EvidenceRole
from plaidnox_scm.l1_review import ChangedLines, ExpansionRequest, L1Candidate
from plaidnox_scm.verification import SastDeepHuntVerifier


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


class _Agent:
    def __init__(self) -> None:
        self.graph = None
        self.calls = []

    def configure_security_graph(self, graph) -> None:
        self.graph = graph

    def hunt(self, root, candidate, finding, security_context, model_tier, route):
        self.calls.append((candidate, finding, security_context, model_tier, route))
        return DeepHuntResult(
            supported=True,
            confidence=0.97,
            reasoning="The changed boundary accepts unauthenticated claims.",
            attack_path="token -> decode -> identity",
            remediation_note="Restore cryptographic verification.",
            title="JWT authenticity check removed",
            vulnerability_class="authentication bypass",
            severity="high",
            message="Decoded claims become trusted identity.",
            business_impact="An attacker can impersonate another user.",
            classification_references=[],
            falsification_attempts=["Searched the changed control for signature validation."],
            required_preconditions=["Attacker can submit a token."],
            evidence_gaps=[],
            security_invariant="Only authentic claims establish identity.",
            gained_capability="impersonate user",
            rejection_reason="",
            gate_results=[],
            evidence_locations=[
                {"path": "middleware.js", "start_line": 2, "end_line": 2, "role": "defense"}
            ],
            proof_plan="Submit a forged token in an isolated test.",
            regression_test="Reject a token with an invalid signature.",
            context_requests=[],
        )


class _Router:
    def classify(self, candidate):
        return RouteDecision(
            depth=Depth.FAST,
            reason="fixture route",
            model_tier=ModelTier.FAST,
        )


def _context(base: str) -> ApplicationContext:
    return ApplicationContext(
        codebase_id="codebase-1",
        tenant_id="tenant-a",
        baseline_revision=base,
        source_tree_hash="tree",
        builder_version="fixture",
        application_type="node-api",
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


def test_sast_verifier_uses_head_snapshot_and_enforces_change_minimum_depth(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "tests@plaidnox.local")
    _git(repo, "config", "user.name", "PlaidNox Tests")
    (repo / "middleware.js").write_text("function validate(token) {\n  return jwt.decode(token);\n}\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    hypothesis = L1Candidate(
        candidate_id="jwt-regression",
        changed_path="middleware.js",
        changed_symbol="validate",
        changed_lines=ChangedLines(2, 2),
        behavior_before="Signature verified.",
        behavior_after="Claims decoded only.",
        security_role="Authentication boundary.",
        suspected_broken_invariant="Only authentic claims establish identity.",
        provisional_attacker_capability="Forge identity claims.",
        context_facts_used=(),
        context_gaps=(),
        requested_expansion=(
            ExpansionRequest(
                "window",
                "middleware.js:1-3",
                "Load the complete changed authentication control.",
            ),
        ),
    )
    agent = _Agent()

    results = SastDeepHuntVerifier(agent, router=_Router()).verify(
        repo,
        head,
        "codebase-1",
        _context(head),
        (hypothesis,),
        "DEEP",
    )

    assert agent.graph is not None
    assert len(agent.calls) == 1
    assert agent.calls[0][4].depth is Depth.DEEP
    assert agent.calls[0][3] is ModelTier.DEEP
    supplied_context = json.loads(agent.calls[0][2])
    assert supplied_context["candidate_context_expansion"]["complete"] is True
    assert results[0].state == "verified"
    assert results[0].severity == "high"
    assert {item.role for item in results[0].evidence} == {
        EvidenceRole.ROOT_CAUSE_CHANGED_CODE,
        EvidenceRole.DEFENSE_REMOVED_OR_BYPASSED,
        EvidenceRole.CONTEXT_ONLY,
    }


def test_missing_candidate_specific_context_keeps_supported_review_unresolved(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "tests@plaidnox.local")
    _git(repo, "config", "user.name", "PlaidNox Tests")
    (repo / "middleware.js").write_text("function validate(token) {\n  return jwt.decode(token);\n}\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    hypothesis = L1Candidate(
        candidate_id="cross-file-proof",
        changed_path="middleware.js",
        changed_symbol="validate",
        changed_lines=ChangedLines(2, 2),
        behavior_before="Signature verified.",
        behavior_after="Claims decoded only.",
        security_role="Authentication boundary.",
        suspected_broken_invariant="Only authentic claims establish identity.",
        provisional_attacker_capability="Forge identity claims.",
        context_facts_used=(),
        context_gaps=("Ownership control not yet located.",),
        requested_expansion=(
            ExpansionRequest(
                "definition",
                "missingOwnershipCheck",
                "Required cross-file ownership proof.",
            ),
        ),
    )

    results = SastDeepHuntVerifier(_Agent(), router=_Router()).verify(
        repo,
        head,
        "codebase-1",
        _context(head),
        (hypothesis,),
        "DEEP",
    )

    assert results[0].state == "unresolved"
    assert results[0].context_expansion is not None
    assert results[0].context_expansion.complete is False
    assert any("missingOwnershipCheck" in gap for gap in results[0].evidence_gaps)
