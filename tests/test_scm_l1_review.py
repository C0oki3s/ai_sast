from __future__ import annotations

import json
import subprocess
from dataclasses import fields
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from plaidnox_scm.change_relevance import classify
from plaidnox_scm.context_store import ApplicationContext
from plaidnox_scm.diffing import compute_diff
from plaidnox_scm.l1_review import L1ReviewError, LiteLLMChangedFileReviewer


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


def _repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "tests@plaidnox.local")
    _git(repo, "config", "user.name", "PlaidNox Tests")
    source = repo / "middleware.js"
    source.write_text("function validate(token) {\n  return verifier.verify(token);\n}\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    source.write_text("function validate(token) {\n  return jwt.decode(token);\n}\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "head")
    return repo, base, _git(repo, "rev-parse", "HEAD")


def _context(base: str) -> ApplicationContext:
    return ApplicationContext(
        codebase_id="codebase-1",
        tenant_id="tenant-a",
        baseline_revision=base,
        source_tree_hash="tree",
        builder_version="fixture",
        application_type="node-api",
        entry_points=({"location": "middleware.js"},),
        components=({"name": "api"},),
        security_controls=({"kind": "authentication"},),
        routes=(),
        sensitive_effects=(),
        environment_metadata={},
        identity_provider=None,
        prior_finding_refs=(),
        confidence=1.0,
        context_version="2",
        computed_at=datetime.now(UTC),
    )


class _Responses:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(status="completed", output_text=json.dumps(self.payload))


class _Client:
    def __init__(self, payload: dict[str, object]) -> None:
        self.responses = _Responses(payload)


def _payload(start_line: int = 2) -> dict[str, object]:
    return {
        "candidates": [
            {
                "candidate_id": "jwt-regression",
                "changed_path": "middleware.js",
                "changed_symbol": "validate",
                "changed_lines": {"start": start_line, "end": start_line},
                "behavior_before": "The signature was verified.",
                "behavior_after": "Claims are decoded only.",
                "security_role": "Authentication boundary.",
                "suspected_broken_invariant": "Only authentic claims establish identity.",
                "provisional_attacker_capability": "Forge identity claims.",
                "context_facts_used": ["The file is an authentication control."],
                "context_gaps": ["Downstream protected route usage is not supplied."],
                "requested_expansion": [
                    {"kind": "route", "target": "validate", "reason": "Confirm downstream trust."}
                ],
            }
        ],
        "coverage_complete": True,
        "coverage_gaps": [],
    }


def test_l1_review_uses_changed_file_context_and_returns_lean_candidate(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path)
    diff = compute_diff(repo, base, head)
    client = _Client(_payload())

    result = LiteLLMChangedFileReviewer(client).review(repo, diff, classify(diff), _context(base))

    assert result.model_calls == 1
    assert result.reviewed_paths == ("middleware.js",)
    assert result.candidates[0].suspected_broken_invariant.startswith("Only authentic")
    assert result.candidates[0].requested_expansion[0].kind == "route"
    request = client.responses.calls[0]
    assert request["text"]["format"]["type"] == "json_schema"
    candidate_fields = {item.name for item in fields(result.candidates[0])}
    assert not {"severity", "cwe", "remediation", "merge_action"}.intersection(candidate_fields)


def test_l1_review_rejects_candidate_not_anchored_to_changed_lines(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path)
    diff = compute_diff(repo, base, head)

    with pytest.raises(L1ReviewError, match="changed line range"):
        LiteLLMChangedFileReviewer(_Client(_payload(start_line=99))).review(
            repo, diff, classify(diff), _context(base)
        )


def test_l1_review_skips_docs_in_mixed_pr_and_scopes_relevance_to_runtime_file(
    tmp_path: Path,
) -> None:
    repo, base, _head = _repo(tmp_path)
    (repo / "RETEST_NOTES.md").write_text("Trigger a fresh review.\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add retest notes")
    head = _git(repo, "rev-parse", "HEAD")
    diff = compute_diff(repo, base, head)
    client = _Client(_payload())

    result = LiteLLMChangedFileReviewer(client).review(repo, diff, classify(diff), _context(base))

    assert result.reviewed_paths == ("RETEST_NOTES.md", "middleware.js")
    assert result.model_calls == 1
    assert len(client.responses.calls) == 1
    rendered_user_prompt = str(client.responses.calls[0]["input"][1]["content"])
    assert '"changed_files": [' in rendered_user_prompt
    assert '"middleware.js"' in rendered_user_prompt
    assert "RETEST_NOTES.md" not in rendered_user_prompt
