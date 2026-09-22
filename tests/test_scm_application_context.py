from __future__ import annotations

import subprocess
from pathlib import Path

from plaidnox_sast.ai import AIRepositoryContext
from plaidnox_scm.application_context import SastApplicationContextBuilder


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True).stdout.strip()


class _ContextAgent:
    def __init__(self) -> None:
        self.source_seen = ""

    def build_repository_context(self, root, codebase, revision, graph, business_context=""):
        self.source_seen = (root / "auth.js").read_text()
        return AIRepositoryContext(
            codebase=codebase,
            revision=revision,
            architecture="Node API with authentication middleware",
            applications=[
                {
                    "app_name": "api",
                    "app_root_path": ".",
                    "architecture": "HTTP API",
                    "entry_points": ["auth.js"],
                    "trust_boundaries": ["HTTP request to authenticated identity"],
                    "data_stores": [],
                    "authentication": ["auth.js verifies bearer tokens"],
                    "authorization": [],
                    "sensitive_operations": ["establish identity"],
                    "external_services": [],
                    "business_workflows": [],
                }
            ],
            source_inventory=[{"path": "auth.js", "language": "javascript", "lines": 1}],
            source_tree=["auth.js"],
            graph_symbols=len(graph.symbols),
            graph_routes=len(graph.routes),
            security_invariants=["Only verified claims establish identity."],
            production_areas=[
                {
                    "name": "api",
                    "root_path": ".",
                    "runtime_role": "HTTP API",
                    "coverage_state": "complete",
                    "evidence": ["auth.js"],
                    "gaps": [],
                }
            ],
            entry_points=[
                {
                    "entry_id": "auth",
                    "application": "api",
                    "entry_type": "middleware",
                    "location": "auth.js:1",
                    "operation": "authenticate",
                    "trust_level": "untrusted",
                    "inputs": ["bearer token"],
                }
            ],
            authentication_paths=[{"location": "auth.js:1", "control": "signature verification"}],
            coverage_ledger=[
                {
                    "obligation": "authentication boundary",
                    "status": "complete",
                    "next_focus": "",
                    "evidence": ["auth.js"],
                    "gaps": [],
                }
            ],
        )


def test_builder_computes_context_from_base_snapshot_not_pr_head(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "tests@plaidnox.local")
    _git(repo, "config", "user.name", "PlaidNox Tests")
    (repo / "auth.js").write_text("const claims = verifier.verify(token);\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "auth.js").write_text("const claims = jwt.decode(token);\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "head")
    agent = _ContextAgent()

    context = SastApplicationContextBuilder(agent).build(repo, base, "codebase-1", "tenant-a")

    assert "verifier.verify" in agent.source_seen
    assert "jwt.decode" not in agent.source_seen
    assert context.baseline_revision == base
    assert context.source_tree_hash == _git(repo, "rev-parse", f"{base}^{{tree}}")
    assert context.security_controls
    assert context.confidence == 1.0
