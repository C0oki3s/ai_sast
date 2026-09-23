from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from plaidnox_sast.graph import build_structural_graph
from plaidnox_scm.context_broker import SCMContextBroker
from plaidnox_scm.context_store import ApplicationContext
from plaidnox_scm.l1_review import ChangedLines, ExpansionRequest, L1Candidate


def _context() -> ApplicationContext:
    return ApplicationContext(
        codebase_id="codebase-1",
        tenant_id="tenant-a",
        baseline_revision="base",
        source_tree_hash="tree",
        builder_version="fixture",
        application_type="node-api",
        entry_points=({"path": "/reports", "handler": "report"},),
        components=({"name": "api"},),
        security_controls=({"kind": "authentication", "symbol": "validate"},),
        routes=({"path": "/reports", "handler": "report", "middleware": "validate"},),
        sensitive_effects=({"operation": "read report"},),
        environment_metadata={},
        identity_provider=None,
        prior_finding_refs=(),
        confidence=1.0,
        context_version="2",
        computed_at=datetime.now(UTC),
    )


def _candidate(*requests: ExpansionRequest) -> L1Candidate:
    return L1Candidate(
        candidate_id="candidate-1",
        changed_path="auth.js",
        changed_symbol="validate",
        changed_lines=ChangedLines(2, 2),
        behavior_before="Verified token.",
        behavior_after="Decoded token.",
        security_role="Authentication boundary.",
        suspected_broken_invariant="Only verified claims establish identity.",
        provisional_attacker_capability="Forge identity claims.",
        context_facts_used=(),
        context_gaps=(),
        requested_expansion=tuple(requests),
    )


def test_context_broker_resolves_exact_tree_sitter_route_window_and_search_requests(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "export function validate(token) {\n  return verifier.verify(token);\n}\n"
    )
    (tmp_path / "routes.js").write_text(
        "import { validate } from './auth.js';\n"
        "export function report(req) {\n  return validate(req.token);\n}\n"
    )
    graph = build_structural_graph(tmp_path)
    candidate = _candidate(
        ExpansionRequest("definition", "validate", "Load the authentication control."),
        ExpansionRequest("callers", "validate", "Find direct consumers."),
        ExpansionRequest("imports", "routes.js", "Confirm how the control is imported."),
        ExpansionRequest("route", "/reports", "Confirm protected route context."),
        ExpansionRequest("window", "auth.js:1-3", "Load the bounded changed control."),
        ExpansionRequest("sibling_handlers", "auth.js", "Inspect neighboring handlers."),
        ExpansionRequest("search", "validate\\(", "Find exact textual references."),
        ExpansionRequest("flow", "validate", "Resolve adjacent call edges."),
    )

    expansion = SCMContextBroker().expand(tmp_path, graph, candidate, _context())

    assert expansion.complete is True
    assert len(expansion.evidence) == 8
    assert all(item.records for item in expansion.evidence)
    assert any(record.get("path") == "routes.js" for item in expansion.evidence for record in item.records)
    compact = expansion.to_prompt_dict(600)
    assert len(json.dumps(compact)) <= 600
    assert compact["prompt_truncated"] is True


def test_context_broker_preserves_missing_cross_file_proof_as_unresolved(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text("export function validate(token) { return token; }\n")
    graph = build_structural_graph(tmp_path)
    candidate = _candidate(
        ExpansionRequest(
            "definition",
            "missingOwnershipCheck",
            "Ownership enforcement is required to prove or reject the hypothesis.",
        )
    )

    expansion = SCMContextBroker().expand(tmp_path, graph, candidate, _context())

    assert expansion.complete is False
    assert expansion.unresolved_gaps
    assert "missingOwnershipCheck" in expansion.unresolved_gaps[0]


def test_context_broker_blocks_path_escape_and_redacts_secret_shaped_evidence(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.py"
    outside.write_text("do_not_read = True\n")
    (tmp_path / "auth.js").write_text("export function validate(token) { return token; }\n")
    (tmp_path / "config.js").write_text("const key = 'AKIAABCDEFGHIJKLMNOP';\n")
    graph = build_structural_graph(tmp_path)
    candidate = _candidate(
        ExpansionRequest("window", "../outside.py:1-1", "Attempted path escape."),
        ExpansionRequest("window", "config.js:1-1", "Inspect relevant configuration."),
    )

    expansion = SCMContextBroker().expand(tmp_path, graph, candidate, _context())

    assert expansion.complete is False
    assert expansion.evidence[0].resolved is False
    redacted = expansion.evidence[1].records[0]["content"]
    assert "AKIAABCDEFGHIJKLMNOP" not in redacted
    assert "<redacted-aws-access-key>" in redacted


def test_context_broker_resolves_definition_requests_given_as_paths(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text("export function validate(token) { return token; }\n")
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "user.js").write_text(
        "const mongoose = require('mongoose');\n"
        "const User = mongoose.model('User', new mongoose.Schema({ email: String }));\n"
        "module.exports = User;\n"
    )
    graph = build_structural_graph(tmp_path)
    candidate = _candidate(
        ExpansionRequest("definition", "auth.js", "Path with extracted symbols."),
        ExpansionRequest("definition", "auth.js:validate", "Path-qualified symbol."),
        ExpansionRequest("definition", "models/user.js", "Path with no extracted symbols."),
        ExpansionRequest("definition", "User", "Binding Tree-sitter does not index."),
    )

    expansion = SCMContextBroker().expand(tmp_path, graph, candidate, _context())

    assert expansion.complete is True
    assert expansion.evidence[0].records[0]["symbol"] == "validate"
    assert expansion.evidence[1].records[0]["path"] == "auth.js"
    assert "mongoose.model" in expansion.evidence[2].records[0]["content"]
    assert expansion.evidence[3].records[0]["path"] == "models/user.js"


def test_context_broker_resolves_path_plus_human_definition_hints(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("const User = require('./models/NST');\n")
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "NST.js").write_text(
        "const User = mongoose.model('User', new mongoose.Schema({ email: String }));\n"
    )
    (tmp_path / "middleware").mkdir()
    (tmp_path / "middleware" / "xss.js").write_text(
        "function sanitizerMiddleware(req, res, next) { return next(); }\n"
    )
    graph = build_structural_graph(tmp_path)
    candidate = _candidate(
        ExpansionRequest("definition", "models/NST.js User schema", "Load the schema."),
        ExpansionRequest(
            "definition",
            "middleware/xss.js sanitizerMiddleware",
            "Load the sanitizer.",
        ),
    )

    expansion = SCMContextBroker().expand(tmp_path, graph, candidate, _context())

    assert expansion.complete is True
    assert expansion.evidence[0].records[0]["path"] == "models/NST.js"
    assert "mongoose.model" in expansion.evidence[0].records[0]["content"]
    assert expansion.evidence[1].records[0]["path"] == "middleware/xss.js"
    assert "sanitizerMiddleware" in expansion.evidence[1].records[0]["content"]
