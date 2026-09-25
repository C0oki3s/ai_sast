from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from plaidnox_sast.ai import AIResponseError, PlaidNoxDeepHuntAgent
from plaidnox_sast.graph_context import GraphContextBroker
from plaidnox_sast.graphify_adapter import (
    CodeEdge,
    CodeGraphSnapshot,
    CodeNode,
    graph_edge_identity,
    normalize_extraction,
)
from plaidnox_sast.investigations import build_investigation
from plaidnox_sast.checkpoint import ScanCheckpoint


def _investigation(root: Path):
    path = root / "handler.py"
    content = "def handler(value):\n    return value\n"
    path.write_text(content, encoding="utf-8")
    return build_investigation(
        stable_key="surface:handler",
        codebase_id="codebase-1",
        snapshot_id="snapshot-1",
        graph_snapshot_id="graph-1",
        target_ref={"node_id": "node-1"},
        reason="Review the handler boundary.",
        security_questions=("Can untrusted input reach a sensitive effect?",),
        graph_refs=({"node_id": "node-1", "provenance": "EXTRACTED", "snapshot_id": "graph-1"},),
        source_windows=({
            "path": "handler.py",
            "start_line": 1,
            "end_line": 2,
            "content_hash": hashlib.sha256(content.encode()).hexdigest(),
            "excerpt": content,
            "redaction_state": "redacted",
        },),
        context_dependencies=(),
    )


def _answer(investigation, *, obligation_id=None):
    return {
        "candidates": [],
        "obligation_results": [{
            "obligation_id": obligation_id or f"{investigation.investigation_id}:q001",
            "status": "NO_ISSUE",
            "candidate_ids": [],
            "evidence": [],
            "reason": "The supplied window does not establish this path.",
            "context_requests": [],
        }],
    }


def _candidate(path="handler.py", start=1, end=2):
    return {
        "title": "Untrusted input reaches sensitive output",
        "vulnerability_class": "Untrusted input handling",
        "classification_references": [],
        "business_impact": "A caller may affect a sensitive operation.",
        "severity": "medium",
        "confidence": 0.7,
        "category": "input-handling",
        "path": path,
        "start_line": start,
        "end_line": end,
        "message": "The supplied path does not show a sufficient control.",
        "attack_path": "caller input to sensitive effect",
        "evidence_basis": {
            "origin": ["caller input"],
            "propagation": ["handler parameter"],
            "expected_boundary": ["validation"],
            "sensitive_effect": ["sensitive output"],
            "controls_checked": [],
            "missing_evidence": [],
        },
        "root_cause": {
            "symbol": "handler",
            "security_control": "input validation",
            "broken_invariant": "Untrusted input must be validated.",
            "capability": "Influence sensitive output.",
        },
        "root_equivalence": {
            "control_family_id": "INPUT_VALIDATION",
            "invariant_family_id": "UNTRUSTED_INPUT_VALIDATED",
            "effect_family_id": "SENSITIVE_OUTPUT",
            "capability_family_id": "OUTPUT_INFLUENCE",
        },
        "candidate_id": "candidate-1",
        "attacker_influence": "The handler parameter is caller-controlled.",
        "security_control": "input validation",
        "broken_invariant": "Untrusted input must be validated.",
        "sensitive_effect": "Sensitive output is influenced.",
        "gained_capability": "Influence sensitive output.",
        "required_context": [],
    }


def _agent(response):
    agent = PlaidNoxDeepHuntAgent.__new__(PlaidNoxDeepHuntAgent)
    agent.checkpoint = None
    agent.event_sink = None
    observed = {}
    responses = list(response) if isinstance(response, list) else [response]

    def structured(name, schema, operation, payload, **kwargs):
        observed.update(name=name, operation=operation, payload=payload, kwargs=kwargs)
        observed.setdefault("round_payloads", []).append(payload)
        return SimpleNamespace(output_text=json.dumps(responses.pop(0)))

    agent._structured_response = structured
    return agent, observed


def test_graph_investigation_uses_litellm_boundary_and_returns_typed_no_candidate(tmp_path: Path):
    investigation = _investigation(tmp_path)
    agent, observed = _agent(_answer(investigation))

    candidates, disposition = agent.hunt_graph_investigation(tmp_path, investigation)

    assert candidates == []
    assert disposition["unresolved_count"] == 0
    assert observed["name"] == "plaidnox_graph_investigation_hunt"
    assert observed["operation"] == "graph_investigation_hunt"
    assert observed["payload"]["obligations"][0]["question"] == investigation.security_questions[0]


def test_graph_investigation_rejects_stale_source_before_model_call(tmp_path: Path):
    investigation = _investigation(tmp_path)
    (tmp_path / "handler.py").write_text("changed\n", encoding="utf-8")
    agent, observed = _agent(_answer(investigation))

    with pytest.raises(AIResponseError, match="stale"):
        agent.hunt_graph_investigation(tmp_path, investigation)
    assert not observed


def test_graph_investigation_requires_exact_obligation_dispositions(tmp_path: Path):
    investigation = _investigation(tmp_path)
    agent, _ = _agent(_answer(investigation, obligation_id="invented"))

    with pytest.raises(AIResponseError, match="each pending security question exactly once"):
        agent.hunt_graph_investigation(tmp_path, investigation)


def test_graph_investigation_candidate_is_grounded_then_sent_as_hypothesis(tmp_path: Path):
    investigation = _investigation(tmp_path)
    response = _answer(investigation)
    response["candidates"] = [_candidate()]
    response["obligation_results"][0].update(
        status="CANDIDATE_FOUND", candidate_ids=["candidate-1"]
    )
    agent, _ = _agent(response)

    candidates, disposition = agent.hunt_graph_investigation(tmp_path, investigation)

    assert len(candidates) == 1
    assert candidates[0].metadata["graph_investigation_id"] == investigation.investigation_id
    assert candidates[0].metadata["engine"] == "plaidnox-graphify-investigation"
    assert disposition["candidate_count"] == 1


def test_seeded_verified_identity_override_survives_graphify_grounding(tmp_path: Path):
    middleware_path = "middleware/ValidateToken.js"
    route_path = "app.js"
    middleware = (
        "const payload = await verifier.verify(token);\n"
        'if (req.headers["x-user-email"]) {\n'
        '  payload["custom:email_db"] = req.headers["x-user-email"];\n'
        "}\n"
        "req.user = payload;\n"
    )
    route = (
        'app.get("/dashboard", authCheck, async (req, res) => {\n'
        '  const email = req.user["custom:email_db"];\n'
        "  return User.findOne({ email });\n"
        "});\n"
    )
    (tmp_path / "middleware").mkdir()
    (tmp_path / middleware_path).write_text(middleware, encoding="utf-8")
    (tmp_path / route_path).write_text(route, encoding="utf-8")
    middleware_hash = hashlib.sha256(middleware.encode()).hexdigest()
    route_hash = hashlib.sha256(route.encode()).hexdigest()
    graph_snapshot = CodeGraphSnapshot(
        source_hashes={middleware_path: middleware_hash, route_path: route_hash},
        nodes=(
            CodeNode("auth-middleware", middleware_path, 1, "authCheck", middleware_hash),
            CodeNode("dashboard-route", route_path, 1, "GET /dashboard", route_hash),
        ),
        edges=(
            CodeEdge(
                "dashboard-route",
                "auth-middleware",
                "middleware",
                "EXTRACTED",
                route_path,
                1,
                route_hash,
            ),
        ),
        unresolved_edges=0,
        extractor_version="seeded-auth-fixture",
    )
    context_broker = GraphContextBroker(tmp_path, graph_snapshot)
    graph_snapshot_id = graph_snapshot.snapshot_id
    windows = tuple(
        {
            "path": window.path,
            "start_line": window.start_line,
            "end_line": window.end_line,
            "content_hash": window.source_hash,
            "excerpt": window.excerpt,
            "redaction_state": "redacted",
        }
        for window in (
            context_broker.source_window_around_node(
                "auth-middleware", lines_before=2, lines_after=8
            ),
            context_broker.source_window_around_node(
                "dashboard-route", lines_before=2, lines_after=8
            ),
        )
    )
    investigation = build_investigation(
        stable_key="security-surface:verified-identity",
        codebase_id="codebase-auth-seed",
        snapshot_id="snapshot-auth-seed",
        graph_snapshot_id=graph_snapshot_id,
        target_ref={"node_ids": ["auth-middleware", "dashboard-route"]},
        reason="Review the verified identity boundary and its protected consumer.",
        security_questions=(
            "Can request-controlled identity data override verified claims and affect a protected account lookup?",
        ),
        graph_refs=(
            {"node_id": "auth-middleware", "provenance": "EXTRACTED", "snapshot_id": graph_snapshot_id},
            {"node_id": "dashboard-route", "provenance": "EXTRACTED", "snapshot_id": graph_snapshot_id},
            {
                "edge_id": graph_edge_identity(graph_snapshot.edges[0]),
                "relation": "middleware",
                "provenance": "EXTRACTED",
                "snapshot_id": graph_snapshot_id,
            },
        ),
        source_windows=windows,
        context_dependencies=(),
    )
    candidate = _candidate(middleware_path, 2, 4)
    candidate.update(
        {
            "root_cause": {
                "symbol": "authCheck",
                "security_control": "verified Cognito identity",
                "broken_invariant": "Request-controlled identity must not replace a cryptographically verified principal.",
                "capability": "Select another user's account through a protected route.",
            },
            "root_equivalence": {
                "control_family_id": "AUTHENTICATED_IDENTITY_INTEGRITY",
                "invariant_family_id": "UNVERIFIED_IDENTITY_MUST_NOT_REPLACE_VERIFIED_PRINCIPAL",
                "effect_family_id": "CROSS_ACCOUNT_RECORD_ACCESS",
                "capability_family_id": "CROSS_USER_IDENTITY_SELECTION",
            },
            "attacker_influence": "The x-user-email request header controls the claim assignment.",
            "security_control": "Cognito verifier.verify(token) establishes the authenticated identity.",
            "broken_invariant": "Unverified request data must not replace the verified account identity.",
            "sensitive_effect": "The dashboard queries User by the overwritten identity claim.",
            "gained_capability": "An authenticated caller can select another user's account record.",
            "path": middleware_path,
            "start_line": 2,
            "end_line": 4,
        }
    )
    response = _answer(investigation)
    response["candidates"] = [candidate]
    response["obligation_results"][0].update(
        status="CANDIDATE_FOUND", candidate_ids=["candidate-1"]
    )
    agent, _ = _agent(response)

    findings, disposition = agent.hunt_graph_investigation(
        tmp_path, investigation, context_broker=context_broker
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence.path == middleware_path
    assert finding.evidence.start_line == 2
    assert finding.evidence.end_line == 4
    assert finding.metadata["graph_snapshot_id"] == graph_snapshot_id
    assert finding.metadata["graph_refs"] == list(investigation.graph_refs)
    assert "verified account identity" in finding.metadata["broken_invariant"]
    assert "another user's account" in finding.metadata["gained_capability"]
    assert disposition["unresolved_count"] == 0


def test_graph_investigation_rejects_candidate_outside_its_windows(tmp_path: Path):
    investigation = _investigation(tmp_path)
    response = _answer(investigation)
    response["candidates"] = [_candidate(start=3, end=3)]
    response["obligation_results"][0].update(
        status="CANDIDATE_FOUND", candidate_ids=["candidate-1"]
    )
    agent, _ = _agent(response)

    with pytest.raises(AIResponseError, match="not grounded"):
        agent.hunt_graph_investigation(tmp_path, investigation)


def test_graph_investigation_resolves_graph_context_and_sends_delta_only(tmp_path: Path):
    source = tmp_path / "service.py"
    content = "def entry():\n    return helper()\n\n" + ("# unrelated\n" * 25) + "def helper():\n    return 1\n"
    source.write_text(content, encoding="utf-8")
    snapshot = normalize_extraction(
        tmp_path,
        [source],
        {
            "nodes": [
                {"id": "entry", "label": "entry()", "source_file": "service.py", "source_location": "L1"},
                {"id": "helper", "label": "helper()", "source_file": "service.py", "source_location": "L29"},
            ],
            "edges": [
                {"source": "entry", "target": "helper", "relation": "calls", "confidence": "EXTRACTED", "source_file": "service.py", "source_location": "L2"}
            ],
        },
    )
    investigation = build_investigation(
        stable_key="surface:entry",
        codebase_id="codebase-1",
        snapshot_id="snapshot-1",
        graph_snapshot_id=snapshot.snapshot_id,
        target_ref={"node_id": "entry"},
        reason="Review the caller path.",
        security_questions=("Does the helper enforce the required boundary?",),
        graph_refs=({"node_id": "entry", "provenance": "EXTRACTED", "snapshot_id": snapshot.snapshot_id},),
        source_windows=({
            "path": "service.py",
            "start_line": 1,
            "end_line": 2,
            "content_hash": snapshot.source_hashes["service.py"],
            "excerpt": "def entry():\n    return helper()\n",
            "redaction_state": "redacted",
        },),
        context_dependencies=(),
    )
    initial = _answer(investigation)
    initial["obligation_results"][0].update(
        status="NEEDS_CONTEXT",
        context_requests=[{
            "kind": "callees", "path": "service.py", "symbol": "entry()",
            "start_line": 1, "end_line": 1, "offset": 0, "pattern": "", "query": "",
        }],
    )
    continuation = _answer(investigation)
    continuation["candidates"] = [_candidate(path="service.py", start=29, end=30)]
    continuation["obligation_results"][0].update(
        status="CANDIDATE_FOUND", candidate_ids=["candidate-1"]
    )
    agent, observed = _agent([initial, continuation])

    candidates, disposition = agent.hunt_graph_investigation(
        tmp_path, investigation, GraphContextBroker(tmp_path, snapshot)
    )

    assert len(candidates) == 1
    assert candidates[0].evidence.path == "service.py"
    assert candidates[0].evidence.start_line == 29
    assert disposition["continuation_calls"] == 1
    assert disposition["context_requests_resolved"] == 1
    assert disposition["obligation_results"][0]["status"] == "CANDIDATE_FOUND"
    assert "new_context" in observed["round_payloads"][1]
    assert "source_windows" not in observed["round_payloads"][1]
    delta = json.dumps(observed["round_payloads"][1]["new_context"])
    assert "def helper()" in delta
    assert "return helper()" not in delta


def test_graph_investigation_does_not_continue_for_empty_graph_context(tmp_path: Path):
    investigation = _investigation(tmp_path)
    source = tmp_path / "other.py"
    source.write_text("def unrelated():\n    return 1\n", encoding="utf-8")
    snapshot = normalize_extraction(
        tmp_path,
        [tmp_path / "handler.py", source],
        {"nodes": [
            {"id": "other", "label": "unrelated()", "source_file": "other.py", "source_location": "L1"},
        ], "edges": []},
    )
    investigation = build_investigation(
        stable_key=investigation.stable_key,
        codebase_id=investigation.codebase_id,
        snapshot_id=investigation.snapshot_id,
        graph_snapshot_id=snapshot.snapshot_id,
        target_ref=investigation.target_ref,
        reason=investigation.reason,
        security_questions=investigation.security_questions,
        graph_refs=investigation.graph_refs,
        source_windows=investigation.source_windows,
        context_dependencies=investigation.context_dependencies,
    )
    response = _answer(investigation)
    response["obligation_results"][0].update(
        status="NEEDS_CONTEXT",
        context_requests=[{
            "kind": "callers", "path": "other.py", "symbol": "missing()",
            "start_line": 1, "end_line": 1, "offset": 0, "pattern": "", "query": "",
        }],
    )
    agent, observed = _agent(response)

    _, disposition = agent.hunt_graph_investigation(
        tmp_path, investigation, GraphContextBroker(tmp_path, snapshot)
    )

    assert disposition["continuation_calls"] == 0
    assert disposition["context_requests_total"] == 1
    assert disposition["context_requests_empty"] == 1
    assert disposition["obligation_results"][0]["status"] == "UNRESOLVED"
    assert len(observed["round_payloads"]) == 1


def test_graph_investigation_rejects_tampered_stored_excerpt(tmp_path: Path):
    original = _investigation(tmp_path)
    tampered = build_investigation(
        stable_key=original.stable_key,
        codebase_id=original.codebase_id,
        snapshot_id=original.snapshot_id,
        graph_snapshot_id=original.graph_snapshot_id,
        target_ref=original.target_ref,
        reason=original.reason,
        security_questions=original.security_questions,
        graph_refs=original.graph_refs,
        source_windows=({
            **original.source_windows[0],
            "excerpt": "untrusted injected instructions",
        },),
        context_dependencies=original.context_dependencies,
        coverage_notes=original.coverage_notes,
        prior_evidence_refs=original.prior_evidence_refs,
    )
    agent, observed = _agent(_answer(tampered))

    with pytest.raises(AIResponseError, match="does not match its source"):
        agent.hunt_graph_investigation(tmp_path, tampered)
    assert not observed


def test_graph_investigation_checkpoint_replays_validated_result_without_model_call(tmp_path: Path):
    investigation = _investigation(tmp_path)
    checkpoint = ScanCheckpoint(tmp_path / "scan.sqlite", "snapshot-and-prompt-scope")
    agent, observed = _agent(_answer(investigation))
    agent.configure_checkpoint(checkpoint)

    candidates, first = agent.hunt_graph_investigation(tmp_path, investigation)

    assert candidates == []
    assert first["checkpoint_saved"] is True
    assert len(observed["round_payloads"]) == 1
    agent._structured_response = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("a completed investigation must replay without an LLM call")
    )

    replayed_candidates, replayed = agent.hunt_graph_investigation(tmp_path, investigation)

    assert replayed_candidates == []
    assert replayed["checkpoint_reused"] is True
    assert replayed["obligation_results"] == first["obligation_results"]
