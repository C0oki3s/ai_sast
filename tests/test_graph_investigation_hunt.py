from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from plaidnox_sast.ai import AIResponseError, PlaidNoxDeepHuntAgent
from plaidnox_sast.investigations import build_investigation


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
    observed = {}

    def structured(name, schema, operation, payload, **kwargs):
        observed.update(name=name, operation=operation, payload=payload, kwargs=kwargs)
        return SimpleNamespace(output_text=json.dumps(response))

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

    with pytest.raises(AIResponseError, match="each security question exactly once"):
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
