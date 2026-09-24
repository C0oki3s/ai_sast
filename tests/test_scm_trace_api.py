from datetime import UTC, datetime

from plaidnox_scm.api_models import ReviewFinding
from plaidnox_scm.api_service import _api_evidence_trace, _api_vulnerable_snippet
from plaidnox_scm.evidence import EvidenceRole
from plaidnox_scm.trace import (
    EvidenceTrace,
    EvidenceTraceEdge,
    EvidenceTraceNode,
    VulnerableSnippet,
)


def _finding(**overrides):
    values = {
        "finding_id": "finding-1",
        "root_cause_fingerprint": "root-1",
        "title": "Identity claim can be overwritten",
        "severity": "high",
        "confidence": 0.99,
        "description": "A request header can replace a verified identity claim.",
        "root_cause_path": "middleware/ValidateToken.js",
        "root_cause_symbol": "authCheck",
        "root_cause_start_line": 54,
        "root_cause_end_line": 60,
        "root_cause_changed_in_pr": True,
        "baseline_relationship": "introduced",
        "tenant_id": "github:installation:1",
        "repository_id": 2,
        "base_revision": "a" * 40,
        "head_revision": "b" * 40,
        "verified_at": datetime.now(UTC),
    }
    values.update(overrides)
    return ReviewFinding(**values)


def test_review_finding_omits_trace_fields_when_verifier_has_none():
    payload = _finding().model_dump(mode="json")

    assert "vulnerable_snippet" not in payload
    assert "evidence_trace" not in payload


def test_verified_snippet_and_branching_trace_are_provider_neutral():
    snippet = VulnerableSnippet(
        path="middleware/ValidateToken.js",
        start_line=54,
        end_line=60,
        content='if (req.headers["x-user-email"]) { payload.email = req.headers["x-user-email"]; }',
    )
    source = EvidenceTraceNode(
        node_id="trace_source",
        role=EvidenceRole.ATTACKER_ORIGIN,
        path="middleware/ValidateToken.js",
        start_line=54,
        end_line=54,
        label="Attacker origin",
        summary="x-user-email request header",
    )
    trust = EvidenceTraceNode(
        node_id="trace_trust",
        role=EvidenceRole.DOWNSTREAM_TRUST,
        path="app.js",
        start_line=151,
        end_line=151,
        label="Downstream trust",
        summary="dashboard trusts req.user custom email",
    )
    effect = EvidenceTraceNode(
        node_id="trace_effect",
        role=EvidenceRole.SENSITIVE_EFFECT,
        path="app.js",
        start_line=200,
        end_line=200,
        label="Sensitive effect",
        summary="cross-user resource lookup",
    )
    trace = EvidenceTrace(
        trace_type="taint_and_trust",
        nodes=(source, trust, effect),
        edges=(
            EvidenceTraceEdge("trace_source", "trace_trust"),
            EvidenceTraceEdge("trace_trust", "trace_effect"),
        ),
        entry_nodes=("trace_source",),
        terminal_nodes=("trace_effect",),
        attack_path="header -> verified claim overwrite -> req.user -> resource lookup",
        gained_capability="select another user's identity-bound resources",
        complete=True,
        evidence_gaps=(),
    )

    api_snippet = _api_vulnerable_snippet(snippet)
    api_trace = _api_evidence_trace(trace)
    payload = _finding(
        vulnerable_snippet=api_snippet,
        evidence_trace=api_trace,
    ).model_dump(mode="json")

    assert payload["vulnerable_snippet"] == {
        "path": "middleware/ValidateToken.js",
        "start_line": 54,
        "end_line": 60,
        "content": snippet.content,
    }
    assert payload["evidence_trace"]["trace_type"] == "taint_and_trust"
    assert payload["evidence_trace"]["complete"] is True
    assert payload["evidence_trace"]["entry_nodes"] == ["trace_source"]
    assert payload["evidence_trace"]["terminal_nodes"] == ["trace_effect"]
    assert [node["role"] for node in payload["evidence_trace"]["nodes"]] == [
        "ATTACKER_ORIGIN",
        "DOWNSTREAM_TRUST",
        "SENSITIVE_EFFECT",
    ]
    assert {edge["relation"] for edge in payload["evidence_trace"]["edges"]} == {
        "supports_transition"
    }
    assert "github.com" not in str(payload["evidence_trace"]).lower()
