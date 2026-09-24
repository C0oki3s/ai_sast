from datetime import UTC, datetime

from plaidnox_scm.api_models import FindingRootCause, ReviewFinding
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


def test_review_finding_omits_new_grouped_fields_when_verifier_has_none():
    payload = _finding().model_dump(mode="json")

    assert "root_cause" not in payload
    assert "vulnerable_snippet" not in payload
    assert "evidence_trace" not in payload
    assert "attack_path" not in payload
    assert "security_invariant" not in payload
    assert "gained_capability" not in payload
    assert "reproduction" not in payload


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
        kind="SOURCE",
        path="middleware/ValidateToken.js",
        start_line=54,
        end_line=54,
        symbol="authCheck",
        expression='req.headers["x-user-email"]',
        label="Attacker origin",
        summary="x-user-email request header",
        provenance="deep_hunt",
    )
    trust = EvidenceTraceNode(
        node_id="trace_trust",
        role=EvidenceRole.DOWNSTREAM_TRUST,
        kind="AUTHORIZATION_DECISION",
        path="app.js",
        start_line=151,
        end_line=151,
        symbol="route:GET /dashboard",
        expression='const email = req.user["custom:email_db"]',
        label="Downstream trust",
        summary="dashboard trusts req.user custom email",
        provenance="deep_hunt",
    )
    effect = EvidenceTraceNode(
        node_id="trace_effect",
        role=EvidenceRole.SENSITIVE_EFFECT,
        kind="SENSITIVE_EFFECT",
        path="app.js",
        start_line=152,
        end_line=152,
        symbol="route:GET /dashboard",
        expression="User.findOne({ email })",
        label="Sensitive effect",
        summary="cross-user resource lookup",
        provenance="deep_hunt",
    )
    trace = EvidenceTrace(
        trace_type="taint_and_trust",
        step_count=3,
        file_count=2,
        nodes=(source, trust, effect),
        edges=(
            EvidenceTraceEdge(
                "trace_source",
                "trace_trust",
                "propagates_to",
                "authCheck is explicitly attached to GET /dashboard",
            ),
            EvidenceTraceEdge(
                "trace_trust",
                "trace_effect",
                "propagates_to",
                "within structural anchor route:GET /dashboard",
            ),
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
        root_cause=FindingRootCause(
            path="middleware/ValidateToken.js",
            symbol="authCheck",
            start_line=54,
            end_line=60,
            changed_in_pr=True,
        ),
        vulnerable_snippet=api_snippet,
        evidence_trace=api_trace,
        attack_path=trace.attack_path,
        security_invariant="Only verified claims establish identity",
        gained_capability=trace.gained_capability,
    ).model_dump(mode="json")

    assert payload["root_cause"] == {
        "path": "middleware/ValidateToken.js",
        "symbol": "authCheck",
        "start_line": 54,
        "end_line": 60,
        "changed_in_pr": True,
    }
    assert payload["vulnerable_snippet"] == {
        "path": "middleware/ValidateToken.js",
        "start_line": 54,
        "end_line": 60,
        "code": snippet.content,
        "content": snippet.content,
    }
    assert payload["evidence_trace"]["trace_type"] == "taint_and_trust"
    assert payload["evidence_trace"]["step_count"] == 3
    assert payload["evidence_trace"]["file_count"] == 2
    assert payload["evidence_trace"]["complete"] is True
    assert payload["evidence_trace"]["entry_nodes"] == ["trace_source"]
    assert payload["evidence_trace"]["terminal_nodes"] == ["trace_effect"]
    assert payload["evidence_trace"]["nodes"][0]["kind"] == "SOURCE"
    assert payload["evidence_trace"]["nodes"][0]["symbol"] == "authCheck"
    assert payload["evidence_trace"]["nodes"][0]["expression"]
    assert payload["evidence_trace"]["nodes"][0]["provenance"] == "deep_hunt"
    assert {edge["relation"] for edge in payload["evidence_trace"]["edges"]} == {
        "propagates_to"
    }
    assert all(edge["via"] for edge in payload["evidence_trace"]["edges"])
    assert "github.com" not in str(payload["evidence_trace"]).lower()
