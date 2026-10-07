from datetime import UTC, datetime

from plaidnox_scm.api_models import FindingRootCause, ReviewFinding
from plaidnox_scm.api_service import (
    _api_evidence_trace,
    _api_vulnerable_snippet,
    _client_proof_of_concept,
    _stored_finding,
)
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


def test_stored_finding_keeps_poc_without_duplicate_or_empty_fields():
    payload = _stored_finding(_finding(
        proof_of_concept="### Steps to Reproduce\n\n1. Run a local request.\n\n```bash\ncurl http://127.0.0.1/test\n```",
        proof_plan="duplicate proof plan",
        root_cause=FindingRootCause(
            path="middleware/ValidateToken.js", symbol="authCheck",
            start_line=54, end_line=60, changed_in_pr=True,
        ),
        context_facts=[], evidence_gaps=[],
    ))

    assert payload["proof_of_concept"].startswith("### Steps to Reproduce")
    assert payload["root_cause_path"] == "middleware/ValidateToken.js"
    assert "proof_plan" not in payload
    assert "root_cause" not in payload
    assert "context_facts" not in payload
    assert "evidence_gaps" not in payload


def test_client_poc_combines_numbered_steps_and_one_bash_block():
    payload = _client_proof_of_concept(
        "1. Start the local service.\n2. Send the controlled request.",
        "```bash\ncurl http://127.0.0.1/test\n```",
    )

    assert payload == (
        "### Steps to Reproduce\n\n"
        "1. Start the local service.\n2. Send the controlled request.\n\n"
        "```bash\ncurl http://127.0.0.1/test\n```"
    )


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


def test_client_poc_keeps_the_steps_when_the_verifier_returned_no_script():
    payload = _client_proof_of_concept("1. Start the local service.\n2. Send the request.", "")

    assert payload == "### Steps to Reproduce\n\n1. Start the local service.\n2. Send the request."
    assert _client_proof_of_concept(None, None) is None


def test_stored_finding_always_carries_a_poc_for_a_proof_plan_only_verification():
    poc = _client_proof_of_concept("1. Send a crafted header.\n2. Observe the other user's data.", "")
    payload = _stored_finding(_finding(proof_of_concept=poc, proof_plan="1. Send a crafted header."))

    assert "proof_plan" not in payload  # folded into the PoC, never lost
    assert payload["proof_of_concept"].startswith("### Steps to Reproduce")
    assert "Observe the other user's data" in payload["proof_of_concept"]


def test_trace_node_code_window_round_trips_through_the_api_and_storage():
    node = EvidenceTraceNode(
        node_id="trace_source",
        role=EvidenceRole.ATTACKER_ORIGIN,
        kind="SOURCE",
        path="src/api_models.py",
        start_line=40,
        end_line=40,
        symbol="ReviewRequest",
        expression="source_bundle_url: str | None = Field(default=None)",
        label="Attacker origin",
        summary="Request body field",
        provenance="deep_hunt",
        code="class ReviewRequest:\n    source_bundle_url: str | None = Field(default=None)\n",
        code_start_line=39,
        code_end_line=41,
    )
    trace = EvidenceTrace(
        trace_type="taint_and_trust", step_count=1, file_count=1, nodes=(node,), edges=(),
        entry_nodes=("trace_source",), terminal_nodes=("trace_source",),
        attack_path="body -> clone", gained_capability="exhaust workers", complete=False, evidence_gaps=(),
    )

    stored = _stored_finding(_finding(evidence_trace=_api_evidence_trace(trace)))
    stored_node = stored["evidence_trace"]["nodes"][0]

    assert stored_node["code"].startswith("class ReviewRequest:")
    assert (stored_node["code_start_line"], stored_node["code_end_line"]) == (39, 41)
    # A stored finding must replay through the strict response model.
    assert ReviewFinding.model_validate(stored).evidence_trace.nodes[0].code_start_line == 39


def test_old_trace_nodes_without_code_still_validate_and_omit_the_keys():
    payload = _finding(evidence_trace={
        "step_count": 1, "file_count": 1, "attack_path": "a", "gained_capability": "b",
        "nodes": [{"node_id": "n", "role": "ATTACKER_ORIGIN", "kind": "SOURCE", "path": "a.py", "symbol": "s",
                   "expression": "x", "label": "Attacker origin", "summary": "s", "provenance": "deep_hunt"}],
    }).model_dump(mode="json")

    assert "code" not in payload["evidence_trace"]["nodes"][0]


def test_classification_references_are_stored_only_when_present():
    from plaidnox_scm.api_models import ClassificationReference

    bare = _finding().model_dump(mode="json")
    tagged = _stored_finding(_finding(classification_references=[
        ClassificationReference(namespace="CWE", identifier="CWE-400", name="Uncontrolled Resource Consumption"),
    ]))

    assert "classification_references" not in bare
    assert tagged["classification_references"] == [
        {"namespace": "CWE", "identifier": "CWE-400", "name": "Uncontrolled Resource Consumption"},
    ]


def test_stage_events_belong_to_the_run_and_keep_safe_metadata():
    from plaidnox_scm.api_service import _activity_record

    record = _activity_record(
        tenant_id="t", provider="github", repository_id=1, installation_id=2, pull_number=9,
        review_id="review_abc", head_sha="b" * 40, event_type="changes_analyzed",
        idempotency_key="review_abc:attempt:1:stage:changes_analyzed",
        metadata={"files_changed": 5, "added": 0, "review_depth": "DEEP", "docs_only": False},
    )

    assert record.review_id == "review_abc"
    assert record.summary == "Changed files analyzed"
    assert record.metadata_json == {"files_changed": 5, "added": 0, "review_depth": "DEEP", "docs_only": False}
