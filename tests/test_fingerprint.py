from plaidnox_sast.fingerprint import (
    candidate_evidence_packet,
    candidate_fingerprint,
    candidate_semantic_key,
    deduplicate,
)
from plaidnox_sast.models import Candidate, Evidence, Severity


def candidate(line: int) -> Candidate:
    return Candidate(
        rule_id="rule",
        title="SQL injection",
        vulnerability_class="CWE-89",
        severity=Severity.HIGH,
        confidence=0.9,
        message="message",
        evidence=Evidence(
            path="api.js",
            start_line=line,
            end_line=line,
            source_symbol="POST /users",
            sink_symbol="db.query",
            graph_path=["request.email", "findUser", "db.query"],
        ),
    )


def test_fingerprint_survives_line_movement():
    assert candidate_fingerprint("org/repo", candidate(10)) == candidate_fingerprint("org/repo", candidate(200))


def test_deduplication_uses_graph_identity():
    unique, removed = deduplicate("org/repo", [candidate(10), candidate(200)])
    assert len(unique) == 1
    assert removed == 1


def test_semantic_key_and_evidence_packet_describe_root_cause_and_branches():
    item = candidate(10)
    item.metadata = {
        "root_cause": {
            "symbol": "authCheck",
            "security_control": "authenticated identity integrity",
            "broken_invariant": "Verified identity cannot be overwritten.",
            "capability": "Select another user's identity-bound resources.",
        },
        "evidence_basis": {
            "origin": ["x-user-email header"],
            "expected_boundary": ["verified identity payload"],
            "sensitive_effect": ["cross-user report selection"],
            "missing_evidence": [],
        },
        "supporting_evidence": [
            {"path": "routes.js", "start_line": 20, "end_line": 22, "attack_path": "GET /reports"}
        ],
    }

    semantic_key = candidate_semantic_key(item)
    packet = candidate_evidence_packet(item)

    assert "authcheck" in semantic_key
    assert packet.invariant == "Verified identity cannot be overwritten."
    assert packet.gained_capabilities == ["Select another user's identity-bound resources."]
    assert packet.downstream_trust[0]["path"] == "routes.js"


def test_semantic_dedup_merges_downstream_branch_evidence_before_verification():
    first = candidate(10)
    second = candidate(11)
    root = {
        "symbol": "authCheck",
        "security_control": "authenticated identity integrity",
        "broken_invariant": "Verified identity cannot be overwritten.",
        "capability": "Select another user's identity-bound resources.",
    }
    first.metadata = {
        "root_cause": root,
        "supporting_evidence": [
            {"path": "routes.js", "start_line": 20, "end_line": 22, "attack_path": "GET /read"}
        ],
    }
    second.metadata = {
        "root_cause": root,
        "supporting_evidence": [
            {"path": "routes.js", "start_line": 40, "end_line": 42, "attack_path": "POST /reports"}
        ],
    }

    unique, removed = deduplicate("org/repo", [first, second])

    assert removed == 1
    assert len(unique) == 1
    assert {item["attack_path"] for item in unique[0].metadata["supporting_evidence"]} >= {
        "GET /read",
        "POST /reports",
    }
