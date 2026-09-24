from plaidnox_sast.fingerprint import (
    CandidateIndex,
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


def test_conflicting_rich_semantic_keys_never_fall_back_to_lexical_dedupe():
    first = candidate(10)
    second = candidate(11)
    second.evidence.graph_path = ["request.email", "loadUser", "response.render"]
    first.metadata = {
        "classification_references": [{"identifier": "CWE-89"}],
        "root_cause": {
            "symbol": "authCheck",
            "security_control": "identity selection",
            "broken_invariant": "Unverified identity cannot mutate session state.",
            "capability": "Revoke another user's token.",
        },
    }
    second.metadata = {
        "classification_references": [{"identifier": "CWE-89"}],
        "root_cause": {
            "symbol": "authCheck",
            "security_control": "identity selection",
            "broken_invariant": "Authenticated principal cannot be replaced.",
            "capability": "Read another user's resources.",
        },
    }

    unique, removed = deduplicate("org/repo", [first, second])

    assert removed == 0
    assert len(unique) == 2


def _family_candidate(line: int, *, title: str, invariant: str, capability: str) -> Candidate:
    item = candidate(line)
    item.title = title
    item.metadata = {
        "root_cause": {
            "symbol": "authCheck",
            "security_control": title,
            "broken_invariant": invariant,
            "capability": capability,
        },
        "root_equivalence": {
            "control_family_id": "AUTHENTICATED_IDENTITY_INTEGRITY",
            "invariant_family_id": "UNVERIFIED_IDENTITY_MUST_NOT_MUTATE_AUTH_STATE",
            "effect_family_id": "AUTH_TOKEN_REVOCATION",
            "capability_family_id": "CROSS_USER_AUTH_STATE_MUTATION",
        },
    }
    return item


def test_root_equivalence_clusters_paraphrases_and_preserves_them_for_deep_hunt():
    first = _family_candidate(
        10,
        title="JWT verification before identity-dependent cleanup",
        invariant="Unverified claims cannot select the account whose token state is changed.",
        capability="Revoke another user's stored access token.",
    )
    second = _family_candidate(
        58,
        title="Cookie claim triggers persistent token revocation",
        invariant="Only a verified principal may choose the target of authentication-state mutation.",
        capability="Force invalidation of a different user's access token.",
    )

    unique, removed = deduplicate("org/repo", [first, second])

    assert removed == 1
    assert len(unique) == 1
    packet = candidate_evidence_packet(unique[0])
    assert len(packet.candidate_cluster_variants) == 2
    assert {item["title"] for item in packet.candidate_cluster_variants} == {
        first.title,
        second.title,
    }


def test_root_equivalence_does_not_merge_distinct_effect_or_capability_families():
    first = _family_candidate(
        10,
        title="Identity swap revokes access token",
        invariant="Unverified identity cannot mutate auth state.",
        capability="Revoke another user's token.",
    )
    second = _family_candidate(
        11,
        title="Identity swap reads another account's report",
        invariant="Unverified identity cannot access protected records.",
        capability="Read another user's report.",
    )
    second.metadata["root_equivalence"]["effect_family_id"] = "CROSS_USER_REPORT_READ"
    second.metadata["root_equivalence"]["capability_family_id"] = "CROSS_USER_DATA_READ"

    unique, removed = deduplicate("org/repo", [first, second])

    assert removed == 0
    assert len(unique) == 2

    conflicting_taxonomy = _family_candidate(
        12,
        title=first.title,
        invariant=first.metadata["root_cause"]["broken_invariant"],
        capability=first.metadata["root_cause"]["capability"],
    )
    conflicting_taxonomy.metadata["root_equivalence"]["effect_family_id"] = "CROSS_USER_REPORT_READ"
    conflicting_taxonomy.metadata["root_equivalence"]["capability_family_id"] = "CROSS_USER_DATA_READ"
    unique_with_conflict, removed_with_conflict = deduplicate(
        "org/repo", [first, conflicting_taxonomy]
    )

    assert removed_with_conflict == 0
    assert len(unique_with_conflict) == 2


def test_candidate_index_clusters_family_equivalent_candidate_before_verification():
    index = CandidateIndex()
    first = _family_candidate(
        10,
        title="JWT identity cleanup boundary",
        invariant="Unverified claims cannot select auth state.",
        capability="Revoke another user's access token.",
    )
    second = _family_candidate(
        58,
        title="Attacker-controlled claim revokes a token",
        invariant="Unverified claims cannot choose the account affected by cleanup.",
        capability="Force token invalidation for another user.",
    )

    assert index.admit(first)
    assert not index.admit(second)
    assert len(first.metadata["candidate_cluster_variants"]) == 2
