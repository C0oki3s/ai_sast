from plaidnox_sast.fingerprint import candidate_fingerprint, deduplicate
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
