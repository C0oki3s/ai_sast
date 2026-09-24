from plaidnox_sast.fingerprint import CandidateIndex
from plaidnox_sast.models import Candidate, Evidence, Severity


def _candidate(start: int, *, invariant: str, capability: str) -> Candidate:
    return Candidate(
        rule_id="plaidnox.ai.authentication",
        title=f"auth issue at {start}",
        vulnerability_class="authentication weakness",
        severity=Severity.HIGH,
        confidence=0.9,
        message="authentication control regression",
        evidence=Evidence(
            path="middleware/ValidateToken.js",
            start_line=start,
            end_line=start + 2,
            snippet="code",
            source_symbol="authCheck",
            sink_symbol="identity",
            graph_path=[],
        ),
        metadata={
            "category": "authentication",
            "root_cause": {
                "symbol": "authCheck",
                "security_control": "identity-validation",
                "broken_invariant": invariant,
                "capability": capability,
            },
        },
    )


def test_same_control_with_different_invariant_is_not_collapsed():
    index = CandidateIndex()
    forged_identity = _candidate(
        20,
        invariant="Only cryptographically verified claims establish identity",
        capability="Forge another user's identity",
    )
    expired_session = _candidate(
        260,
        invariant="Expired identities are never accepted",
        capability="Keep an expired session alive",
    )

    assert index.admit(forged_identity) is True
    assert index.admit(expired_session) is True


def test_same_semantic_root_cause_merges_even_when_reported_far_apart():
    index = CandidateIndex()
    first = _candidate(
        20,
        invariant="Only cryptographically verified claims establish identity",
        capability="Forge another user's identity",
    )
    duplicate = _candidate(
        260,
        invariant="Only cryptographically verified claims establish identity",
        capability="Forge another user's identity",
    )

    assert index.admit(first) is True
    assert index.admit(duplicate) is False
    assert first.metadata["duplicate_reports"] == 1
