from pathlib import Path

from plaidnox_scm.evidence import EvidenceRole, ReviewEvidence
from plaidnox_scm.l1_review import ChangedLines, L1Candidate
from plaidnox_scm.trace import build_evidence_trace, build_vulnerable_snippet


def _candidate() -> L1Candidate:
    return L1Candidate(
        candidate_id="candidate-1",
        changed_path="middleware/ValidateToken.js",
        changed_symbol="authCheck",
        changed_lines=ChangedLines(2, 4),
        behavior_before="verify signed JWT",
        behavior_after="decode JWT without verification",
        security_role="authentication boundary",
        suspected_broken_invariant="Only verified claims establish identity",
        provisional_attacker_capability="Forge identity claims",
        context_facts_used=(),
        context_gaps=(),
        requested_expansion=(),
    )


def test_vulnerable_snippet_is_exact_changed_range_and_redacted(tmp_path: Path):
    target = tmp_path / "middleware" / "ValidateToken.js"
    target.parent.mkdir(parents=True)
    target.write_text(
        "line1\nconst token = req.headers.authorization;\n"
        "const payload = jwt.decode(token);\nreq.user = payload;\nline5\n",
        encoding="utf-8",
    )

    snippet = build_vulnerable_snippet(tmp_path, _candidate())

    assert snippet is not None
    assert snippet.path == "middleware/ValidateToken.js"
    assert (snippet.start_line, snippet.end_line) == (2, 4)
    assert snippet.content.splitlines() == [
        "const token = req.headers.authorization;",
        "const payload = jwt.decode(token);",
        "req.user = payload;",
    ]


def _branching_evidence() -> tuple[ReviewEvidence, ...]:
    return (
        ReviewEvidence(
            EvidenceRole.ATTACKER_ORIGIN,
            "deep_hunt",
            "middleware/ValidateToken.js",
            2,
            2,
            "Untrusted bearer token",
        ),
        ReviewEvidence(
            EvidenceRole.ROOT_CAUSE_CHANGED_CODE,
            "changed_code",
            "middleware/ValidateToken.js",
            2,
            4,
            "JWT verification replaced with decode",
        ),
        ReviewEvidence(
            EvidenceRole.DOWNSTREAM_TRUST,
            "deep_hunt",
            "app.js",
            120,
            120,
            "Protected routes trust req.user",
        ),
        ReviewEvidence(
            EvidenceRole.SENSITIVE_EFFECT,
            "deep_hunt",
            "app.js",
            150,
            150,
            "Manager report access",
        ),
        ReviewEvidence(
            EvidenceRole.SENSITIVE_EFFECT,
            "deep_hunt",
            "app.js",
            180,
            180,
            "Flag access",
        ),
    )


def test_evidence_trace_branches_from_downstream_trust_to_sensitive_effects():
    trace = build_evidence_trace(
        _candidate(),
        _branching_evidence(),
        attack_path="bearer token -> req.user -> protected routes",
        gained_capability="Forge identity claims",
    )

    assert trace is not None
    assert trace.trace_type == "taint_and_trust"
    assert trace.complete is True
    assert trace.evidence_gaps == ()
    assert len(trace.entry_nodes) == 1
    assert len(trace.terminal_nodes) == 2
    terminal_ids = set(trace.terminal_nodes)
    downstream = next(node for node in trace.nodes if node.role == EvidenceRole.DOWNSTREAM_TRUST)
    assert {
        edge.target
        for edge in trace.edges
        if edge.source == downstream.node_id
    } == terminal_ids
    assert {edge.relation for edge in trace.edges} == {"supports_transition"}


def test_evidence_trace_marks_unresolved_evidence_gap_incomplete():
    trace = build_evidence_trace(
        _candidate(),
        _branching_evidence(),
        attack_path="bearer token -> req.user -> protected routes",
        gained_capability="Forge identity claims",
        evidence_gaps=("Runtime-only authorization branch was not observed",),
    )

    assert trace is not None
    assert trace.complete is False
    assert trace.evidence_gaps == ("Runtime-only authorization branch was not observed",)
