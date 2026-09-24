from pathlib import Path

from plaidnox_sast.graph import build_structural_graph
from plaidnox_scm.evidence import EvidenceRole, ReviewEvidence
from plaidnox_scm.l1_review import ChangedLines, L1Candidate
from plaidnox_scm.trace import build_evidence_trace, build_vulnerable_snippet


def _candidate() -> L1Candidate:
    return L1Candidate(
        candidate_id="candidate-1",
        changed_path="middleware/ValidateToken.js",
        changed_symbol="authCheck",
        changed_lines=ChangedLines(3, 4),
        behavior_before="verified Cognito claims remain authoritative",
        behavior_after="request header overwrites a verified identity claim",
        security_role="authentication boundary",
        suspected_broken_invariant="Only verified claims establish identity",
        provisional_attacker_capability="Select another user's identity",
        context_facts_used=(),
        context_gaps=(),
        requested_expansion=(),
    )


def _write_fixture(root: Path) -> None:
    middleware = root / "middleware" / "ValidateToken.js"
    middleware.parent.mkdir(parents=True)
    middleware.write_text(
        "async function authCheck(req, res, next) {\n"
        "  const payload = await verifier.verify(token);\n"
        "  if (req.headers[\"x-user-email\"]) {\n"
        "    payload[\"custom:email_db\"] = req.headers[\"x-user-email\"];\n"
        "  }\n"
        "  req.user = payload;\n"
        "  return next();\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "app.js").write_text(
        "app.get(\"/dashboard\", authCheck, async (req, res) => {\n"
        "  const email = req.user[\"custom:email_db\"];\n"
        "  const user = await User.findOne({ email });\n"
        "  return res.json(user);\n"
        "});\n"
        "\n"
        "app.get(\"/api/pdfs\", authCheck, async (req, res) => {\n"
        "  const userEmail = req.user.email;\n"
        "  const user = await User.findOne({ email: userEmail });\n"
        "  return res.json(user.PDFurls);\n"
        "});\n",
        encoding="utf-8",
    )


def test_vulnerable_snippet_is_exact_changed_range_and_redacted(tmp_path: Path):
    _write_fixture(tmp_path)

    snippet = build_vulnerable_snippet(tmp_path, _candidate())

    assert snippet is not None
    assert snippet.path == "middleware/ValidateToken.js"
    assert (snippet.start_line, snippet.end_line) == (3, 4)
    assert snippet.content.splitlines() == [
        '  if (req.headers["x-user-email"]) {',
        '    payload["custom:email_db"] = req.headers["x-user-email"];',
    ]


def _branching_evidence() -> tuple[ReviewEvidence, ...]:
    return (
        ReviewEvidence(
            EvidenceRole.ATTACKER_ORIGIN,
            "deep_hunt",
            "middleware/ValidateToken.js",
            3,
            3,
            "Attacker-controlled x-user-email header",
        ),
        ReviewEvidence(
            EvidenceRole.ROOT_CAUSE_CHANGED_CODE,
            "changed_code",
            "middleware/ValidateToken.js",
            3,
            4,
            "Request data overwrites a verified identity claim",
        ),
        ReviewEvidence(
            EvidenceRole.DOWNSTREAM_TRUST,
            "deep_hunt",
            "app.js",
            2,
            2,
            "Dashboard trusts custom:email_db from req.user",
        ),
        ReviewEvidence(
            EvidenceRole.DOWNSTREAM_TRUST,
            "deep_hunt",
            "app.js",
            8,
            8,
            "PDF endpoint trusts req.user.email",
        ),
        ReviewEvidence(
            EvidenceRole.SENSITIVE_EFFECT,
            "deep_hunt",
            "app.js",
            3,
            4,
            "Identity-selected database read",
        ),
        ReviewEvidence(
            EvidenceRole.SENSITIVE_EFFECT,
            "deep_hunt",
            "app.js",
            9,
            10,
            "Sensitive PDF lookup and response",
        ),
    )


def test_evidence_trace_is_machine_supported_and_branches_by_route(tmp_path: Path):
    _write_fixture(tmp_path)
    graph = build_structural_graph(tmp_path)

    trace = build_evidence_trace(
        tmp_path,
        graph,
        _candidate(),
        _branching_evidence(),
        attack_path="x-user-email -> verified claim overwrite -> protected user lookups",
        gained_capability="Select another user's identity",
    )

    assert trace is not None
    assert trace.trace_type == "taint_and_trust"
    assert trace.step_count == 6
    assert trace.file_count == 2
    assert trace.complete is True
    assert trace.evidence_gaps == ()
    assert len(trace.entry_nodes) == 1
    assert len(trace.terminal_nodes) == 2
    assert {node.kind for node in trace.nodes} >= {
        "SOURCE",
        "PROPAGATION",
        "AUTHORIZATION_DECISION",
        "SENSITIVE_EFFECT",
    }
    assert all(node.expression for node in trace.nodes)
    assert all(node.symbol for node in trace.nodes)
    assert all(node.provenance for node in trace.nodes)
    assert {edge.relation for edge in trace.edges} == {"propagates_to"}
    assert all(edge.via for edge in trace.edges)
    assert any("authCheck" in edge.via for edge in trace.edges)


def test_evidence_trace_marks_unproven_or_unresolved_hops_incomplete(tmp_path: Path):
    _write_fixture(tmp_path)
    graph = build_structural_graph(tmp_path)
    evidence = _branching_evidence() + (
        ReviewEvidence(
            EvidenceRole.SENSITIVE_EFFECT,
            "deep_hunt",
            "app.js",
            6,
            6,
            "Unrelated location with no machine-supported transition",
        ),
    )

    trace = build_evidence_trace(
        tmp_path,
        graph,
        _candidate(),
        evidence,
        attack_path="x-user-email -> req.user",
        gained_capability="Select another user's identity",
        evidence_gaps=("Runtime-only authorization branch was not observed",),
    )

    assert trace is not None
    assert trace.complete is False
    assert "Runtime-only authorization branch was not observed" in trace.evidence_gaps
    assert any("could not be machine-validated" in gap or "No machine-supported transition" in gap for gap in trace.evidence_gaps)
