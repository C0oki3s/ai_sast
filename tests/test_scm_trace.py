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


def test_every_trace_node_stores_its_code_window_with_line_numbers(tmp_path: Path):
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
    for node in trace.nodes:
        assert node.code, node
        assert node.code_start_line is not None and node.code_end_line is not None
        # The window always contains the node's own range.
        assert node.code_start_line <= node.start_line <= node.end_line <= node.code_end_line
        source = (tmp_path / node.path).read_text(encoding="utf-8").splitlines()
        assert node.code.splitlines() == source[node.code_start_line - 1 : node.code_end_line]

    origin = next(node for node in trace.nodes if node.kind == "SOURCE")
    # Four lines of context either side, clipped to the file.
    assert (origin.code_start_line, origin.code_end_line) == (1, 7)


def test_trace_node_code_window_is_bounded(tmp_path: Path):
    from plaidnox_scm.trace import _code_window

    lines = [f"line {index}" for index in range(1, 501)]
    start, end, code = _code_window(lines, 200, 300)

    assert start <= 200
    assert end - start + 1 <= 40
    assert code.splitlines()[0] == f"line {start}"


def test_trace_steps_follow_the_attack_order_and_branches_keep_their_own_links(tmp_path: Path):
    _write_fixture(tmp_path)
    trace = build_evidence_trace(
        tmp_path,
        build_structural_graph(tmp_path),
        _candidate(),
        _branching_evidence(),
        attack_path="header -> claim -> lookups",
        gained_capability="Select another user's identity",
    )

    assert trace is not None
    steps = [(node.step, node.label, node.path, node.start_line) for node in trace.nodes]
    assert steps == [
        (1, "Attacker origin", "middleware/ValidateToken.js", 3),
        (2, "Changed root cause", "middleware/ValidateToken.js", 3),
        (3, "Downstream trust", "app.js", 2),
        (4, "Downstream trust", "app.js", 8),
        (5, "Sensitive effect", "app.js", 3),
        (6, "Sensitive effect", "app.js", 9),
    ]
    step_of = {node.node_id: node.step for node in trace.nodes}
    links = {(step_of[edge.source], step_of[edge.target]): edge.via for edge in trace.edges}
    assert links == {
        (1, 2): "same function `authCheck`",
        (2, 3): "`authCheck` runs before route `GET /dashboard`",
        (2, 4): "`authCheck` runs before route `GET /api/pdfs`",
        (3, 5): "`email` flows on within `GET /dashboard`",
        (4, 6): "`userEmail` flows on within `GET /api/pdfs`",
    }
    assert [step_of[item] for item in trace.terminal_nodes] == [5, 6]
    assert trace.complete is True


def test_a_verifier_location_on_the_changed_lines_becomes_the_root_cause_step(tmp_path: Path):
    _write_fixture(tmp_path)
    evidence = (
        ReviewEvidence(EvidenceRole.DOWNSTREAM_TRUST, "deep_hunt", "middleware/ValidateToken.js", 4, 4,
                       "`payload` takes the header value", step_role="propagation"),
        ReviewEvidence(EvidenceRole.SENSITIVE_EFFECT, "deep_hunt", "app.js", 3, 3, "Lookup by forged email"),
    )
    trace = build_evidence_trace(
        tmp_path, build_structural_graph(tmp_path), _candidate(), evidence,
        attack_path="a", gained_capability="b",
    )

    assert trace is not None
    first = trace.nodes[0]
    assert (first.label, first.start_line, first.end_line) == ("Changed root cause", 3, 4)
    assert first.summary == "`payload` takes the header value"
    assert len(trace.nodes) == 2


def test_trace_code_keeps_expressions_that_mention_tokens_and_hides_only_literal_secrets(tmp_path: Path):
    source = tmp_path / "auth.js"
    source.write_text(
        "function auth(req) {\n"
        "  const token = req.headers.authorization.split(' ')[1];\n"
        f"  const apiKey = \"{'x' * 16}\";\n"
        "  return verify(token, apiKey);\n"
        "}\n",
        encoding="utf-8",
    )
    candidate = L1Candidate(
        candidate_id="c", changed_path="auth.js", changed_symbol="auth", changed_lines=ChangedLines(2, 3),
        behavior_before="", behavior_after="token is read from the header", security_role="auth",
        suspected_broken_invariant="", provisional_attacker_capability="", context_facts_used=(),
        context_gaps=(), requested_expansion=(),
    )
    snippet = build_vulnerable_snippet(tmp_path, candidate)
    trace = build_evidence_trace(
        tmp_path, build_structural_graph(tmp_path), candidate, (), attack_path="a", gained_capability="b"
    )

    assert snippet is not None and snippet.content.splitlines() == [
        "  const token = req.headers.authorization.split(' ')[1];",
        '  const apiKey = "<redacted-credential>";',
    ]
    assert trace is not None and "req.headers.authorization.split(' ')[1];" in trace.nodes[0].code
