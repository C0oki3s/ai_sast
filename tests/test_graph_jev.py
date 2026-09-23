import json

import pytest

from plaidnox_sast.graph import (
    RipgrepDiscovery,
    RipgrepQueryError,
    build_structural_graph,
    readable_source_tree,
    source_files,
)
from plaidnox_sast.jev import (
    FRONTIER_PRIORITY_WEIGHT,
    JevClient,
    JevFrontierRouter,
    JevRetryRouter,
    JevRouter,
)
from plaidnox_sast.models import (
    Candidate,
    Depth,
    Evidence,
    ModelTier,
    Severity,
)
from plaidnox_sast.validation import FindingValidator


def test_structural_graph_uses_tree_sitter_without_baked_in_searches(sample_repo):
    graph = build_structural_graph(sample_repo)
    assert graph.tree_sitter_files >= 1
    assert graph.rg_queries == 0
    assert graph.routes == []


def test_structural_graph_returns_changed_attack_surface(sample_repo):
    surface = build_structural_graph(sample_repo).affected_surface(["app.js"])
    assert surface["changed_paths"] == ["app.js"]
    assert surface["routes"] == []


def test_structural_graph_keeps_symbol_references_for_incremental_navigation(tmp_path):
    (tmp_path / "service.py").write_text(
        "def load_record(identifier):\n    return identifier\n\n"
        "def handle_request(value):\n    return load_record(value)\n",
        encoding="utf-8",
    )

    graph = build_structural_graph(tmp_path)

    assert any(
        item.source == "handle_request" and item.target == "load_record"
        for item in graph.references
    )


def test_readable_source_tree_is_stable_and_excludes_secret_containers(sample_repo):
    assert readable_source_tree(sample_repo) == [".plaidnox/config.yaml", "app.js"]


def test_ripgrep_discovery_returns_bounded_structured_hits(sample_repo):
    hits = RipgrepDiscovery(sample_repo).search("signin", "req\\.body", ["*.js"])

    assert hits
    assert hits[0].query_id == "signin"
    assert hits[0].path == "app.js"
    assert hits[0].line > 0


def test_ripgrep_discovery_preserves_a_redacted_diagnostic_for_invalid_model_pattern(sample_repo):
    with pytest.raises(RipgrepQueryError) as raised:
        RipgrepDiscovery(sample_repo).search("model-query-1", r"(?<!\.)eval\(")

    error = raised.value
    assert error.query_id == "model-query-1"
    assert error.exit_code == 2
    assert len(error.pattern_hash) == 64
    assert error.diagnostic
    assert "exit code 2" in str(error)


def test_ripgrep_discovery_never_searches_unlisted_file_types(tmp_path):
    (tmp_path / "app.py").write_text("dangerous_call(user_input)\n", encoding="utf-8")
    (tmp_path / ".env").write_text("dangerous_call(secret_value)\n", encoding="utf-8")

    hits = RipgrepDiscovery(tmp_path).search("security-signal", "dangerous_call")

    assert [hit.path for hit in hits] == ["app.py"]


def test_source_inventory_enforces_excludes_and_maximum_size(tmp_path):
    (tmp_path / "keep.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / "excluded.py").write_text("print('excluded')", encoding="utf-8")
    (tmp_path / "large.py").write_text("x" * 100, encoding="utf-8")

    files = source_files(tmp_path, exclude=["excluded.py"], max_file_bytes=20)

    assert [path.name for path in files] == ["keep.py"]


def test_source_inventory_recognizes_common_extensionless_manifests(tmp_path):
    for filename in ("go.mod", "requirements.txt", "build.gradle", "Cargo.lock"):
        (tmp_path / filename).write_text("module metadata\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not source inventory\n", encoding="utf-8")

    files = source_files(tmp_path)

    assert [path.name for path in files] == [
        "Cargo.lock",
        "build.gradle",
        "go.mod",
        "requirements.txt",
    ]


def test_ripgrep_enforces_project_excludes_and_exact_maximum_size(tmp_path):
    (tmp_path / "keep.py").write_text("signal()\n", encoding="utf-8")
    (tmp_path / "excluded.py").write_text("signal()\n", encoding="utf-8")
    (tmp_path / "large.py").write_text("signal()\n" + "x" * 100, encoding="utf-8")

    hits = RipgrepDiscovery(
        tmp_path,
        exclude=["excluded.py"],
        max_file_bytes=20,
    ).search("bounded", "signal")

    assert [hit.path for hit in hits] == ["keep.py"]


def test_jev_escalates_ssrf_to_deep():
    candidate = Candidate(
        rule_id="ssrf",
        title="SSRF",
        vulnerability_class="CWE-918",
        severity=Severity.HIGH,
        confidence=0.8,
        message="message",
        evidence=Evidence("app.js", 1, 1),
        metadata={"category": "ssrf"},
    )
    decision = JevRouter().classify(candidate)
    assert decision.depth is Depth.DEEP
    assert decision.needs_cross_file == "likely"
    assert decision.needs_deep_falsification == "likely"
    assert decision.analysis_complexity == 4
    assert decision.task_class == "ssrf"
    assert decision.model_tier is ModelTier.DEEP
    assert decision.needs_deep_hunt is True


def test_validated_findings_record_provider_independent_jev_classification(sample_repo):
    candidate = Candidate(
        "ssrf", "SSRF", "CWE-918", Severity.HIGH, 0.8, "request renderer", Evidence("app.js", 1, 1), {"category": "ssrf"}
    )
    finding = FindingValidator().validate(
        "owner/repo", sample_repo, candidate, JevRouter().classify(candidate)
    )
    assert finding is not None
    assert finding.metadata["jev_task_class"] == "ssrf"
    assert finding.metadata["jev_model_tier"] == "deep"
    assert finding.metadata["jev_needs_deep_hunt"] is True


class FakeHTTPResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _noul_answers(choice="likely", confidence=0.9):
    return {
        "needs_cross_file": {"choice": choice, "confidence": confidence},
        "needs_state_reconstruction": {"choice": choice, "confidence": confidence},
        "needs_external_semantics": {"choice": choice, "confidence": confidence},
        "needs_environment_context": {"choice": choice, "confidence": confidence},
        "needs_deep_falsification": {"choice": choice, "confidence": confidence},
        "analysis_complexity": {"choice": "3", "confidence": confidence},
    }


def test_jev_uses_high_confidence_remote_route(monkeypatch):
    response = {
        "model": "jev-test",
        "answers": {
            "analysis_depth": {"choice": "deep", "confidence": 0.93},
            **_noul_answers("likely", 0.91),
        },
    }
    monkeypatch.setattr("plaidnox_sast.jev.urlopen", lambda request, timeout: FakeHTTPResponse(response))
    candidate = Candidate(
        "rule", "Finding", "CWE-639", Severity.HIGH, 0.8, "object ownership check", Evidence("app.js", 1, 1), {"category": "general"}
    )
    decision = JevRouter(JevClient("test-key", endpoint="https://example.test")).classify(candidate)
    assert decision.depth is Depth.DEEP
    assert decision.needs_cross_file == "likely"
    assert decision.analysis_complexity == 3
    assert decision.reason.startswith("JEV jev-test")


def test_jev_falls_back_when_confidence_is_low(monkeypatch):
    response = {
        "answers": {
            "analysis_depth": {"choice": "fast", "confidence": 0.6},
            **_noul_answers("unlikely", 0.6),
        },
    }
    monkeypatch.setattr("plaidnox_sast.jev.urlopen", lambda request, timeout: FakeHTTPResponse(response))
    candidate = Candidate("rule", "Finding", "CWE-918", Severity.HIGH, 0.8, "request renderer", Evidence("app.js", 1, 1), {"category": "ssrf"})
    decision = JevRouter(JevClient("test-key", endpoint="https://example.test")).classify(candidate)
    assert decision.depth is Depth.DEEP
    assert decision.reason.endswith("JEV low confidence")


def test_jev_requests_each_typed_decision_without_local_prompt_cache(monkeypatch):
    calls = []
    response = {
        "model": "jev-test",
        "answers": {
            "analysis_depth": {"choice": "standard", "confidence": 0.95},
            **_noul_answers("unlikely", 0.94),
        },
    }

    def fake_urlopen(request, timeout):
        calls.append((request, timeout))
        return FakeHTTPResponse(response)

    monkeypatch.setattr("plaidnox_sast.jev.urlopen", fake_urlopen)
    client = JevClient("test-key", endpoint="https://example.test")
    state = {"rule_id": "rule", "path": "app.js"}

    client.decide_questions(state, "routing/jev.json")
    client.decide_questions(state, "routing/jev.json")

    assert len(calls) == 2


def test_jev_client_redacts_secrets_from_state_before_sending(monkeypatch):
    response = {
        "model": "jev-test",
        "answers": {
            "analysis_depth": {"choice": "standard", "confidence": 0.95},
            **_noul_answers("unlikely", 0.94),
        },
    }
    captured = {}

    def fake_urlopen(request, timeout):
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return FakeHTTPResponse(response)

    monkeypatch.setattr("plaidnox_sast.jev.urlopen", fake_urlopen)
    client = JevClient("test-key", endpoint="https://example.test")
    state = {"message": "Uses AKIAABCDEFGHIJKLMNOP to sign requests."}

    client.decide_questions(state, "routing/jev.json")

    assert "AKIAABCDEFGHIJKLMNOP" not in captured["body"]["state"]["message"]
    assert captured["body"]["state"]["message"] == "Uses <redacted-aws-access-key> to sign requests."


def test_frontier_priority_weight_orders_low_below_standard_below_high():
    assert FRONTIER_PRIORITY_WEIGHT["low"] < FRONTIER_PRIORITY_WEIGHT["standard"] < FRONTIER_PRIORITY_WEIGHT["high"]


def test_frontier_router_locally_prioritizes_high_severity_capabilities_as_high():
    decision = JevFrontierRouter().prioritize({"severity": "critical", "capability": "remote code execution"})
    assert decision.priority == "high"
    assert decision.reason == "severity-safe frontier fallback"


def test_frontier_router_locally_prioritizes_other_severities_as_standard():
    decision = JevFrontierRouter().prioritize({"severity": "medium", "capability": "read internal config"})
    assert decision.priority == "standard"


def test_frontier_router_uses_high_confidence_remote_route(monkeypatch):
    response = {
        "model": "jev-test",
        "answers": {"pivot_priority": {"choice": "low", "confidence": 0.9}},
    }
    monkeypatch.setattr("plaidnox_sast.jev.urlopen", lambda request, timeout: FakeHTTPResponse(response))
    router = JevFrontierRouter(JevClient("test-key", endpoint="https://example.test"))
    decision = router.prioritize({"severity": "high", "capability": "ssrf into metadata service"})
    assert decision.priority == "low"
    assert decision.reason.startswith("JEV jev-test")


def test_frontier_router_falls_back_when_confidence_is_low(monkeypatch):
    response = {
        "answers": {"pivot_priority": {"choice": "low", "confidence": 0.5}},
    }
    monkeypatch.setattr("plaidnox_sast.jev.urlopen", lambda request, timeout: FakeHTTPResponse(response))
    router = JevFrontierRouter(JevClient("test-key", endpoint="https://example.test"))
    decision = router.prioritize({"severity": "critical", "capability": "admin token theft"})
    assert decision.priority == "high"
    assert decision.reason.endswith("JEV low confidence")


def test_retry_router_locally_escalates_a_candidate_never_routed_to_deep():
    decision = JevRetryRouter().decide({"model_tier": "standard", "context_requests_pending": 1})
    assert decision.action == "escalate_model"
    assert decision.reason == "tier-safe retry fallback"


def test_retry_router_locally_expands_context_for_a_deep_candidate_with_a_pending_request():
    decision = JevRetryRouter().decide({"model_tier": "deep", "context_requests_pending": 2})
    assert decision.action == "expand_context"
    assert decision.reason == "unresolved-context retry fallback"


def test_retry_router_locally_marks_unresolved_when_deep_and_nothing_pending():
    decision = JevRetryRouter().decide({"model_tier": "deep", "context_requests_pending": 0})
    assert decision.action == "mark_unresolved"
    assert decision.reason == "no-further-signal retry fallback"


def test_retry_router_uses_high_confidence_remote_route(monkeypatch):
    response = {
        "model": "jev-test",
        "answers": {"next_action": {"choice": "escalate_model", "confidence": 0.9}},
    }
    monkeypatch.setattr("plaidnox_sast.jev.urlopen", lambda request, timeout: FakeHTTPResponse(response))
    router = JevRetryRouter(JevClient("test-key", endpoint="https://example.test"))
    decision = router.decide({"model_tier": "deep", "context_requests_pending": 0})
    assert decision.action == "escalate_model"
    assert decision.reason.startswith("JEV jev-test")


def test_retry_router_falls_back_when_confidence_is_low(monkeypatch):
    response = {
        "answers": {"next_action": {"choice": "mark_unresolved", "confidence": 0.5}},
    }
    monkeypatch.setattr("plaidnox_sast.jev.urlopen", lambda request, timeout: FakeHTTPResponse(response))
    router = JevRetryRouter(JevClient("test-key", endpoint="https://example.test"))
    decision = router.decide({"model_tier": "deep", "context_requests_pending": 1})
    assert decision.action == "expand_context"
    assert decision.reason.endswith("JEV low confidence")
