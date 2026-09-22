import json

from plaidnox_sast.graph import (
    RipgrepDiscovery,
    build_structural_graph,
    readable_source_tree,
    source_files,
)
from plaidnox_sast.jev import JevClient, JevRouter
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


def test_readable_source_tree_is_stable_and_excludes_secret_containers(sample_repo):
    assert readable_source_tree(sample_repo) == [".plaidnox/config.yaml", "app.js"]


def test_ripgrep_discovery_returns_bounded_structured_hits(sample_repo):
    hits = RipgrepDiscovery(sample_repo).search("signin", "req\\.body", ["*.js"])

    assert hits
    assert hits[0].query_id == "signin"
    assert hits[0].path == "app.js"
    assert hits[0].line > 0


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
    assert decision.profile == "ssrf"
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


def test_jev_uses_high_confidence_remote_route(monkeypatch):
    response = {
        "model": "jev-test",
        "answers": {
            "analysis_depth": {"choice": "deep", "confidence": 0.93},
            "context_profile": {"choice": "authorization", "confidence": 0.91},
        },
    }
    monkeypatch.setattr("plaidnox_sast.jev.urlopen", lambda request, timeout: FakeHTTPResponse(response))
    candidate = Candidate(
        "rule", "Finding", "CWE-639", Severity.HIGH, 0.8, "object ownership check", Evidence("app.js", 1, 1), {"category": "general"}
    )
    decision = JevRouter(JevClient("test-key", endpoint="https://example.test")).classify(candidate)
    assert decision.depth is Depth.DEEP
    assert decision.profile == "authorization"
    assert decision.reason.startswith("JEV jev-test")


def test_jev_falls_back_when_confidence_is_low(monkeypatch):
    response = {
        "answers": {
            "analysis_depth": {"choice": "fast", "confidence": 0.6},
            "context_profile": {"choice": "general", "confidence": 0.6},
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
            "context_profile": {"choice": "generic", "confidence": 0.94},
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
