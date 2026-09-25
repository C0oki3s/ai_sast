import pytest

from plaidnox_sast.cli import _record_context_base
from plaidnox_sast.context_fabric import ContextFabricStore, _snapshot_symbols
from plaidnox_sast.graph import build_structural_graph, stable_symbol_id, stable_symbol_keys
from plaidnox_sast.pipeline import SastPipeline


class _Context:
    def to_dict(self):
        return {"architecture": "test fixture", "applications": []}


class _DeepHunt:
    def build_repository_context(self, root, repository, commit, graph, business_context=""):
        return _Context()

    def plan_tasks(self, context, security_context=""):
        return _Plan()

    def discover_candidates(self, root, context, plan=None):
        return [], 0

    def sweep_variants(self, root, context, plan, verified):
        return [], 0

    def consolidate_findings(self, findings):
        return findings

    def hunt(self, root, candidate, finding, security_context):
        from plaidnox_sast.ai import DeepHuntResult

        return DeepHuntResult(True, 0.9, "tracked metadata supports review", "Git index", "Remove the artifact")


class _Plan:
    def to_dict(self):
        return {"plan_id": "plan-test", "strategy": "fixture", "tasks": []}


def test_context_base_is_content_addressed_and_reused(sample_repo, tmp_path):
    store = ContextFabricStore(tmp_path / "context.sqlite")
    (sample_repo / "helper.js").write_text(
        "function helper(value) { return String(value); }\n", encoding="utf-8"
    )
    graph = build_structural_graph(sample_repo)

    first = store.create_base("owner/repo", "a" * 40, sample_repo, graph)
    second = store.create_base("owner/repo", "a" * 40, sample_repo, graph)

    assert first.context_id == second.context_id
    assert first.symbol_count > 0
    assert second.reused is True
    summaries = store.list_security_summaries(first.context_id)
    assert summaries
    assert all(len(item["content_hash"]) == 64 for item in summaries)
    assert any(item["unresolved_relationship_ids"] for item in summaries)
    stable_keys = stable_symbol_keys(graph.symbols + graph.routes)
    assert {item["symbol_id"] for item in summaries} == {
        stable_symbol_id(stable_keys[id(symbol)])
        for symbol in graph.symbols
        if symbol.kind != "route"
    }


def test_context_base_rejects_conflicting_summary_for_immutable_revision(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "service.py"
    source.write_text("def load():\n    return 1\n", encoding="utf-8")
    store = ContextFabricStore(tmp_path / "context.sqlite")
    store.create_base("owner/repo", "revision-a", repository, build_structural_graph(repository))

    source.write_text("def load():\n    return 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="immutable Context Fabric snapshot"):
        store.create_base("owner/repo", "revision-a", repository, build_structural_graph(repository))


def test_overlay_tombstone_hides_deleted_summary_and_recomputes_caller(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "service.py"
    source.write_text(
        "def persist(value):\n    return value\n\n"
        "def handle(value):\n    return persist(value)\n",
        encoding="utf-8",
    )
    store = ContextFabricStore(tmp_path / "context.sqlite")
    base_graph = build_structural_graph(repository)
    base = store.create_base("owner/repo", "revision-a", repository, base_graph)
    base_summaries = {
        item["facts"][0]["name"]: item
        for item in store.list_security_summaries(base.context_id)
    }

    source.write_text("def handle(value):\n    return persist(value)\n", encoding="utf-8")
    overlay = store.create_overlay(
        base, "revision-b", repository, ["service.py"], build_structural_graph(repository)
    )

    effective = {
        item["facts"][0]["name"]: item
        for item in store.effective_security_summaries(overlay.overlay_id)
    }
    assert "persist" not in effective
    assert effective["handle"]["content_hash"] != base_summaries["handle"]["content_hash"]
    assert effective["handle"]["unresolved_relationship_ids"]


def test_overlay_keeps_changed_code_and_revalidates_only_linked_finding(sample_repo, tmp_path):
    store = ContextFabricStore(tmp_path / "context.sqlite")
    base = store.create_base("owner/repo", "a" * 40, sample_repo, build_structural_graph(sample_repo))
    (sample_repo / "app.js").write_text(
        (sample_repo / "app.js").read_text() + "\nfunction validateAccount(id) { return id; }\nvalidateAccount('a');\n"
    )
    overlay = store.create_overlay(
        base,
        "b" * 40,
        sample_repo,
        ["app.js"],
        build_structural_graph(sample_repo),
    )

    assert overlay.changed_paths == ["app.js"]
    assert overlay.changed_symbols
    assert overlay.context_reused_percent < 100
    store.link_finding("owner/repo", "FND-1", base.context_id, overlay.changed_symbols)
    store.add_memory("owner/repo", "repository", "authorization", "Tenant access requires ownership scope.", "confirmed-triage")
    packet = store.compile_packet(overlay, "authorization")

    assert packet.code_slices
    assert packet.prior_findings == ["FND-1"]
    assert packet.memories[0].statement.startswith("Tenant access")
    assert packet.cache["base_context_hit"] is True


def test_changed_callee_keeps_identity_and_revalidates_unchanged_caller(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "app.js"
    source.write_text(
        "function loadAccount(id) {\n  return database.find(id);\n}\n"
        "function handleRequest(id) {\n  return loadAccount(id);\n}\n",
        encoding="utf-8",
    )
    store = ContextFabricStore(tmp_path / "context.sqlite")
    base = store.create_base(
        "owner/repo", "a" * 40, repository, build_structural_graph(repository)
    )
    base_ids = {
        name: symbol_id
        for symbol_id, _path, name, _line, _content_hash, _content in _snapshot_symbols(
            repository, build_structural_graph(repository)
        )
    }

    source.write_text(
        "function loadAccount(id) {\n  const normalized = String(id);\n  return database.find(normalized);\n}\n"
        "function handleRequest(id) {\n  return loadAccount(id);\n}\n",
        encoding="utf-8",
    )
    overlay = store.create_overlay(
        base,
        "b" * 40,
        repository,
        ["app.js"],
        build_structural_graph(repository),
    )
    base_summaries = {
        item["facts"][0]["name"]: item
        for item in store.list_security_summaries(base.context_id)
    }
    overlay_summaries = {
        item["facts"][0]["name"]: item
        for item in store.list_overlay_security_summaries(overlay.overlay_id)
    }

    assert base_ids["loadAccount"] in overlay.changed_symbols
    assert base_ids["handleRequest"] not in overlay.changed_symbols
    assert base_ids["handleRequest"] in overlay.affected_symbols
    assert set(overlay_summaries) == {"loadAccount", "handleRequest"}
    assert (
        overlay_summaries["loadAccount"]["content_hash"]
        != base_summaries["loadAccount"]["content_hash"]
    )
    assert (
        overlay_summaries["handleRequest"]["content_hash"]
        == base_summaries["handleRequest"]["content_hash"]
    )


def test_unrelated_change_reuses_linked_finding_context(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "account.js").write_text(
        "function loadAccount(id) { return database.find(id); }\n",
        encoding="utf-8",
    )
    unrelated = repository / "format.js"
    unrelated.write_text("function format(value) { return String(value); }\n", encoding="utf-8")
    store = ContextFabricStore(tmp_path / "context.sqlite")
    base_graph = build_structural_graph(repository)
    base = store.create_base("owner/repo", "revision-a", repository, base_graph)
    ids = {
        name: symbol_id
        for symbol_id, _path, name, _line, _content_hash, _content in _snapshot_symbols(repository, base_graph)
    }
    store.link_finding("owner/repo", "FND-account", base.context_id, [ids["loadAccount"]])

    unrelated.write_text(
        "function format(value) { return String(value).trim(); }\n",
        encoding="utf-8",
    )
    overlay = store.create_overlay(
        base,
        "revision-b",
        repository,
        ["format.js"],
        build_structural_graph(repository),
    )
    packet = store.compile_packet(overlay, "mixed")

    assert ids["loadAccount"] not in overlay.affected_symbols
    assert packet.prior_findings == []
    assert all(item["path"] == "format.js" for item in packet.code_slices)


def test_context_snapshot_contains_only_files_admitted_to_security_ir(tmp_path):
    (tmp_path / "app.py").write_text("def run():\n    return True\n", encoding="utf-8")
    (tmp_path / "generated.py").write_text("def generated():\n    return False\n", encoding="utf-8")
    graph = build_structural_graph(tmp_path, exclude=["generated.py"])

    records = _snapshot_symbols(tmp_path, graph)

    assert {record[1] for record in records} == {"app.py"}


def test_local_scan_can_record_a_reusable_snapshot_context(sample_repo, tmp_path):
    result = SastPipeline().scan_snapshot(
        sample_repo, "owner/repo", deep_hunt_agent=_DeepHunt()
    )
    store_path = tmp_path / "durable-context.sqlite"
    store = ContextFabricStore(store_path)
    _record_context_base(store, result, sample_repo)
    first = result.repository_context["context_fabric"]
    _record_context_base(store, result, sample_repo)

    assert first["context_id"] == result.repository_context["context_fabric"]["context_id"]
    assert result.repository_context["context_fabric"]["reused"] is True
