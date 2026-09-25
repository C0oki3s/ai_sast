from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.graph import build_structural_graph
from plaidnox_sast.knowledge import KnowledgeDecision, KnowledgeEntry
from plaidnox_sast.persistence.adapters import (
    PostgresContextFabricStore,
    PostgresKnowledgeStore,
    _derive_ids,
)
from plaidnox_sast.persistence.models import Base
from plaidnox_sast.persistence.models import OverlaySymbolSummaryRecord
from plaidnox_sast.persistence.repositories import (
    FindingEvidenceInput,
    stable_id,
    unit_of_work,
)


def _session_factory():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_postgresql_context_adapter_preserves_overlay_memory_and_finding_context(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "app.js"
    source.write_text(
        "function loadAccount(id) {\n  return database.find(id);\n}\n"
        "function handleRequest(id) {\n  return loadAccount(id);\n}\n"
        "function obsoleteHandler() {\n  return 'unused';\n}\n",
        encoding="utf-8",
    )
    factory = _session_factory()
    store = PostgresContextFabricStore(factory, "tenant-a")
    base_graph = build_structural_graph(repository)
    base = store.create_base("owner/repo", "revision-a", repository, base_graph)
    repeated = store.create_base("owner/repo", "revision-a", repository, base_graph)
    assert repeated.reused is True
    with unit_of_work(factory, "tenant-a") as repo:
        summaries = repo.list_security_summaries(base.context_id)
        assert summaries
        assert {item["symbol_id"] for item in summaries} == {
            item.symbol_id
            for item in repo.list_symbols(base.context_id)
            if item.kind != "route"
        }
        summary_by_name = {
            item["facts"][0]["name"]: item for item in summaries
        }
        assert summary_by_name["loadAccount"]["symbol_id"] in summary_by_name[
            "handleRequest"
        ]["dependency_symbol_ids"]
        assert summary_by_name["handleRequest"]["symbol_id"] in repo.reverse_dependencies(
            base.context_id, [summary_by_name["loadAccount"]["symbol_id"]]
        )

    source.write_text(
        "function loadAccount(id) {\n  const normalized = String(id);\n"
        "  return database.find(normalized);\n}\n"
        "function handleRequest(id) {\n  return loadAccount(id);\n}\n",
        encoding="utf-8",
    )
    overlay = store.create_overlay(
        base,
        "revision-b",
        repository,
        ["app.js"],
        build_structural_graph(repository),
    )
    with unit_of_work(factory, "tenant-a") as repo:
        base_summaries = {
            item["facts"][0]["name"]: item
            for item in repo.list_security_summaries(base.context_id)
        }
        overlay_summaries = {
            item["facts"][0]["name"]: item
            for item in repo.list_effective_security_summaries(overlay.overlay_id)
        }
        assert (
            base_summaries["loadAccount"]["content_hash"]
            != overlay_summaries["loadAccount"]["content_hash"]
        )
        assert (
            base_summaries["handleRequest"]["content_hash"]
            == overlay_summaries["handleRequest"]["content_hash"]
        )
        assert overlay_summaries["handleRequest"]["symbol_id"] in repo.reverse_dependencies(
            overlay.overlay_id, [overlay_summaries["loadAccount"]["symbol_id"]]
        )
        delta_rows = repo.session.query(OverlaySymbolSummaryRecord).filter_by(
            snapshot_id=overlay.overlay_id
        ).all()
        assert len(delta_rows) == 3
        assert {item.summary_state for item in delta_rows} == {"active", "deleted"}
        assert {
            item.symbol_id for item in delta_rows if item.summary_state == "active"
        } <= {
            overlay_summaries["loadAccount"]["symbol_id"],
            overlay_summaries["handleRequest"]["symbol_id"],
        }
        assert repo.list_security_summaries(overlay.overlay_id) == []
        assert next(item for item in delta_rows if item.summary_state == "deleted").symbol_id == next(
            item["symbol_id"]
            for item in repo.list_security_summaries(base.context_id)
            if item["facts"][0]["name"] == "obsoleteHandler"
        )
        effective = repo.list_effective_security_summaries(overlay.overlay_id)
        effective_by_name = {item["facts"][0]["name"]: item for item in effective}
        assert "obsoleteHandler" not in effective_by_name
        assert effective_by_name["loadAccount"]["content_hash"] == overlay_summaries[
            "loadAccount"
        ]["content_hash"]
        assert effective_by_name["handleRequest"]["content_hash"] == base_summaries[
            "handleRequest"
        ]["content_hash"]
    repeated_overlay = store.create_overlay(
        base,
        "revision-b",
        repository,
        ["app.js"],
        build_structural_graph(repository),
    )
    assert repeated_overlay.overlay_id == overlay.overlay_id
    assert store.effective_security_summaries(overlay.overlay_id) == effective
    store.add_memory(
        "owner/repo",
        "repository",
        "authorization",
        "Account access requires ownership validation.",
        "confirmed-triage",
    )

    codebase_id, _snapshot_id, _scan_id = _derive_ids("owner/repo", "revision-a", "tenant-a")
    scan_id = stable_id("scan", codebase_id, base.context_id)
    finding_id = stable_id("finding", codebase_id, "FND-1")
    with unit_of_work(factory, "tenant-a") as repo:
        repo.start_scan(scan_id, codebase_id, base.context_id, "deep", "workflow-test")
        repo.save_finding(
            finding_id,
            codebase_id,
            scan_id,
            "FND-1",
            "Missing ownership validation",
            "authorization bypass",
            "high",
            "confirmed",
            0.95,
            "A caller can request another account.",
            "Cross-account data exposure.",
            "Validate ownership before loading the record.",
            {},
            [FindingEvidenceInput("primary", "app.js", 1, 3, "redacted", "hash", "deep-hunt")],
            [],
        )
    store.link_finding("owner/repo", "FND-1", base.context_id, overlay.changed_symbols)
    packet = store.compile_packet(overlay, "authorization")

    assert overlay.changed_symbols
    assert overlay.context_reused_percent < 100
    assert packet.code_slices
    assert packet.memories[0].statement.startswith("Account access")
    assert packet.prior_findings == ["FND-1"]
    assert packet.cache["base_context_hit"] is True


def test_postgresql_context_adapter_prepares_incremental_scope_and_reuses_summary(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    stable = repository / "account.js"
    stable.write_text("function loadAccount(id) { return database.find(id); }\n", encoding="utf-8")
    changed = repository / "format.js"
    changed.write_text("function format(value) { return String(value); }\n", encoding="utf-8")
    factory = _session_factory()
    store = PostgresContextFabricStore(factory, "tenant-incremental")

    first = store.prepare_snapshot(
        "owner/repo",
        "revision-a",
        repository,
        build_structural_graph(repository),
    )
    store.save_repository_context(
        first.current.context_id,
        "owner/repo",
        {"architecture": "Account and formatting modules.", "applications": []},
    )
    changed.write_text(
        "function format(value) { return String(value).trim(); }\n",
        encoding="utf-8",
    )

    second = store.prepare_snapshot(
        "owner/repo",
        "revision-b",
        repository,
        build_structural_graph(repository),
    )

    assert second.changed_paths == ["format.js"]
    assert second.overlay is not None
    assert second.packet is not None
    assert {item["path"] for item in second.packet.code_slices} == {"format.js"}
    assert second.previous_repository_context["architecture"].startswith("Account")


def test_postgresql_knowledge_adapter_is_content_addressed_reusable_and_idempotent():
    factory = _session_factory()
    repository = "owner/repo"
    revision = "revision-a"
    codebase_id, snapshot_id, scan_id = _derive_ids(repository, revision, "tenant-a")
    with unit_of_work(factory, "tenant-a") as repo:
        repo.add_codebase(codebase_id, repository, repository)
        repo.add_snapshot(snapshot_id, codebase_id, revision, "tree-hash", "context-v1")
        repo.start_scan(scan_id, codebase_id, snapshot_id, "deep", "workflow-test")

    store = PostgresKnowledgeStore(factory, "tenant-a")
    entry = store.upsert(
        KnowledgeEntry(
            topic="Framework request boundary",
            content="Treat forwarded identity metadata as authoritative only behind configured proxies.",
            vulnerability_class="request-origin trust",
            ecosystem="javascript",
            framework="express",
            source_url="https://expressjs.com/en/guide/behind-proxies.html",
            source_title="Express behind proxies",
            confidence=0.95,
        )
    )
    assert store.upsert(entry).knowledge_id == entry.knowledge_id
    assert store.search("configured proxies")[0].knowledge_id == entry.knowledge_id

    task = {
        "task_id": "boundary-review",
        "title": "Review trust boundary",
        "objective": "Establish which metadata is authoritative.",
    }
    decision = KnowledgeDecision("use_database", "framework", 0.94, "test-model", "stored guidance applies")
    store.record_usage(repository, revision, task["task_id"], "proxy behavior", decision, [entry])
    store.record_usage(repository, revision, task["task_id"], "proxy behavior", decision, [entry])
    plan_id = store.save_plan(repository, revision, "Review observed boundaries.", [task])
    cached = store.load_plan(repository, revision)

    assert cached is not None
    assert cached["plan_id"] == plan_id
    assert cached["tasks"] == [task]


def test_postgresql_context_identity_is_namespaced_by_tenant(tmp_path):
    source = tmp_path / "service.py"
    source.write_text("def run():\n    return True\n", encoding="utf-8")
    graph = build_structural_graph(tmp_path)
    factory = _session_factory()

    tenant_a = PostgresContextFabricStore(factory, "tenant-a").create_base(
        "shared/repository",
        "same-revision",
        tmp_path,
        graph,
    )
    tenant_b = PostgresContextFabricStore(factory, "tenant-b").create_base(
        "shared/repository",
        "same-revision",
        tmp_path,
        graph,
    )

    assert tenant_a.context_id != tenant_b.context_id


def test_postgres_context_fabric_store_indexes_once_and_reuses_thereafter(sample_repo):
    factory = _session_factory()
    store = PostgresContextFabricStore(factory, "tenant-a")
    graph = build_structural_graph(sample_repo)

    first = store.create_base("owner/repo", "a" * 40, sample_repo, graph)
    second = store.create_base("owner/repo", "a" * 40, sample_repo, graph)

    assert first.context_id == second.context_id
    assert first.symbol_count > 0
    assert first.reused is False
    assert second.reused is True


def test_postgres_knowledge_store_upsert_is_content_addressed_and_searchable():
    factory = _session_factory()
    store = PostgresKnowledgeStore(factory, "tenant-a")
    entry = KnowledgeEntry(
        topic="JWT verification",
        content="Always verify the signature before trusting claims.",
        vulnerability_class="improper-authentication",
        ecosystem="npm",
        framework="express",
        source_url="https://example.com/jwt",
        source_title="JWT best practices",
        provenance="web-research",
        confidence=0.9,
    )

    saved = store.upsert(entry)
    saved_again = store.upsert(entry)

    assert saved.knowledge_id == saved_again.knowledge_id

    results = store.search("jwt verification")
    assert [item.knowledge_id for item in results] == [saved.knowledge_id]


def test_postgres_knowledge_store_round_trips_claims():
    factory = _session_factory()
    store = PostgresKnowledgeStore(factory, "tenant-a")
    entry = KnowledgeEntry(
        topic="JWT verification",
        content="Always verify the signature before trusting claims.",
        vulnerability_class="improper-authentication",
        ecosystem="npm",
        framework="express",
        source_url="https://example.com/jwt",
        source_title="JWT best practices",
        provenance="web-research",
        confidence=0.9,
        claims=["Verify the JWT signature before trusting any embedded claims."],
    )

    saved = store.upsert(entry)

    assert saved.claims == ["Verify the JWT signature before trusting any embedded claims."]
    results = store.search("jwt verification")
    assert results[0].claims == ["Verify the JWT signature before trusting any embedded claims."]


def test_postgres_knowledge_store_record_usage_creates_task_row_before_plan_is_saved():
    factory = _session_factory()
    store = PostgresKnowledgeStore(factory, "tenant-a")
    decision = KnowledgeDecision("reuse_stored", "task", 0.9, "test-model", "already covered")

    store.record_usage("owner/repo", "revision-1", "task-key-1", "jwt verification", decision, [])


def test_postgres_knowledge_store_save_and_load_plan_round_trips():
    factory = _session_factory()
    store = PostgresKnowledgeStore(factory, "tenant-a")
    tasks = [
        {"task_id": "task-key-1", "title": "Inspect auth", "objective": "Find auth bypass"},
    ]

    plan_id = store.save_plan("owner/repo", "a" * 40, "recon", tasks)
    loaded = store.load_plan("owner/repo", "a" * 40)

    assert loaded is not None
    assert loaded["plan_id"] == plan_id
    assert loaded["strategy"] == "recon"
    assert loaded["tasks"] == tasks


def test_postgres_knowledge_store_load_plan_is_none_when_no_plan_was_saved():
    factory = _session_factory()
    store = PostgresKnowledgeStore(factory, "tenant-a")

    assert store.load_plan("owner/repo", "a" * 40) is None
