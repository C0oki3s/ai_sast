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
        "function handleRequest(id) {\n  return loadAccount(id);\n}\n",
        encoding="utf-8",
    )
    factory = _session_factory()
    store = PostgresContextFabricStore(factory, "tenant-a")
    base = store.create_base("owner/repo", "revision-a", repository, build_structural_graph(repository))

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
    decision = KnowledgeDecision("use_database", "framework", 0.94, "jev-test", "stored guidance applies")
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
