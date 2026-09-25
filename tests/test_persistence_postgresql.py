"""Real-PostgreSQL persistence tests.

Skipped unless PLAIDNOX_TEST_DATABASE_URL is set to a disposable PostgreSQL
instance (see docker/postgres-test/docker-compose.yml) -- deliberately a
different variable from the production PLAIDNOX_DATABASE_URL so these tests
can never accidentally target a real database.

The target schema is created by the actual checked-in PostgreSQL migration DDL
(applied in order via the compose file's init scripts), not SQLAlchemy's
`create_all`, so these tests
also verify the ORM matches the deployable migration.

All row identifiers are suffixed with a fresh run id so the suite tolerates
being run more than once against the same disposable container (a fixed
literal id would collide with the previous run's leftover rows).
"""

import os
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.graph import build_structural_graph
from plaidnox_sast.knowledge import KnowledgeDecision, KnowledgeEntry
from plaidnox_sast.persistence import (
    FindingDependencyInput,
    FindingEvidenceInput,
    HuntTaskInput,
    unit_of_work,
)
from plaidnox_sast.persistence.adapters import (
    PostgresContextFabricStore,
    PostgresKnowledgeStore,
    _derive_ids,
)

TEST_DATABASE_URL = os.environ.get("PLAIDNOX_TEST_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="set PLAIDNOX_TEST_DATABASE_URL to a disposable PostgreSQL instance to run these tests",
)

RUN_ID = uuid.uuid4().hex[:8]


def _id(name: str) -> str:
    return f"{name}-{RUN_ID}"


@pytest.fixture(scope="module")
def pg_session_factory():
    engine = create_engine(TEST_DATABASE_URL)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    yield factory
    engine.dispose()


def test_hunt_task_leasing_is_concurrency_safe_and_completion_is_idempotent(pg_session_factory):
    factory = pg_session_factory
    tenant_id = _id("tenant-pg-lease")
    codebase_id = _id("codebase-pg-lease")
    plan_id = _id("plan-pg-lease")

    with unit_of_work(factory, tenant_id) as repository:
        repository.add_codebase(codebase_id, "local/lease-example", "Lease Example")
        snapshot = repository.add_snapshot(_id("snapshot-pg-lease"), codebase_id, "revision-1", "tree-hash-1", "context-v1")
        scan = repository.start_scan(_id("scan-pg-lease"), codebase_id, snapshot.snapshot_id, "deep", "workflow-v1")
        plan = repository.create_hunt_plan(plan_id, scan.scan_id, "recon", "context-hash-1", "workflow-v1")
        repository.create_hunt_tasks(
            plan.plan_id,
            [HuntTaskInput("task-key-1", "Inspect auth", "Find auth bypass", {"paths": ["app.js"]})],
        )

    leased = []
    errors = []
    lock = threading.Lock()

    def worker(worker_id: str) -> None:
        try:
            with unit_of_work(factory, tenant_id) as repository:
                task = repository.lease_next_task(plan_id, worker_id, lease_seconds=60)
                if task is not None:
                    with lock:
                        leased.append(task)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(f"worker-{i}",)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    assert len(leased) == 1

    winner = leased[0]
    with unit_of_work(factory, tenant_id) as repository:
        assert repository.complete_task(winner.task_id, winner.lease_owner) is True
        assert repository.complete_task(winner.task_id, winner.lease_owner) is False

    with unit_of_work(factory, tenant_id) as repository:
        assert repository.lease_next_task(plan_id, "worker-late", lease_seconds=60) is None


def test_expired_hunt_task_lease_can_be_reclaimed(pg_session_factory):
    factory = pg_session_factory
    tenant_id = _id("tenant-pg-expired")
    codebase_id = _id("codebase-pg-expired")
    plan_id = _id("plan-pg-expired")
    now = datetime.now(UTC)

    with unit_of_work(factory, tenant_id) as repository:
        repository.add_codebase(codebase_id, "local/expired-example", "Expired Example")
        snapshot = repository.add_snapshot(
            _id("snapshot-pg-expired"), codebase_id, "revision-1", "tree-hash-1", "context-v1"
        )
        scan = repository.start_scan(_id("scan-pg-expired"), codebase_id, snapshot.snapshot_id, "deep", "workflow-v1")
        plan = repository.create_hunt_plan(plan_id, scan.scan_id, "recon", "context-hash-1", "workflow-v1")
        repository.create_hunt_tasks(
            plan.plan_id,
            [HuntTaskInput("task-key-1", "Inspect auth", "Find auth bypass", {})],
        )
        first = repository.lease_next_task(plan_id, "worker-1", lease_seconds=1, now=now)
        second = repository.lease_next_task(plan_id, "worker-2", lease_seconds=60, now=now + timedelta(seconds=5))

    assert first is not None
    assert second is not None
    assert second.task_id == first.task_id
    assert second.lease_owner == "worker-2"


def test_finding_round_trips_through_postgresql_shaped_schema(pg_session_factory):
    factory = pg_session_factory
    tenant_id = _id("tenant-pg-finding")
    codebase_id = _id("codebase-pg-finding")
    scan_id = _id("scan-pg-finding")
    finding_id = _id("finding-pg-1")
    fingerprint = _id("fingerprint-pg-1")

    evidence = [
        FindingEvidenceInput(
            "source", "app.js", 5, 5, "const identity = jwt.decode(req.body.token)", "ev-hash-1", "tree_sitter"
        ),
        FindingEvidenceInput(
            "sink", "app.js", 6, 6, 'res.cookie("idToken", req.body.token)', "ev-hash-2", "tree_sitter"
        ),
    ]
    dependencies = [FindingDependencyInput("symbol", "app.js:handleSignin:0", "dep-hash-1")]

    with unit_of_work(factory, tenant_id) as repository:
        repository.add_codebase(codebase_id, "local/finding-example", "Finding Example")
        snapshot = repository.add_snapshot(_id("snapshot-pg-finding"), codebase_id, "revision-1", "tree-hash-1", "context-v1")
        scan = repository.start_scan(scan_id, codebase_id, snapshot.snapshot_id, "deep", "workflow-v1")
        saved = repository.save_finding(
            finding_id,
            codebase_id,
            scan.scan_id,
            fingerprint,
            "JWT decoded without verification",
            "improper-authentication",
            "high",
            "validated",
            0.9,
            "Token is decoded but never verified before trusting its claims.",
            "Account takeover via forged tokens.",
            "Verify the signature before trusting claims.",
            {"deep_hunt": "supported"},
            evidence,
            dependencies,
        )

    with unit_of_work(factory, tenant_id) as repository:
        reloaded = repository.get_finding(finding_id)

    assert reloaded is not None
    assert [item.evidence_type for item in reloaded.evidence] == ["source", "sink"]
    assert reloaded.dependencies[0].dependency_key == "app.js:handleSignin:0"

    with unit_of_work(factory, tenant_id) as repository:
        updated = repository.save_finding(
            _id("finding-pg-1-ignored"),
            codebase_id,
            scan_id,
            fingerprint,
            "JWT decoded without verification",
            "improper-authentication",
            "high",
            "false_positive",
            0.9,
            "Re-reviewed: the caller re-verifies claims downstream.",
            "None.",
            "No action required.",
            {"deep_hunt": "not-supported"},
            [],
            [],
        )

    assert updated.finding_id == saved.finding_id
    assert updated.state == "false_positive"
    assert updated.evidence == []


def test_postgresql_cross_snapshot_reuse_requires_complete_graph_dependency_contract(
    pg_session_factory,
):
    factory = pg_session_factory
    tenant_id = _id("tenant-pg-graph-reuse")
    codebase_id = _id("codebase-pg-graph-reuse")
    report = {
        "schema_version": 1,
        "fingerprint": _id("fingerprint-graph-reuse"),
        "rule_id": "plaidnox.ai.graph-investigation",
        "state": "validated",
        "taint_path": [{"file": "app.js", "line": 3, "end_line": 4}],
    }

    with unit_of_work(factory, tenant_id) as repository:
        repository.add_codebase(codebase_id, "local/graph-reuse", "Graph Reuse")
        snapshot = repository.add_snapshot(
            _id("snapshot-pg-graph-reuse"),
            codebase_id,
            "revision-graph-reuse",
            "tree-graph-reuse",
            "context-v1",
        )
        scan = repository.start_scan(
            _id("scan-pg-graph-reuse"),
            codebase_id,
            snapshot.snapshot_id,
            "deep",
            "workflow-graph-reuse",
            {"context_scope_hash": "context-hash"},
        )
        complete_fingerprint = ""
        for suffix, validation in (
            (
                "complete",
                {
                    "graph_dependency_version": 1,
                    "graph_dependencies_complete": True,
                },
            ),
            ("legacy", {"deep_hunt": "supported"}),
        ):
            finding_id = _id(f"finding-pg-graph-{suffix}")
            fingerprint = _id(f"fingerprint-pg-graph-{suffix}")
            if suffix == "complete":
                complete_fingerprint = fingerprint
            repository.save_finding(
                finding_id,
                codebase_id,
                scan.scan_id,
                fingerprint,
                "Graph-backed authorization finding",
                "authorization",
                "high",
                "validated",
                0.9,
                "A reachable update path lacks ownership enforcement.",
                "Cross-account update.",
                "Enforce ownership.",
                validation,
                [],
                [
                    FindingDependencyInput(
                        "graph_investigation", _id(f"investigation-{suffix}"), "snapshot-hash"
                    ),
                    FindingDependencyInput("graph_node", "handler", "node-hash"),
                    FindingDependencyInput(
                        "graph_node_neighborhood", "handler", "neighborhood-hash"
                    ),
                    FindingDependencyInput("source_file", "app.js", "source-hash"),
                ]
                if suffix == "complete"
                else [],
            )
            repository.save_scan_finding(
                scan_id=scan.scan_id,
                finding_id=finding_id,
                fingerprint=fingerprint,
                severity="high",
                category="authorization",
                cwe_id=None,
                owasp_category="",
                report_schema_version=1,
                report_data={**report, "fingerprint": fingerprint},
            )
        repository.finish_scan(scan.scan_id, coverage_complete=True)

    with unit_of_work(factory, tenant_id) as repository:
        delta_eligible = repository.reusable_scan_findings(
            scan.scan_id,
            codebase_id=codebase_id,
            workflow_version="workflow-graph-reuse",
            context_scope_hash="context-hash",
            require_graph_dependencies=True,
        )
        exact_snapshot_eligible = repository.reusable_scan_findings(
            scan.scan_id,
            codebase_id=codebase_id,
            workflow_version="workflow-graph-reuse",
            context_scope_hash="context-hash",
        )

    assert len(delta_eligible) == 1
    assert delta_eligible[0].fingerprint == complete_fingerprint
    assert len(exact_snapshot_eligible) == 2


def test_unit_of_work_rolls_back_the_full_transaction_on_exception(pg_session_factory):
    """SQLite's simpler transaction model doesn't meaningfully exercise this the same way real Postgres does."""

    factory = pg_session_factory
    tenant_id = _id("tenant-pg-rollback")
    codebase_id = _id("codebase-pg-rollback")
    snapshot_id = _id("snapshot-pg-rollback")

    with pytest.raises(RuntimeError, match="boom"), unit_of_work(factory, tenant_id) as repository:
        repository.add_codebase(codebase_id, "local/rollback-example", "Rollback Example")
        snapshot = repository.add_snapshot(snapshot_id, codebase_id, "revision-1", "tree-hash-1", "context-v1")
        repository.start_scan(_id("scan-pg-rollback"), codebase_id, snapshot.snapshot_id, "deep", "workflow-v1")
        raise RuntimeError("boom")

    with unit_of_work(factory, tenant_id) as repository:
        assert repository.get_codebase(codebase_id) is None
        assert repository.get_snapshot(snapshot_id) is None


def test_context_and_knowledge_adapters_run_against_deployable_postgresql_schema(
    pg_session_factory,
    tmp_path,
):
    factory = pg_session_factory
    tenant_id = _id("tenant-pg-adapters")
    repository_name = _id("owner/repo")
    source = tmp_path / "service.py"
    source.write_text(
        "def load_record(identifier):\n    return store.load(identifier)\n\n"
        "def handle_request(identifier):\n    return load_record(identifier)\n",
        encoding="utf-8",
    )
    context_store = PostgresContextFabricStore(factory, tenant_id)
    base = context_store.create_base(
        repository_name,
        "revision-a",
        tmp_path,
        build_structural_graph(tmp_path),
    )
    source.write_text(
        "def load_record(identifier):\n    normalized = str(identifier)\n"
        "    return store.load(normalized)\n\n"
        "def handle_request(identifier):\n    return load_record(identifier)\n",
        encoding="utf-8",
    )
    overlay = context_store.create_overlay(
        base,
        "revision-b",
        tmp_path,
        ["service.py"],
        build_structural_graph(tmp_path),
    )
    context_store.add_memory(
        repository_name,
        "repository",
        "authorization",
        "Object access must enforce the owning principal.",
        "confirmed-triage",
    )
    packet = context_store.compile_packet(overlay, "authorization")

    assert overlay.changed_symbols
    assert packet.code_slices
    assert packet.memories

    codebase_id, snapshot_id, scan_id = _derive_ids(repository_name, "revision-a", tenant_id)
    with unit_of_work(factory, tenant_id) as repository:
        repository.start_scan(scan_id, codebase_id, snapshot_id, "deep", "workflow-test")
    knowledge_store = PostgresKnowledgeStore(factory, tenant_id)
    entry = knowledge_store.upsert(
        KnowledgeEntry(
            topic="Runtime authorization boundary",
            content="Authorization must be evaluated against the selected object.",
            source_url="https://example.test/primary-guidance",
            source_title="Primary guidance",
            confidence=0.9,
        )
    )
    task = {"task_id": "object-access", "title": "Object access", "objective": "Verify ownership."}
    decision = KnowledgeDecision("use_database", "repository", 0.9, "test-model", "stored evidence applies")
    knowledge_store.record_usage(
        repository_name,
        "revision-a",
        task["task_id"],
        "object ownership",
        decision,
        [entry],
    )
    knowledge_store.save_plan(repository_name, "revision-a", "Review ownership.", [task])

    assert knowledge_store.search("authorization boundary")[0].knowledge_id == entry.knowledge_id
    assert knowledge_store.load_plan(repository_name, "revision-a")["tasks"] == [task]
