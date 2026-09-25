import re
import threading
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.assets import load_json, load_text
from plaidnox_sast.graphify_adapter import (
    CodeEdge,
    CodeGraphSnapshot,
    CodeNode,
    graph_edge_identity,
    graph_node_neighborhood_hash,
)
from plaidnox_sast.redaction import redact
from plaidnox_sast.persistence.database import (
    DatabaseConfigurationError,
    DatabaseSettings,
)
from plaidnox_sast.persistence.models import Base
from plaidnox_sast.persistence.repositories import (
    EdgeInput,
    FindingDependencyInput,
    FindingEvidenceInput,
    HuntTaskInput,
    SourceFileInput,
    SymbolInput,
    _hash,
    security_ir_inputs,
    unit_of_work,
)


def test_postgresql_configuration_is_external_and_password_is_redacted():
    settings = DatabaseSettings.from_environment(
        {"PLAIDNOX_DATABASE_URL": "postgresql+psycopg://scanner:secret@db/code_scanning"}
    )

    assert settings.url.drivername == "postgresql+psycopg"
    assert "secret" not in settings.redacted_url
    assert "***" in settings.redacted_url


def test_finding_storage_redaction_covers_credentials_tokens_and_private_keys():
    source = (
        'DATABASE_PASSWORD = "fixture-db-password"\n'
        "TOKEN='eyJabcdefgh.ijklmnop.qrstuvwx'\n"
        "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n"
        "-----BEGIN PRIVATE KEY-----\nprivate-key-fixture\n-----END PRIVATE KEY-----"
    )
    safe = redact(source)

    for secret in (
        "fixture-db-password",
        "eyJabcdefgh.ijklmnop.qrstuvwx",
        "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        "private-key-fixture",
    ):
        assert secret not in safe


def test_production_database_rejects_non_postgresql_driver():
    with pytest.raises(DatabaseConfigurationError, match="Unsupported production database driver"):
        DatabaseSettings.from_environment({"PLAIDNOX_DATABASE_URL": "sqlite:///context.sqlite"})


def test_production_database_requires_tls() -> None:
    with pytest.raises(DatabaseConfigurationError, match="requires sslmode"):
        DatabaseSettings.from_environment(
            {
                "PLAIDNOX_DATABASE_URL": "postgresql+psycopg://scanner:secret@db/code_scanning",
                "PLAIDNOX_PRODUCTION_MODE": "true",
            }
        )


def test_production_database_accepts_verified_tls_mode() -> None:
    settings = DatabaseSettings.from_environment(
        {
            "PLAIDNOX_DATABASE_URL": ("postgresql+psycopg://scanner:secret@db/code_scanning?sslmode=verify-full"),
            "PLAIDNOX_PRODUCTION_MODE": "true",
        }
    )

    assert settings.url.query["sslmode"] == "verify-full"


def test_code_scanning_orm_matches_deployable_postgresql_tables():
    manifest = load_json("migrations/postgresql/manifest.json")
    ddl = "\n".join(load_text(path) for path in manifest["migrations"])
    ddl_tables = set(re.findall(r"CREATE TABLE IF NOT EXISTS\s+(code_scanning_[a-z_]+)", ddl))
    orm_tables = set(Base.metadata.tables)

    assert orm_tables <= ddl_tables
    assert "code_scanning_codebases" in orm_tables
    assert "code_scanning_findings" in orm_tables
    assert "code_scanning_finding_dependencies" in orm_tables
    assert all(not name.startswith(("scm_", "sca_", "dast_", "cloud_")) for name in ddl_tables)


def test_repository_is_tenant_scoped_and_snapshot_creation_is_idempotent():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-1", "local/example", "Example")
        first = repository.add_snapshot(
            "snapshot-1",
            "codebase-1",
            "revision-1",
            "tree-hash-1",
            "context-v1",
        )
        second = repository.add_snapshot(
            "snapshot-ignored",
            "codebase-1",
            "revision-1",
            "tree-hash-1",
            "context-v1",
        )
        scan = repository.start_scan(
            "scan-1",
            "codebase-1",
            first.snapshot_id,
            "deep",
            "workflow-v1",
        )

    with unit_of_work(factory, "tenant-b") as repository:
        assert repository.get_codebase("codebase-1") is None

    assert first.snapshot_id == second.snapshot_id
    assert scan.snapshot_id == "snapshot-1"


def test_security_ir_persistence_is_idempotent_and_reveals_callers_via_reverse_dependencies():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    caller = SymbolInput(
        stable_key="app.js:handleSignin:0",
        qualified_name="handleSignin",
        kind="function",
        path="app.js",
        start_line=4,
        end_line=8,
        content_hash="hash-caller-1",
        content="function handleSignin() { decodeToken(); }",
    )
    callee = SymbolInput(
        stable_key="app.js:decodeToken:0",
        qualified_name="decodeToken",
        kind="function",
        path="app.js",
        start_line=1,
        end_line=3,
        content_hash="hash-callee-1",
        content="function decodeToken() { return jwt.decode(token); }",
    )
    source_file = SourceFileInput("app.js", "javascript", "file-hash-1", 128)
    edge = EdgeInput(caller.stable_key, callee.stable_key, "calls", "tree_sitter")

    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-1", "local/example", "Example")
        snapshot = repository.add_snapshot("snapshot-1", "codebase-1", "revision-1", "tree-hash-1", "context-v1")
        indexed = repository.save_security_ir(snapshot.snapshot_id, [source_file], [caller, callee], [edge])
        reindexed = repository.save_security_ir(snapshot.snapshot_id, [source_file], [caller, callee], [edge])

        callee_symbol_id = f"sym-{_hash(callee.stable_key)}"
        caller_symbol_id = f"sym-{_hash(caller.stable_key)}"
        affected = repository.reverse_dependencies(snapshot.snapshot_id, [callee_symbol_id])

    assert indexed is True
    assert reindexed is False
    assert caller_symbol_id in affected


def test_security_ir_symbol_identity_survives_body_and_line_changes(tmp_path):
    from plaidnox_sast.graph import build_structural_graph

    source = tmp_path / "app.js"
    source.write_text(
        "function loadAccount(id) {\n  return database.find(id);\n}\n",
        encoding="utf-8",
    )
    first = security_ir_inputs(tmp_path, build_structural_graph(tmp_path))[1]
    first_symbol = next(item for item in first if item.qualified_name.endswith("loadAccount"))

    source.write_text(
        "const moduleVersion = 2;\n\n"
        "function loadAccount(id) {\n  const normalized = String(id);\n"
        "  return database.find(normalized);\n}\n",
        encoding="utf-8",
    )
    second = security_ir_inputs(tmp_path, build_structural_graph(tmp_path))[1]
    second_symbol = next(item for item in second if item.qualified_name.endswith("loadAccount"))

    assert first_symbol.stable_key == second_symbol.stable_key
    assert first_symbol.content_hash != second_symbol.content_hash


def test_hunt_task_leasing_is_concurrency_safe_and_completion_is_idempotent(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'leasing.db'}", connect_args={"timeout": 30})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-1", "local/example", "Example")
        snapshot = repository.add_snapshot("snapshot-1", "codebase-1", "revision-1", "tree-hash-1", "context-v1")
        scan = repository.start_scan("scan-1", "codebase-1", snapshot.snapshot_id, "deep", "workflow-v1")
        plan = repository.create_hunt_plan("plan-1", scan.scan_id, "recon", "context-hash-1", "workflow-v1")
        repository.create_hunt_tasks(
            plan.plan_id,
            [
                HuntTaskInput(
                    "task-key-1",
                    "Inspect auth",
                    "Find auth bypass",
                    {"paths": ["app.js"]},
                )
            ],
        )

    leased = []
    errors = []
    lock = threading.Lock()

    def worker(worker_id: str) -> None:
        try:
            with unit_of_work(factory, "tenant-a") as repository:
                task = repository.lease_next_task("plan-1", worker_id, lease_seconds=60)
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
    with unit_of_work(factory, "tenant-a") as repository:
        assert repository.complete_task(winner.task_id, winner.lease_owner) is True
        assert repository.complete_task(winner.task_id, winner.lease_owner) is False

    with unit_of_work(factory, "tenant-a") as repository:
        assert repository.lease_next_task("plan-1", "worker-late", lease_seconds=60) is None


def test_expired_hunt_task_lease_can_be_reclaimed():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(UTC)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-1", "local/example", "Example")
        snapshot = repository.add_snapshot("snapshot-1", "codebase-1", "revision-1", "tree-hash-1", "context-v1")
        scan = repository.start_scan("scan-1", "codebase-1", snapshot.snapshot_id, "deep", "workflow-v1")
        plan = repository.create_hunt_plan("plan-1", scan.scan_id, "recon", "context-hash-1", "workflow-v1")
        repository.create_hunt_tasks(
            plan.plan_id,
            [HuntTaskInput("task-key-1", "Inspect auth", "Find auth bypass", {})],
        )
        first = repository.lease_next_task("plan-1", "worker-1", lease_seconds=1, now=now)
        second = repository.lease_next_task("plan-1", "worker-2", lease_seconds=60, now=now + timedelta(seconds=5))

    assert first is not None
    assert second is not None
    assert second.task_id == first.task_id
    assert second.lease_owner == "worker-2"


def test_finding_round_trips_through_postgresql_shaped_schema():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    evidence = [
        FindingEvidenceInput(
            "source",
            "app.js",
            5,
            5,
            "const identity = jwt.decode(req.body.token)",
            "ev-hash-1",
            "tree_sitter",
        ),
        FindingEvidenceInput(
            "sink",
            "app.js",
            6,
            6,
            'res.cookie("idToken", req.body.token)',
            "ev-hash-2",
            "tree_sitter",
        ),
    ]
    dependencies = [FindingDependencyInput("symbol", "app.js:handleSignin:0", "dep-hash-1")]

    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-1", "local/example", "Example")
        snapshot = repository.add_snapshot("snapshot-1", "codebase-1", "revision-1", "tree-hash-1", "context-v1")
        scan = repository.start_scan("scan-1", "codebase-1", snapshot.snapshot_id, "deep", "workflow-v1")
        saved = repository.save_finding(
            "finding-1",
            "codebase-1",
            scan.scan_id,
            "fingerprint-1",
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

    with unit_of_work(factory, "tenant-a") as repository:
        reloaded = repository.get_finding("finding-1")

    assert reloaded is not None
    assert [item.evidence_type for item in reloaded.evidence] == ["source", "sink"]
    assert reloaded.dependencies[0].dependency_key == "app.js:handleSignin:0"

    with unit_of_work(factory, "tenant-a") as repository:
        updated = repository.save_finding(
            "finding-1-ignored",
            "codebase-1",
            "scan-1",
            "fingerprint-1",
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


def test_a_changed_callee_flags_its_own_and_its_callers_findings_but_leaves_unrelated_findings_alone():
    """Mutation test for the Phase 2 exit condition: a changed callee revalidates
    callers and linked findings, while unrelated code (and its findings) is reused."""

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    caller = SymbolInput(
        stable_key="app.js:handleSignin:0",
        qualified_name="handleSignin",
        kind="function",
        path="app.js",
        start_line=4,
        end_line=8,
        content_hash="hash-caller-1",
        content="function handleSignin() { decodeToken(); }",
    )
    callee = SymbolInput(
        stable_key="app.js:decodeToken:0",
        qualified_name="decodeToken",
        kind="function",
        path="app.js",
        start_line=1,
        end_line=3,
        content_hash="hash-callee-1",
        content="function decodeToken() { return jwt.decode(token); }",
    )
    unrelated = SymbolInput(
        stable_key="util.js:formatDate:0",
        qualified_name="formatDate",
        kind="function",
        path="util.js",
        start_line=1,
        end_line=2,
        content_hash="hash-unrelated-1",
        content="function formatDate(value) { return value; }",
    )
    source_files = [
        SourceFileInput("app.js", "javascript", "file-hash-1", 128),
        SourceFileInput("util.js", "javascript", "file-hash-2", 64),
    ]
    edge = EdgeInput(caller.stable_key, callee.stable_key, "calls", "tree_sitter")

    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-1", "local/example", "Example")
        snapshot_1 = repository.add_snapshot("snapshot-1", "codebase-1", "revision-1", "tree-hash-1", "context-v1")
        repository.save_security_ir(snapshot_1.snapshot_id, source_files, [caller, callee, unrelated], [edge])
        scan_1 = repository.start_scan("scan-1", "codebase-1", snapshot_1.snapshot_id, "deep", "workflow-v1")

        caller_finding = repository.save_finding(
            "finding-caller",
            "codebase-1",
            scan_1.scan_id,
            "fingerprint-caller",
            "Token decoded without verification",
            "improper-authentication",
            "high",
            "validated",
            0.9,
            "handleSignin decodes the token via decodeToken without verifying it.",
            "Account takeover via forged tokens.",
            "Verify the signature before trusting claims.",
            {"deep_hunt": "supported"},
            [],
            [FindingDependencyInput("symbol", caller.stable_key, caller.content_hash)],
        )
        callee_finding = repository.save_finding(
            "finding-callee",
            "codebase-1",
            scan_1.scan_id,
            "fingerprint-callee",
            "JWT decoded without verification",
            "improper-authentication",
            "high",
            "validated",
            0.9,
            "decodeToken never verifies the token signature.",
            "Account takeover via forged tokens.",
            "Verify the signature before trusting claims.",
            {"deep_hunt": "supported"},
            [],
            [FindingDependencyInput("symbol", callee.stable_key, callee.content_hash)],
        )
        unrelated_finding = repository.save_finding(
            "finding-unrelated",
            "codebase-1",
            scan_1.scan_id,
            "fingerprint-unrelated",
            "Date formatting uses local timezone",
            "improper-input-validation",
            "low",
            "validated",
            0.6,
            "formatDate does not normalise timezones.",
            "Minor display inconsistency.",
            "Normalise to UTC.",
            {"deep_hunt": "supported"},
            [],
            [FindingDependencyInput("symbol", unrelated.stable_key, unrelated.content_hash)],
        )

    # A new snapshot mutates only the callee's body; the caller and the
    # unrelated symbol keep their identity (`stable_key`) and their content.
    mutated_callee = SymbolInput(
        stable_key=callee.stable_key,
        qualified_name=callee.qualified_name,
        kind=callee.kind,
        path=callee.path,
        start_line=callee.start_line,
        end_line=callee.end_line,
        content_hash="hash-callee-2-mutated",
        content="function decodeToken() { return jwt.verify(token, secret); }",
    )
    with unit_of_work(factory, "tenant-a") as repository:
        snapshot_2 = repository.add_snapshot("snapshot-2", "codebase-1", "revision-2", "tree-hash-2", "context-v1")
        repository.save_security_ir(
            snapshot_2.snapshot_id,
            source_files,
            [caller, mutated_callee, unrelated],
            [edge],
        )

        stale = repository.findings_requiring_revalidation("codebase-1", snapshot_2.snapshot_id, hops=3)
        assert set(stale) == {caller_finding.finding_id, callee_finding.finding_id}

        flagged = repository.flag_findings_for_revalidation(stale)
        assert flagged == 2

        assert repository.get_finding(caller_finding.finding_id).state == "discovered"
        assert repository.get_finding(callee_finding.finding_id).state == "discovered"
        # Unrelated code was reused: its finding is untouched by the callee mutation.
        assert repository.get_finding(unrelated_finding.finding_id).state == "validated"

        snapshot_3 = repository.add_snapshot(
            "snapshot-3", "codebase-1", "revision-3", "tree-hash-3", "context-v1"
        )
        repository.save_security_ir(
            snapshot_3.snapshot_id,
            source_files,
            [caller, unrelated],
            [],
        )
        removed_dependency_findings = repository.findings_requiring_revalidation(
            "codebase-1", snapshot_3.snapshot_id, hops=3
        )
        assert callee_finding.finding_id in removed_dependency_findings


def test_graph_relationship_changes_invalidate_findings_linked_to_graph_slice():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    source_hash = "source-hash"
    node = CodeNode("handler", "app.js", 4, "updateAccount", source_hash)
    edge = CodeEdge("route", "handler", "calls", "tree_sitter", "app.js", 3, source_hash)
    previous_graph = CodeGraphSnapshot(
        source_hashes={"app.js": source_hash},
        nodes=(node,),
        edges=(edge,),
        unresolved_edges=0,
        extractor_version="test",
    )
    dependencies = [
        FindingDependencyInput("source_file", "app.js", source_hash),
        FindingDependencyInput("graph_node", node.id, node.source_hash),
        FindingDependencyInput(
            "graph_node_neighborhood",
            node.id,
            graph_node_neighborhood_hash(previous_graph, node.id),
        ),
        FindingDependencyInput("graph_edge", graph_edge_identity(edge), graph_edge_identity(edge)),
    ]

    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-graph", "local/graph", "Graph")
        snapshot = repository.add_snapshot(
            "snapshot-graph", "codebase-graph", "revision-graph", "tree-graph", "context-v1"
        )
        scan = repository.start_scan(
            "scan-graph", "codebase-graph", snapshot.snapshot_id, "deep", "workflow-v1"
        )
        finding = repository.save_finding(
            "finding-graph",
            "codebase-graph",
            scan.scan_id,
            "fingerprint-graph",
            "Authorization finding",
            "authorization",
            "high",
            "validated",
            0.9,
            "The route reaches the handler without an ownership check.",
            "Cross-account update.",
            "Enforce ownership.",
            {"deep_hunt": "supported"},
            [],
            dependencies,
        )
        assert repository.findings_requiring_graph_revalidation(
            "codebase-graph", previous_graph
        ) == []

        # The file and node are unchanged, but the route-to-handler relationship
        # disappeared. This must invalidate the finding because reachability was
        # part of the evidence packet.
        changed_graph = CodeGraphSnapshot(
            source_hashes={"app.js": source_hash},
            nodes=(node,),
            edges=(),
            unresolved_edges=0,
            extractor_version="test",
        )
        stale = repository.findings_requiring_graph_revalidation(
            "codebase-graph", changed_graph
        )
        assert stale == [finding.finding_id]
