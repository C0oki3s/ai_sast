from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.graphify_adapter import CodeEdge, CodeGraphSnapshot, CodeNode
from plaidnox_sast.persistence.models import Base
from plaidnox_sast.persistence.repositories import PersistenceConflictError, unit_of_work
from plaidnox_sast.persistence.models import ScanRunRecord


def _snapshot(source: str, *, add_node: bool = False) -> CodeGraphSnapshot:
    source_hash = hashlib.sha256(source.encode()).hexdigest()
    nodes = [CodeNode("handler", "app.py", 1, "handler()", source_hash)]
    edges = []
    if add_node:
        nodes.append(CodeNode("service", "app.py", 2, "service()", source_hash))
        edges.append(
            CodeEdge("handler", "service", "calls", "EXTRACTED", "app.py", 1, source_hash)
        )
    return CodeGraphSnapshot(
        source_hashes={"app.py": source_hash},
        nodes=tuple(nodes),
        edges=tuple(edges),
        unresolved_edges=0,
        extractor_version="test-extractor",
    )


def test_graphify_snapshot_is_normalized_tenant_scoped_and_loads_latest():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    first = _snapshot("def handler(): pass\n")
    second = _snapshot("def handler(): return service()\n", add_node=True)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-a", "org/repo", "repo")
        for scan_id, storage_id, revision in (
            ("scan-a", "snapshot-a", "rev-a"),
            ("scan-b", "snapshot-b", "rev-b"),
        ):
            repository.add_snapshot(
                storage_id, "codebase-a", revision, revision, "context-v1"
            )
            repository.start_scan(scan_id, "codebase-a", storage_id, "deep", "workflow-v1")
        scan_b = repository.session.get(ScanRunRecord, "scan-b")
        assert scan_b is not None
        scan_b.created_at = datetime.now(UTC) + timedelta(seconds=1)
        saved = repository.save_graphify_snapshot("scan-a", "snapshot-a", first)
        assert saved.graph_snapshot == first
        assert repository.save_graphify_snapshot("scan-a", "snapshot-a", first) == saved

    with unit_of_work(factory, "tenant-a") as repository:
        previous = repository.latest_graphify_snapshot(
            "codebase-a", excluding_scan_id="scan-b"
        )
        assert previous is not None
        assert previous.graph_snapshot == first
        saved = repository.save_graphify_snapshot("scan-b", "snapshot-b", second)
        assert saved.graph_snapshot == second
        current = repository.latest_graphify_snapshot("codebase-a")
        assert current is not None
        assert current.scan_id == "scan-b"
        assert current.graph_snapshot == second

    with unit_of_work(factory, "tenant-b") as repository:
        assert repository.latest_graphify_snapshot("codebase-a") is None
        assert repository.get_graphify_snapshot(saved.graphify_record_id) is None


def test_graphify_snapshot_retry_rejects_conflicting_immutable_data():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    original = _snapshot("def handler(): pass\n")
    changed = _snapshot("def handler(): return 1\n")
    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-a", "org/repo", "repo")
        repository.add_snapshot(
            "snapshot-a", "codebase-a", "rev-a", "tree-a", "context-v1"
        )
        repository.start_scan("scan-a", "codebase-a", "snapshot-a", "deep", "workflow-v1")
        repository.save_graphify_snapshot("scan-a", "snapshot-a", original)

    with unit_of_work(factory, "tenant-a") as repository:
        try:
            repository.save_graphify_snapshot("scan-a", "snapshot-a", changed)
        except PersistenceConflictError as exc:
            assert "changed during scan resume" in str(exc)
        else:  # pragma: no cover - protects the immutability invariant
            raise AssertionError("conflicting Graphify graph was accepted")
