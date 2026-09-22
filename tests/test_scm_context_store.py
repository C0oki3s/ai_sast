from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_scm.context_store import ApplicationContext, unit_of_work
from plaidnox_scm.models import Base


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _context(codebase_id: str, tenant_id: str) -> ApplicationContext:
    return ApplicationContext(
        codebase_id=codebase_id,
        tenant_id=tenant_id,
        baseline_revision="base-sha",
        source_tree_hash="tree-sha",
        builder_version="test-builder",
        application_type="node-express",
        entry_points=("src/index.js",),
        components=("api",),
        security_controls=("session-middleware",),
        routes=("/signin",),
        sensitive_effects=("writes user table",),
        environment_metadata={"runtime": "node20"},
        identity_provider="cognito",
        prior_finding_refs=("finding-1",),
        confidence=0.8,
        context_version="1",
        computed_at=datetime.now(UTC),
    )


def test_upsert_then_get_round_trips_through_sqlite() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.upsert_context(_context("codebase-1", "tenant-a"))

    with unit_of_work(factory, "tenant-a") as repository:
        fetched = repository.get_context("codebase-1")

    assert fetched is not None
    assert fetched.application_type == "node-express"
    assert fetched.entry_points == ("src/index.js",)
    assert fetched.identity_provider == "cognito"


def test_get_context_is_tenant_scoped() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.upsert_context(_context("codebase-1", "tenant-a"))

    with unit_of_work(factory, "tenant-b") as repository:
        fetched = repository.get_context("codebase-1")

    assert fetched is None


def test_same_codebase_identity_can_be_cached_for_multiple_tenants() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.upsert_context(_context("shared-codebase", "tenant-a"))
    with unit_of_work(factory, "tenant-b") as repository:
        repository.upsert_context(_context("shared-codebase", "tenant-b"))

    with unit_of_work(factory, "tenant-a") as repository:
        tenant_a = repository.get_context("shared-codebase")
    with unit_of_work(factory, "tenant-b") as repository:
        tenant_b = repository.get_context("shared-codebase")

    assert tenant_a is not None and tenant_a.tenant_id == "tenant-a"
    assert tenant_b is not None and tenant_b.tenant_id == "tenant-b"


def test_get_or_compute_reuses_cached_context_without_recomputing() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)
    calls = 0

    def compute() -> ApplicationContext:
        nonlocal calls
        calls += 1
        return _context("codebase-1", "tenant-a")

    with unit_of_work(factory, "tenant-a") as repository:
        repository.get_or_compute("codebase-1", "base-sha", compute)
    assert calls == 1

    with unit_of_work(factory, "tenant-a") as repository:
        repository.get_or_compute("codebase-1", "base-sha", compute)
    assert calls == 1  # cache hit: compute must not run again


def test_get_or_compute_rebuilds_context_when_baseline_changes() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)
    calls = 0

    def compute(revision: str) -> ApplicationContext:
        nonlocal calls
        calls += 1
        original = _context("codebase-1", "tenant-a")
        return replace(original, baseline_revision=revision, source_tree_hash=f"tree-{revision}")

    with unit_of_work(factory, "tenant-a") as repository:
        repository.get_or_compute("codebase-1", "base-a", lambda: compute("base-a"))
    with unit_of_work(factory, "tenant-a") as repository:
        repository.get_or_compute("codebase-1", "base-b", lambda: compute("base-b"))

    assert calls == 2


def test_get_or_compute_rebuilds_context_when_builder_version_changes() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)
    calls = 0

    def compute(builder_version: str) -> ApplicationContext:
        nonlocal calls
        calls += 1
        return replace(_context("codebase-1", "tenant-a"), builder_version=builder_version)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.get_or_compute(
            "codebase-1",
            "base-sha",
            lambda: compute("builder-a"),
            builder_version="builder-a",
        )
    with unit_of_work(factory, "tenant-a") as repository:
        repository.get_or_compute(
            "codebase-1",
            "base-sha",
            lambda: compute("builder-b"),
            builder_version="builder-b",
        )

    assert calls == 2
