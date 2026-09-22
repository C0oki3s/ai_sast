import re

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.assets import load_json, load_text
from plaidnox_sast.persistence.database import (
    DatabaseConfigurationError,
    DatabaseSettings,
)
from plaidnox_sast.persistence.models import Base
from plaidnox_sast.persistence.repositories import unit_of_work


def test_postgresql_configuration_is_external_and_password_is_redacted():
    settings = DatabaseSettings.from_environment(
        {"PLAIDNOX_DATABASE_URL": "postgresql+psycopg://scanner:secret@db/code_scanning"}
    )

    assert settings.url.drivername == "postgresql+psycopg"
    assert "secret" not in settings.redacted_url
    assert "***" in settings.redacted_url


def test_production_database_rejects_non_postgresql_driver():
    with pytest.raises(DatabaseConfigurationError, match="Unsupported production database driver"):
        DatabaseSettings.from_environment({"PLAIDNOX_DATABASE_URL": "sqlite:///context.sqlite"})


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
