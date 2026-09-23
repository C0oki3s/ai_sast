"""Ordered PostgreSQL migration runner for deployable Code Scanning jobs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine, inspect
from sqlalchemy.orm import Session

from ..assets import ASSET_ROOT, AssetConfigurationError, load_json
from .models import SchemaMigrationRecord


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Migration:
    version: str
    relative_path: str
    checksum: str
    sql: str


def migration_plan() -> list[Migration]:
    manifest = load_json("migrations/postgresql/manifest.json")
    migrations: list[Migration] = []
    seen: set[str] = set()
    for configured in manifest["migrations"]:
        relative = str(configured)
        path = (ASSET_ROOT / relative).resolve()
        if ASSET_ROOT not in path.parents or not path.is_file():
            raise AssetConfigurationError(f"PostgreSQL migration is invalid: {relative}")
        version = Path(relative).stem
        if version in seen:
            raise MigrationError(f"duplicate PostgreSQL migration version: {version}")
        seen.add(version)
        content = path.read_text(encoding="utf-8")
        migrations.append(
            Migration(
                version=version,
                relative_path=relative,
                checksum=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                sql=content,
            )
        )
    return migrations


def apply_migrations(engine: Engine) -> list[str]:
    applied: list[str] = []
    for migration in migration_plan():
        existing = _existing_checksum(engine, migration.version)
        if existing == migration.checksum:
            continue
        if existing and existing != "managed-by-release-checksum":
            raise MigrationError(f"checksum mismatch for applied migration {migration.version}")
        if existing != "managed-by-release-checksum":
            with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                connection.exec_driver_sql(migration.sql)
        with Session(engine) as session, session.begin():
            record = session.get(SchemaMigrationRecord, migration.version)
            if record is None:
                session.add(SchemaMigrationRecord(version=migration.version, checksum=migration.checksum))
            else:
                record.checksum = migration.checksum
        applied.append(migration.version)
    return applied


def _existing_checksum(engine: Engine, version: str) -> str | None:
    if not inspect(engine).has_table("code_scanning_schema_migrations"):
        return None
    with Session(engine) as session:
        record = session.get(SchemaMigrationRecord, version)
        return record.checksum if record is not None else None
