"""Tenant-scoped ORM repositories for Code Scanning persistence."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .models import CodebaseRecord, ScanRunRecord, SnapshotRecord


class PersistenceConflictError(RuntimeError):
    """Raised when an immutable record is reused with conflicting data."""


@dataclass(frozen=True, slots=True)
class CodebaseValue:
    codebase_id: str
    tenant_id: str
    external_key: str
    display_name: str
    status: str


@dataclass(frozen=True, slots=True)
class SnapshotValue:
    snapshot_id: str
    tenant_id: str
    codebase_id: str
    revision: str
    tree_hash: str
    context_version: str
    state: str


@dataclass(frozen=True, slots=True)
class ScanRunValue:
    scan_id: str
    tenant_id: str
    codebase_id: str
    snapshot_id: str
    state: str
    mode: str
    workflow_version: str


class CodeScanningRepository:
    """Repository methods require an explicit tenant scope for every root row."""

    def __init__(self, session: Session, tenant_id: str) -> None:
        if not tenant_id.strip():
            raise ValueError("tenant_id is required")
        self.session = session
        self.tenant_id = tenant_id

    def get_codebase(self, codebase_id: str) -> CodebaseValue | None:
        record = self.session.scalar(
            select(CodebaseRecord).where(
                CodebaseRecord.codebase_id == codebase_id,
                CodebaseRecord.tenant_id == self.tenant_id,
            )
        )
        return _codebase_value(record) if record else None

    def add_codebase(
        self,
        codebase_id: str,
        external_key: str,
        display_name: str,
    ) -> CodebaseValue:
        existing = self.get_codebase(codebase_id)
        if existing:
            if existing.external_key != external_key:
                raise PersistenceConflictError("codebase_id already identifies a different external key")
            return existing
        record = CodebaseRecord(
            codebase_id=codebase_id,
            tenant_id=self.tenant_id,
            external_key=external_key,
            display_name=display_name,
            status="active",
        )
        self.session.add(record)
        self.session.flush()
        return _codebase_value(record)

    def get_snapshot_by_revision(self, codebase_id: str, revision: str) -> SnapshotValue | None:
        record = self.session.scalar(
            select(SnapshotRecord).where(
                SnapshotRecord.tenant_id == self.tenant_id,
                SnapshotRecord.codebase_id == codebase_id,
                SnapshotRecord.revision == revision,
            )
        )
        return _snapshot_value(record) if record else None

    def get_snapshot(self, snapshot_id: str) -> SnapshotValue | None:
        record = self.session.scalar(
            select(SnapshotRecord).where(
                SnapshotRecord.snapshot_id == snapshot_id,
                SnapshotRecord.tenant_id == self.tenant_id,
            )
        )
        return _snapshot_value(record) if record else None

    def add_snapshot(
        self,
        snapshot_id: str,
        codebase_id: str,
        revision: str,
        tree_hash: str,
        context_version: str,
        parent_snapshot_id: str | None = None,
    ) -> SnapshotValue:
        existing = self.get_snapshot_by_revision(codebase_id, revision)
        if existing:
            if existing.tree_hash != tree_hash or existing.context_version != context_version:
                raise PersistenceConflictError("immutable snapshot revision has conflicting content")
            return existing
        if self.get_codebase(codebase_id) is None:
            raise PersistenceConflictError("snapshot codebase does not exist in the tenant scope")
        record = SnapshotRecord(
            snapshot_id=snapshot_id,
            tenant_id=self.tenant_id,
            codebase_id=codebase_id,
            revision=revision,
            tree_hash=tree_hash,
            context_version=context_version,
            parent_snapshot_id=parent_snapshot_id,
            state="indexed",
        )
        self.session.add(record)
        self.session.flush()
        return _snapshot_value(record)

    def start_scan(
        self,
        scan_id: str,
        codebase_id: str,
        snapshot_id: str,
        mode: str,
        workflow_version: str,
    ) -> ScanRunValue:
        existing = self.session.scalar(
            select(ScanRunRecord).where(
                ScanRunRecord.scan_id == scan_id,
                ScanRunRecord.tenant_id == self.tenant_id,
            )
        )
        if existing:
            if existing.snapshot_id != snapshot_id:
                raise PersistenceConflictError("scan_id already identifies another snapshot")
            return _scan_value(existing)
        snapshot = self.get_snapshot(snapshot_id)
        if snapshot is None or snapshot.codebase_id != codebase_id:
            raise PersistenceConflictError("scan snapshot does not exist in the tenant scope")
        record = ScanRunRecord(
            scan_id=scan_id,
            tenant_id=self.tenant_id,
            codebase_id=codebase_id,
            snapshot_id=snapshot_id,
            state="pending",
            mode=mode,
            workflow_version=workflow_version,
            coverage_complete=False,
            failure_code="",
        )
        self.session.add(record)
        self.session.flush()
        return _scan_value(record)

@contextmanager
def unit_of_work(
    factory: sessionmaker[Session],
    tenant_id: str,
) -> Iterator[CodeScanningRepository]:
    """Commit one domain operation or roll the complete transaction back."""

    session = factory()
    try:
        with session.begin():
            yield CodeScanningRepository(session, tenant_id)
    finally:
        session.close()


def _codebase_value(record: CodebaseRecord) -> CodebaseValue:
    return CodebaseValue(
        record.codebase_id,
        record.tenant_id,
        record.external_key,
        record.display_name,
        record.status,
    )


def _snapshot_value(record: SnapshotRecord) -> SnapshotValue:
    return SnapshotValue(
        record.snapshot_id,
        record.tenant_id,
        record.codebase_id,
        record.revision,
        record.tree_hash,
        record.context_version,
        record.state,
    )


def _scan_value(record: ScanRunRecord) -> ScanRunValue:
    return ScanRunValue(
        record.scan_id,
        record.tenant_id,
        record.codebase_id,
        record.snapshot_id,
        record.state,
        record.mode,
        record.workflow_version,
    )
