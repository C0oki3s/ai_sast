"""Tenant-scoped ORM repositories for Code Scanning persistence."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from ..assets import load_json
from ..graph import StructuralGraph, Symbol, stable_symbol_id, stable_symbol_keys
from ..investigations import Investigation, validate_investigation
from ..redaction import redact_payload
from .models import (
    ArtifactRecord,
    AuditEventRecord,
    CodebaseRecord,
    CodeEdgeRecord,
    DeletionRequestRecord,
    FindingDependencyRecord,
    FindingEvidenceRecord,
    FindingRecord,
    GraphifyEdgeRecord,
    GraphifyNodeRecord,
    GraphifySnapshotRecord,
    HuntPlanRecord,
    HuntTaskRecord,
    InvestigationRecord,
    KnowledgeUsageRecord,
    OverlaySymbolSummaryRecord,
    RepositoryContextRecord,
    ScanJobRecord,
    ScanFindingRecord,
    ScanRunRecord,
    SecurityKnowledgeRecord,
    SecurityMemoryRecord,
    SnapshotRecord,
    SurfacePlanningRecord,
    SourceFileRecord,
    SymbolSummaryRecord,
    SymbolRecord,
    TenantControlRecord,
    UsageEventRecord,
)


class PersistenceConflictError(RuntimeError):
    """Raised when an immutable record is reused with conflicting data."""


class ProductionControlError(RuntimeError):
    """Raised when a queue, quota, retention, or artifact invariant is violated."""


def _hash(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()[:16]


def stable_id(prefix: str, *parts: str) -> str:
    """A codebase/revision-derived id safe as a primary key (unlike raw names)."""

    digest = hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()[:32]
    return f"{prefix}-{digest}"


def symbol_id(stable_key: str) -> str:
    """Return the cross-snapshot identity used for a Security IR symbol."""

    return stable_symbol_id(stable_key)


# Versions the shape of `security_ir_inputs()`'s output, independent of prompt wording.
SECURITY_IR_CONTEXT_VERSION = "1"


def snapshot_tree_hash(graph: StructuralGraph) -> str:
    digest = hashlib.sha256()
    for item in sorted(graph.files, key=lambda value: value.path):
        digest.update(item.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(item.content_hash.encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


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
    scan_status: str = "RUNNING"
    scan_parameters: dict[str, Any] = field(default_factory=dict)
    result_summary: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanFindingValue:
    scan_finding_id: str
    tenant_id: str
    scan_id: str
    finding_id: str | None
    fingerprint: str
    severity: str
    category: str
    cwe_id: int | None
    owasp_category: str
    report_schema_version: int
    report_data: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TenantControlValue:
    tenant_id: str
    maximum_concurrent_jobs: int
    maximum_daily_jobs: int
    maximum_monthly_model_cost_usd: float
    completed_scan_retention_days: int
    failed_scan_retention_days: int


@dataclass(frozen=True, slots=True)
class ScanJobValue:
    job_id: str
    tenant_id: str
    request_key: str
    codebase_external_key: str
    revision: str
    snapshot_uri: str
    output_uri: str
    job_data: dict[str, Any]
    state: str
    priority: int
    attempt_count: int
    maximum_attempts: int
    lease_owner: str | None
    lease_expires_at: datetime | None
    failure_code: str
    result_summary: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SourceFileInput:
    path: str
    language: str
    content_hash: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class SymbolInput:
    """Occurrence-disambiguated identity; `stable_key` must exclude content (Rule 5)."""

    stable_key: str
    qualified_name: str
    kind: str
    path: str
    start_line: int
    end_line: int
    content_hash: str
    content: str
    signature: str = ""


@dataclass(frozen=True, slots=True)
class SymbolIdentity:
    symbol_id: str
    stable_key: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class SymbolValue:
    symbol_id: str
    stable_key: str
    qualified_name: str
    kind: str
    path: str
    start_line: int
    end_line: int
    content_hash: str
    content: str


@dataclass(frozen=True, slots=True)
class SecurityMemoryValue:
    memory_id: str
    codebase_id: str | None
    scope: str
    category: str
    statement: str
    provenance: str
    status: str
    version: int


@dataclass(frozen=True, slots=True)
class EdgeInput:
    source_stable_key: str
    target_stable_key: str
    relation: str
    provenance: str
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class HuntPlanValue:
    plan_id: str
    scan_id: str
    strategy: str
    context_hash: str
    workflow_version: str


@dataclass(frozen=True, slots=True)
class HuntTaskInput:
    task_key: str
    title: str
    objective: str
    task_data: dict[str, Any]


@dataclass(frozen=True, slots=True)
class HuntTaskValue:
    task_id: str
    plan_id: str
    task_key: str
    title: str
    objective: str
    task_data: dict[str, Any]
    state: str
    attempt_count: int
    lease_owner: str | None
    lease_expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class InvestigationValue:
    investigation_id: str
    scan_id: str
    codebase_id: str
    snapshot_id: str
    stable_key: str
    evidence_hash: str
    investigation_data: dict[str, Any]
    state: str
    checkpoint_ref: str | None
    revision: int
    attempt_count: int


@dataclass(frozen=True, slots=True)
class SurfacePlanningValue:
    scan_id: str
    tenant_id: str
    snapshot_id: str
    state: str
    revision: int
    planning_data: dict[str, Any]


@dataclass(frozen=True, slots=True)
class GraphifySnapshotValue:
    graphify_record_id: str
    tenant_id: str
    codebase_id: str
    scan_id: str
    snapshot_id: str
    graph_snapshot: Any


@dataclass(frozen=True, slots=True)
class FindingEvidenceInput:
    evidence_type: str
    path: str
    start_line: int | None
    end_line: int | None
    redacted_content: str
    content_hash: str
    provenance: str


@dataclass(frozen=True, slots=True)
class FindingDependencyInput:
    dependency_type: str
    dependency_key: str
    dependency_hash: str


@dataclass(frozen=True, slots=True)
class FindingEvidenceValue(FindingEvidenceInput):
    evidence_id: str
    sequence: int


@dataclass(frozen=True, slots=True)
class FindingDependencyValue(FindingDependencyInput):
    finding_dependency_id: str


@dataclass(frozen=True, slots=True)
class KnowledgeInput:
    knowledge_id: str
    topic: str
    vulnerability_class: str
    ecosystem: str
    framework: str
    content: str
    source_url: str
    source_title: str
    source_updated_at: str
    provenance: str
    confidence: float
    content_hash: str
    claims: list[str]


@dataclass(frozen=True, slots=True)
class KnowledgeValue(KnowledgeInput):
    tenant_id: str
    status: str


@dataclass(frozen=True, slots=True)
class FindingValue:
    finding_id: str
    tenant_id: str
    codebase_id: str
    scan_id: str
    fingerprint: str
    title: str
    vulnerability_class: str
    severity: str
    state: str
    confidence: float
    summary: str
    impact: str
    remediation: str
    validation: dict[str, Any]
    evidence: list[FindingEvidenceValue]
    dependencies: list[FindingDependencyValue]


class CodeScanningRepository:
    """Repository methods require an explicit tenant scope for every root row."""

    def __init__(self, session: Session, tenant_id: str) -> None:
        if not tenant_id.strip():
            raise ValueError("tenant_id is required")
        self.session = session
        self.tenant_id = tenant_id

    def upsert_tenant_controls(
        self,
        *,
        maximum_concurrent_jobs: int,
        maximum_daily_jobs: int,
        maximum_monthly_model_cost_usd: float,
        completed_scan_retention_days: int,
        failed_scan_retention_days: int,
    ) -> TenantControlValue:
        values = (
            maximum_concurrent_jobs,
            maximum_daily_jobs,
            maximum_monthly_model_cost_usd,
            completed_scan_retention_days,
            failed_scan_retention_days,
        )
        if any(value <= 0 for value in (values[0], values[1], values[3], values[4])) or values[2] < 0:
            raise ProductionControlError("tenant control limits must be positive and cost must be nonnegative")
        record = self.session.get(TenantControlRecord, self.tenant_id)
        if record is None:
            record = TenantControlRecord(
                tenant_id=self.tenant_id,
                maximum_concurrent_jobs=maximum_concurrent_jobs,
                maximum_daily_jobs=maximum_daily_jobs,
                maximum_monthly_model_cost_usd=maximum_monthly_model_cost_usd,
                completed_scan_retention_days=completed_scan_retention_days,
                failed_scan_retention_days=failed_scan_retention_days,
            )
            self.session.add(record)
        else:
            record.maximum_concurrent_jobs = maximum_concurrent_jobs
            record.maximum_daily_jobs = maximum_daily_jobs
            record.maximum_monthly_model_cost_usd = maximum_monthly_model_cost_usd
            record.completed_scan_retention_days = completed_scan_retention_days
            record.failed_scan_retention_days = failed_scan_retention_days
        self.session.flush()
        return _tenant_control_value(record)

    def tenant_controls(self) -> TenantControlValue:
        record = self.session.get(TenantControlRecord, self.tenant_id)
        if record is None:
            runtime = load_json("runtime/production_controls.json")
            worker = runtime["worker"]
            retention = runtime["retention"]
            return self.upsert_tenant_controls(
                maximum_concurrent_jobs=int(worker["maximum_concurrent_jobs"]),
                maximum_daily_jobs=int(worker["maximum_daily_jobs"]),
                maximum_monthly_model_cost_usd=float(worker["maximum_monthly_model_cost_usd"]),
                completed_scan_retention_days=int(retention["completed_scan_days"]),
                failed_scan_retention_days=int(retention["failed_scan_days"]),
            )
        return _tenant_control_value(record)

    def enqueue_scan_job(
        self,
        request_key: str,
        codebase_external_key: str,
        revision: str,
        snapshot_uri: str,
        output_uri: str,
        *,
        job_data: dict[str, Any] | None = None,
        priority: int = 100,
        maximum_attempts: int | None = None,
        now: datetime | None = None,
    ) -> ScanJobValue:
        existing = self.session.scalar(
            select(ScanJobRecord).where(
                ScanJobRecord.tenant_id == self.tenant_id,
                ScanJobRecord.request_key == request_key,
            )
        )
        if existing is not None:
            return _scan_job_value(existing)
        if not all(
            value.strip()
            for value in (
                request_key,
                codebase_external_key,
                revision,
                snapshot_uri,
                output_uri,
            )
        ):
            raise ProductionControlError("scan job identity, revision, snapshot URI, and output URI are required")
        if priority < 0:
            raise ProductionControlError("scan job priority must be nonnegative")
        controls = self._lock_tenant_controls()
        moment = now or datetime.now(UTC)
        if self._monthly_model_cost(moment) >= controls.maximum_monthly_model_cost_usd:
            raise ProductionControlError("tenant monthly model-cost quota exceeded")
        daily_count = int(
            self.session.scalar(
                select(func.count())
                .select_from(ScanJobRecord)
                .where(
                    ScanJobRecord.tenant_id == self.tenant_id,
                    ScanJobRecord.created_at >= moment - timedelta(days=1),
                )
            )
            or 0
        )
        if daily_count >= controls.maximum_daily_jobs:
            raise ProductionControlError("tenant daily scan-job quota exceeded")
        configured_attempts = maximum_attempts or int(
            load_json("runtime/production_controls.json")["worker"]["maximum_attempts"]
        )
        record = ScanJobRecord(
            job_id=stable_id("job", self.tenant_id, request_key),
            tenant_id=self.tenant_id,
            request_key=request_key,
            codebase_external_key=codebase_external_key,
            revision=revision,
            snapshot_uri=snapshot_uri,
            output_uri=output_uri,
            job_data=redact_payload(job_data or {}),
            state="queued",
            priority=priority,
            attempt_count=0,
            maximum_attempts=configured_attempts,
            failure_code="",
            result_summary={},
        )
        self.session.add(record)
        self.session.flush()
        return _scan_job_value(record)

    def lease_next_scan_job(
        self,
        worker_id: str,
        lease_seconds: int,
        *,
        now: datetime | None = None,
    ) -> ScanJobValue | None:
        if not worker_id.strip() or lease_seconds <= 0:
            raise ProductionControlError("worker_id and a positive lease are required")
        moment = now or datetime.now(UTC)
        controls = self._lock_tenant_controls()
        # A worker that died holding a job's final attempt leaves it "leased" with
        # an expired lease; the lease query below skips exhausted jobs, so without
        # this the job would stay leased forever instead of reaching "failed".
        self.session.execute(
            update(ScanJobRecord)
            .where(
                ScanJobRecord.tenant_id == self.tenant_id,
                ScanJobRecord.state == "leased",
                ScanJobRecord.lease_expires_at <= moment,
                ScanJobRecord.attempt_count >= ScanJobRecord.maximum_attempts,
            )
            .values(
                state="failed",
                lease_owner=None,
                lease_expires_at=None,
                failure_code="lease_expired_attempts_exhausted",
            )
        )
        if self._monthly_model_cost(moment) >= controls.maximum_monthly_model_cost_usd:
            return None
        active = int(
            self.session.scalar(
                select(func.count())
                .select_from(ScanJobRecord)
                .where(
                    ScanJobRecord.tenant_id == self.tenant_id,
                    ScanJobRecord.state == "leased",
                    ScanJobRecord.lease_expires_at > moment,
                )
            )
            or 0
        )
        if active >= controls.maximum_concurrent_jobs:
            return None
        considered: set[str] = set()
        while True:
            filters = [
                ScanJobRecord.tenant_id == self.tenant_id,
                ScanJobRecord.state.in_(("queued", "leased")),
                ScanJobRecord.attempt_count < ScanJobRecord.maximum_attempts,
                or_(
                    ScanJobRecord.lease_expires_at.is_(None),
                    ScanJobRecord.lease_expires_at <= moment,
                ),
            ]
            if considered:
                filters.append(ScanJobRecord.job_id.not_in(considered))
            candidate_id = self.session.scalar(
                select(ScanJobRecord.job_id)
                .where(*filters)
                .order_by(
                    ScanJobRecord.priority,
                    ScanJobRecord.created_at,
                    ScanJobRecord.job_id,
                )
                .limit(1)
            )
            if candidate_id is None:
                return None
            considered.add(candidate_id)
            result = self.session.execute(
                update(ScanJobRecord)
                .where(
                    ScanJobRecord.job_id == candidate_id,
                    ScanJobRecord.tenant_id == self.tenant_id,
                    ScanJobRecord.state.in_(("queued", "leased")),
                    ScanJobRecord.attempt_count < ScanJobRecord.maximum_attempts,
                    or_(
                        ScanJobRecord.lease_expires_at.is_(None),
                        ScanJobRecord.lease_expires_at <= moment,
                    ),
                )
                .values(
                    state="leased",
                    lease_owner=worker_id,
                    lease_expires_at=moment + timedelta(seconds=lease_seconds),
                    attempt_count=ScanJobRecord.attempt_count + 1,
                    failure_code="",
                )
            )
            if result.rowcount == 1:
                self.session.flush()
                return _scan_job_value(self.session.get(ScanJobRecord, candidate_id))

    def renew_scan_job_lease(
        self,
        job_id: str,
        worker_id: str,
        lease_seconds: int,
        *,
        now: datetime | None = None,
    ) -> bool:
        moment = now or datetime.now(UTC)
        result = self.session.execute(
            update(ScanJobRecord)
            .where(
                ScanJobRecord.job_id == job_id,
                ScanJobRecord.tenant_id == self.tenant_id,
                ScanJobRecord.state == "leased",
                ScanJobRecord.lease_owner == worker_id,
                ScanJobRecord.lease_expires_at > moment,
            )
            .values(lease_expires_at=moment + timedelta(seconds=lease_seconds))
        )
        self.session.flush()
        return result.rowcount == 1

    def complete_scan_job(self, job_id: str, worker_id: str, result_summary: dict[str, Any]) -> bool:
        result = self.session.execute(
            update(ScanJobRecord)
            .where(
                ScanJobRecord.job_id == job_id,
                ScanJobRecord.tenant_id == self.tenant_id,
                ScanJobRecord.state == "leased",
                ScanJobRecord.lease_owner == worker_id,
            )
            .values(
                state="completed",
                lease_owner=None,
                lease_expires_at=None,
                result_summary=redact_payload(result_summary),
            )
        )
        self.session.flush()
        return result.rowcount == 1

    def fail_scan_job(self, job_id: str, worker_id: str, failure_code: str) -> bool:
        record = self.session.scalar(
            select(ScanJobRecord).where(
                ScanJobRecord.job_id == job_id,
                ScanJobRecord.tenant_id == self.tenant_id,
                ScanJobRecord.state == "leased",
                ScanJobRecord.lease_owner == worker_id,
            )
        )
        if record is None:
            return False
        record.state = "failed" if record.attempt_count >= record.maximum_attempts else "queued"
        record.lease_owner = None
        record.lease_expires_at = None
        record.failure_code = failure_code.strip()[:128] or "worker_error"
        self.session.flush()
        return True

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

    def latest_snapshot(
        self,
        codebase_id: str,
        exclude_snapshot_id: str = "",
    ) -> SnapshotValue | None:
        statement = select(SnapshotRecord).where(
            SnapshotRecord.tenant_id == self.tenant_id,
            SnapshotRecord.codebase_id == codebase_id,
        )
        if exclude_snapshot_id:
            statement = statement.where(SnapshotRecord.snapshot_id != exclude_snapshot_id)
        record = self.session.scalar(
            statement.order_by(SnapshotRecord.created_at.desc(), SnapshotRecord.snapshot_id.desc()).limit(1)
        )
        return _snapshot_value(record) if record else None

    def list_source_files(self, snapshot_id: str) -> list[SourceFileInput]:
        records = self.session.scalars(
            select(SourceFileRecord).where(SourceFileRecord.snapshot_id == snapshot_id).order_by(SourceFileRecord.path)
        ).all()
        return [SourceFileInput(item.path, item.language, item.content_hash, item.size_bytes) for item in records]

    def get_repository_context(self, snapshot_id: str) -> dict[str, object] | None:
        record = self.session.scalar(
            select(RepositoryContextRecord).where(
                RepositoryContextRecord.snapshot_id == snapshot_id,
                RepositoryContextRecord.tenant_id == self.tenant_id,
            )
        )
        return dict(record.context_data) if record is not None else None

    def save_repository_context(
        self,
        snapshot_id: str,
        codebase_id: str,
        context_data: dict[str, object],
    ) -> None:
        snapshot = self.get_snapshot(snapshot_id)
        if snapshot is None or snapshot.codebase_id != codebase_id:
            raise PersistenceConflictError("repository context snapshot does not exist in the tenant scope")
        serialized = json.dumps(context_data, sort_keys=True, ensure_ascii=False)
        context_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        record = self.session.scalar(
            select(RepositoryContextRecord).where(
                RepositoryContextRecord.snapshot_id == snapshot_id,
                RepositoryContextRecord.tenant_id == self.tenant_id,
            )
        )
        if record is None:
            self.session.add(
                RepositoryContextRecord(
                    snapshot_id=snapshot_id,
                    tenant_id=self.tenant_id,
                    codebase_id=codebase_id,
                    context_hash=context_hash,
                    context_data=context_data,
                )
            )
        else:
            record.context_hash = context_hash
            record.context_data = context_data
        self.session.flush()

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

    def attach_snapshot_parent(self, snapshot_id: str, parent_snapshot_id: str) -> None:
        """Attach an initially indexed revision to its immutable base exactly once."""
        child = self.session.scalar(
            select(SnapshotRecord).where(
                SnapshotRecord.snapshot_id == snapshot_id,
                SnapshotRecord.tenant_id == self.tenant_id,
            )
        )
        parent = self.get_snapshot(parent_snapshot_id)
        if child is None or parent is None:
            raise PersistenceConflictError("snapshot or parent is outside the tenant scope")
        if child.parent_snapshot_id not in (None, parent_snapshot_id):
            raise PersistenceConflictError("immutable snapshot is already attached to another parent")
        child.parent_snapshot_id = parent_snapshot_id
        self.session.flush()

    def clear_snapshot_security_summaries(self, snapshot_id: str) -> None:
        """Remove a just-indexed full summary set before storing its sparse overlay delta."""
        if self.get_snapshot(snapshot_id) is None:
            raise PersistenceConflictError("snapshot does not exist in the tenant scope")
        self.session.execute(delete(SymbolSummaryRecord).where(SymbolSummaryRecord.snapshot_id == snapshot_id))

    def start_scan(
        self,
        scan_id: str,
        codebase_id: str,
        snapshot_id: str,
        mode: str,
        workflow_version: str,
        scan_parameters: dict[str, Any] | None = None,
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
            if existing.state != "completed":
                existing.state = "running"
                existing.failure_code = ""
                existing.scan_status = "RUNNING"
                existing.scan_parameters = redact_payload(scan_parameters or {})
                existing.result_summary = {}
                existing.finished_at = None
                self.session.flush()
            return _scan_value(existing)
        snapshot = self.get_snapshot(snapshot_id)
        if snapshot is None or snapshot.codebase_id != codebase_id:
            raise PersistenceConflictError("scan snapshot does not exist in the tenant scope")
        record = ScanRunRecord(
            scan_id=scan_id,
            tenant_id=self.tenant_id,
            codebase_id=codebase_id,
            snapshot_id=snapshot_id,
            state="running",
            mode=mode,
            workflow_version=workflow_version,
            coverage_complete=False,
            failure_code="",
            scan_status="RUNNING",
            scan_parameters=redact_payload(scan_parameters or {}),
            result_summary={},
        )
        self.session.add(record)
        self.session.flush()
        return _scan_value(record)

    def get_scan(self, scan_id: str) -> ScanRunValue | None:
        record = self.session.scalar(
            select(ScanRunRecord).where(
                ScanRunRecord.scan_id == scan_id,
                ScanRunRecord.tenant_id == self.tenant_id,
            )
        )
        return _scan_value(record) if record is not None else None

    def finish_scan(
        self,
        scan_id: str,
        *,
        coverage_complete: bool,
        failure_code: str = "",
        scan_status: str | None = None,
        result_summary: dict[str, Any] | None = None,
    ) -> bool:
        state = "completed" if coverage_complete else "incomplete"
        normalized_status = scan_status or ("SUCCESSFUL" if coverage_complete else "UNSUCCESSFUL")
        if normalized_status not in {"SUCCESSFUL", "UNSUCCESSFUL"}:
            raise ValueError("scan_status must be SUCCESSFUL or UNSUCCESSFUL")
        result = self.session.execute(
            update(ScanRunRecord)
            .where(
                ScanRunRecord.scan_id == scan_id,
                ScanRunRecord.tenant_id == self.tenant_id,
            )
            .values(
                state=state,
                coverage_complete=coverage_complete,
                failure_code=failure_code.strip()[:128],
                scan_status=normalized_status,
                result_summary=redact_payload(result_summary or {}),
                finished_at=datetime.now(UTC),
            )
        )
        self.session.flush()
        return result.rowcount == 1

    def save_scan_finding(
        self,
        *,
        scan_id: str,
        finding_id: str | None,
        fingerprint: str,
        severity: str,
        category: str,
        cwe_id: int | None,
        owasp_category: str,
        report_schema_version: int,
        report_data: dict[str, Any],
    ) -> ScanFindingValue:
        """Persist the finding's reportable fields and evidence snapshot for this run."""
        scan = self.session.scalar(
            select(ScanRunRecord).where(
                ScanRunRecord.scan_id == scan_id,
                ScanRunRecord.tenant_id == self.tenant_id,
            )
        )
        if scan is None:
            raise PersistenceConflictError("scan does not exist in the tenant scope")
        if report_schema_version < 1 or cwe_id is not None and cwe_id < 1:
            raise ValueError("report schema version and CWE identifiers must be positive")
        record = self.session.scalar(
            select(ScanFindingRecord).where(
                ScanFindingRecord.scan_id == scan_id,
                ScanFindingRecord.fingerprint == fingerprint,
                ScanFindingRecord.tenant_id == self.tenant_id,
            )
        )
        values = dict(
            finding_id=finding_id,
            severity=severity.strip().lower()[:32],
            category=category.strip()[:255],
            cwe_id=cwe_id,
            owasp_category=owasp_category.strip()[:255],
            report_schema_version=report_schema_version,
            report_data=redact_payload(report_data),
        )
        if record is None:
            record = ScanFindingRecord(
                scan_finding_id=stable_id("scan-finding", scan_id, fingerprint),
                tenant_id=self.tenant_id,
                scan_id=scan_id,
                fingerprint=fingerprint,
                **values,
            )
            self.session.add(record)
        else:
            for name, value in values.items():
                setattr(record, name, value)
        self.session.flush()
        return _scan_finding_value(record)

    def scan_findings(self, scan_id: str) -> list[ScanFindingValue]:
        """Load the complete, tenant-scoped finding snapshots for a scan run."""
        rows = self.session.scalars(
            select(ScanFindingRecord)
            .where(
                ScanFindingRecord.scan_id == scan_id,
                ScanFindingRecord.tenant_id == self.tenant_id,
            )
            .order_by(ScanFindingRecord.severity, ScanFindingRecord.fingerprint)
        ).all()
        return [_scan_finding_value(row) for row in rows]

    def reusable_scan_findings(
        self,
        scan_id: str,
        *,
        codebase_id: str,
        workflow_version: str,
        context_scope_hash: str,
        require_graph_dependencies: bool = False,
    ) -> list[ScanFindingValue]:
        """Read prior successful report snapshots with compatible analysis scope.

        Cross-snapshot callers require the explicit current graph-dependency contract;
        older findings remain eligible only for exact-snapshot reuse.
        """
        scan = self.session.scalar(
            select(ScanRunRecord).where(
                ScanRunRecord.scan_id == scan_id,
                ScanRunRecord.tenant_id == self.tenant_id,
                ScanRunRecord.codebase_id == codebase_id,
                ScanRunRecord.scan_status == "SUCCESSFUL",
                ScanRunRecord.workflow_version == workflow_version,
            )
        )
        if scan is None or scan.scan_parameters.get("context_scope_hash") != context_scope_hash:
            return []
        rows = self.session.execute(
            select(ScanFindingRecord, FindingRecord.state, FindingRecord.validation)
            .join(FindingRecord, FindingRecord.finding_id == ScanFindingRecord.finding_id)
            .where(
                ScanFindingRecord.scan_id == scan_id,
                ScanFindingRecord.tenant_id == self.tenant_id,
                ScanFindingRecord.report_schema_version == 1,
                FindingRecord.tenant_id == self.tenant_id,
                FindingRecord.codebase_id == codebase_id,
                FindingRecord.state.in_(("validated", "open", "in_progress")),
            )
            .order_by(ScanFindingRecord.fingerprint)
        ).all()
        return [
            _scan_finding_value(record)
            for record, state, validation in rows
            if state in {"validated", "open", "in_progress"}
            and (
                not require_graph_dependencies
                or _has_complete_graph_finding_dependencies(validation)
            )
            if isinstance(record.report_data, dict)
            and record.report_data.get("schema_version") == 1
            and isinstance(record.report_data.get("taint_path"), list)
        ]

    def record_model_usage(
        self,
        usage_event_id: str,
        scan_id: str | None,
        model_alias: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        *,
        now: datetime | None = None,
    ) -> None:
        if min(input_tokens, output_tokens) < 0 or cost_usd < 0:
            raise ProductionControlError("model usage values must be nonnegative")
        # Spend has already been incurred by the time it is reported, so it is
        # always recorded; the monthly quota is enforced before new work starts
        # (enqueue_scan_job / lease_next_scan_job), where refusing still helps.
        if self.session.get(UsageEventRecord, usage_event_id) is not None:
            return
        moment = now or datetime.now(UTC)
        self.session.add(
            UsageEventRecord(
                usage_event_id=usage_event_id,
                tenant_id=self.tenant_id,
                scan_id=scan_id,
                model_alias=model_alias,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=cost_usd,
                created_at=moment,
            )
        )
        self.session.flush()

    def monthly_model_cost_exceeded(self, *, now: datetime | None = None) -> bool:
        controls = self.tenant_controls()
        return self._monthly_model_cost(now or datetime.now(UTC)) >= controls.maximum_monthly_model_cost_usd

    def _monthly_model_cost(self, moment: datetime) -> float:
        month_start = datetime(moment.year, moment.month, 1, tzinfo=UTC)
        return float(
            self.session.scalar(
                select(func.coalesce(func.sum(UsageEventRecord.cost_usd), 0.0)).where(
                    UsageEventRecord.tenant_id == self.tenant_id,
                    UsageEventRecord.created_at >= month_start,
                )
            )
            or 0.0
        )

    def _lock_tenant_controls(self) -> TenantControlValue:
        """Serialize quota check-then-act per tenant (no-op lock on SQLite)."""

        self.tenant_controls()
        record = self.session.scalar(
            select(TenantControlRecord).where(TenantControlRecord.tenant_id == self.tenant_id).with_for_update()
        )
        return _tenant_control_value(record)

    def append_audit_event(
        self,
        audit_event_id: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        outcome: str,
        details: dict[str, Any],
    ) -> str:
        existing = self.session.get(AuditEventRecord, audit_event_id)
        if existing is not None:
            return existing.event_hash
        safe_details = redact_payload(details)
        canonical = json.dumps(
            {
                "tenant_id": self.tenant_id,
                "event_type": event_type,
                "actor_type": actor_type,
                "actor_id": actor_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "outcome": outcome,
                "details": safe_details,
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.session.add(
            AuditEventRecord(
                audit_event_id=audit_event_id,
                tenant_id=self.tenant_id,
                event_type=event_type,
                actor_type=actor_type,
                actor_id=actor_id,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome=outcome,
                details=safe_details,
                event_hash=event_hash,
            )
        )
        self.session.flush()
        return event_hash

    def register_artifact(
        self,
        artifact_id: str,
        scan_id: str | None,
        artifact_kind: str,
        storage_uri: str,
        content_hash: str,
        encryption_key_ref: str,
        expires_at: datetime,
    ) -> None:
        if not encryption_key_ref.strip():
            raise ProductionControlError("artifact encryption key reference is required")
        if expires_at.tzinfo is None:
            raise ProductionControlError("artifact expiry must include a timezone")
        existing = self.session.get(ArtifactRecord, artifact_id)
        if existing is not None:
            if existing.content_hash != content_hash or existing.storage_uri != storage_uri:
                raise PersistenceConflictError("artifact_id already identifies different content")
            return
        self.session.add(
            ArtifactRecord(
                artifact_id=artifact_id,
                tenant_id=self.tenant_id,
                scan_id=scan_id,
                artifact_kind=artifact_kind,
                storage_uri=storage_uri,
                content_hash=content_hash,
                encryption_key_ref=encryption_key_ref,
                expires_at=expires_at,
            )
        )
        self.session.flush()

    def artifacts_due_for_deletion(self, *, now: datetime | None = None) -> list[str]:
        moment = now or datetime.now(UTC)
        return list(
            self.session.scalars(
                select(ArtifactRecord.artifact_id)
                .where(
                    ArtifactRecord.tenant_id == self.tenant_id,
                    ArtifactRecord.deleted_at.is_(None),
                    ArtifactRecord.expires_at <= moment,
                )
                .order_by(ArtifactRecord.expires_at, ArtifactRecord.artifact_id)
            ).all()
        )

    def mark_artifact_deleted(self, artifact_id: str, *, now: datetime | None = None) -> bool:
        result = self.session.execute(
            update(ArtifactRecord)
            .where(
                ArtifactRecord.artifact_id == artifact_id,
                ArtifactRecord.tenant_id == self.tenant_id,
                ArtifactRecord.deleted_at.is_(None),
            )
            .values(deleted_at=now or datetime.now(UTC))
        )
        self.session.flush()
        return result.rowcount == 1

    def request_deletion(
        self,
        deletion_request_id: str,
        resource_type: str,
        resource_id: str,
        requested_by: str,
        reason: str,
    ) -> None:
        if not reason.strip():
            raise ProductionControlError("deletion requests require an auditable reason")
        if self.session.get(DeletionRequestRecord, deletion_request_id) is not None:
            return
        self.session.add(
            DeletionRequestRecord(
                deletion_request_id=deletion_request_id,
                tenant_id=self.tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
                requested_by=requested_by,
                reason=reason,
                state="pending",
            )
        )
        self.session.flush()

    def save_security_ir(
        self,
        snapshot_id: str,
        source_files: Iterable[SourceFileInput],
        symbols: Iterable[SymbolInput],
        edges: Iterable[EdgeInput],
    ) -> bool:
        """Persist Security IR for an immutable snapshot; no-op if already indexed."""

        already_indexed = self.session.scalar(
            select(SourceFileRecord.source_file_id).where(SourceFileRecord.snapshot_id == snapshot_id).limit(1)
        )
        if already_indexed is not None:
            return False
        file_id_by_path: dict[str, str] = {}
        for item in source_files:
            source_file_id = f"srcfile-{_hash(snapshot_id, item.path)}"
            file_id_by_path[item.path] = source_file_id
            self.session.add(
                SourceFileRecord(
                    source_file_id=source_file_id,
                    snapshot_id=snapshot_id,
                    path=item.path,
                    language=item.language,
                    content_hash=item.content_hash,
                    size_bytes=item.size_bytes,
                )
            )
        symbol_id_by_key: dict[str, str] = {}
        for item in symbols:
            source_file_id = file_id_by_path.get(item.path)
            if source_file_id is None:
                raise PersistenceConflictError(f"symbol path {item.path!r} has no matching source file")
            current_symbol_id = symbol_id(item.stable_key)
            symbol_id_by_key[item.stable_key] = current_symbol_id
            self.session.add(
                SymbolRecord(
                    symbol_version_id=f"symv-{_hash(snapshot_id, item.stable_key)}",
                    symbol_id=current_symbol_id,
                    snapshot_id=snapshot_id,
                    source_file_id=source_file_id,
                    stable_key=item.stable_key,
                    qualified_name=item.qualified_name,
                    signature=item.signature,
                    kind=item.kind,
                    path=item.path,
                    start_line=item.start_line,
                    end_line=item.end_line,
                    content_hash=item.content_hash,
                    content=item.content,
                )
            )
        for item in edges:
            source_symbol_id = symbol_id_by_key.get(item.source_stable_key)
            target_symbol_id = symbol_id_by_key.get(item.target_stable_key)
            if source_symbol_id is None or target_symbol_id is None:
                continue
            self.session.add(
                CodeEdgeRecord(
                    edge_id=f"edge-{_hash(snapshot_id, source_symbol_id, target_symbol_id, item.relation)}",
                    snapshot_id=snapshot_id,
                    source_symbol_id=source_symbol_id,
                    target_symbol_id=target_symbol_id,
                    relation=item.relation,
                    provenance=item.provenance,
                    confidence=item.confidence,
                    attributes={},
                )
            )
        self.session.flush()
        return True

    def save_security_summaries(self, snapshot_id: str, summaries: Iterable[dict[str, Any]]) -> int:
        """Persist immutable content-versioned summaries for one tenant snapshot."""
        if self.get_snapshot(snapshot_id) is None:
            raise PersistenceConflictError("snapshot does not exist in the tenant scope")
        incoming = {str(item["symbol_id"]): dict(item) for item in summaries}
        from ..worksets import validate_security_contract

        for symbol_id_value, data in incoming.items():
            validate_security_contract("security_summary", data)
            if data["symbol_id"] != symbol_id_value:
                raise PersistenceConflictError("summary key does not match its symbol identity")
        existing_rows = (
            self.session.execute(select(SymbolSummaryRecord).where(SymbolSummaryRecord.snapshot_id == snapshot_id))
            .scalars()
            .all()
        )
        existing = {item.symbol_id: item for item in existing_rows}
        if existing and set(existing) != set(incoming):
            raise PersistenceConflictError("immutable snapshot has a conflicting symbol summary set")
        inserted = 0
        for symbol_id_value, data in incoming.items():
            content_hash = str(data.get("content_hash", ""))
            prior = existing.get(symbol_id_value)
            if prior is not None:
                if prior.content_hash != content_hash or prior.summary_data != data:
                    raise PersistenceConflictError("immutable snapshot has conflicting symbol summary data")
                continue
            record_id = stable_id("summary", snapshot_id, symbol_id_value)
            self.session.add(
                SymbolSummaryRecord(
                    summary_record_id=record_id,
                    snapshot_id=snapshot_id,
                    symbol_id=symbol_id_value,
                    content_hash=content_hash,
                    summary_data=data,
                )
            )
            inserted += 1
        self.session.flush()
        return inserted

    def list_security_summaries(self, snapshot_id: str) -> list[dict[str, Any]]:
        """Load summaries only from an existing tenant-owned snapshot."""
        if self.get_snapshot(snapshot_id) is None:
            raise PersistenceConflictError("snapshot does not exist in the tenant scope")
        rows = (
            self.session.execute(
                select(SymbolSummaryRecord.summary_data)
                .where(SymbolSummaryRecord.snapshot_id == snapshot_id)
                .order_by(SymbolSummaryRecord.symbol_id)
            )
            .scalars()
            .all()
        )
        return [dict(item) for item in rows]

    def save_overlay_security_summaries(
        self,
        snapshot_id: str,
        base_snapshot_id: str,
        summaries: Iterable[dict[str, Any]],
    ) -> int:
        """Persist only changed summaries and deletion tombstones for a child snapshot."""
        snapshot = self.get_snapshot(snapshot_id)
        base_snapshot = self.get_snapshot(base_snapshot_id)
        if snapshot is None or base_snapshot is None:
            raise PersistenceConflictError("overlay snapshot or base is outside the tenant scope")
        child_record = self.session.scalar(
            select(SnapshotRecord).where(
                SnapshotRecord.snapshot_id == snapshot_id,
                SnapshotRecord.tenant_id == self.tenant_id,
            )
        )
        if child_record is None or child_record.parent_snapshot_id != base_snapshot_id:
            raise PersistenceConflictError("summary overlay must reference its declared parent snapshot")

        incoming = {str(item["symbol_id"]): dict(item) for item in summaries}
        from ..worksets import validate_security_contract

        for symbol_id_value, data in incoming.items():
            validate_security_contract("security_summary", data)
            if data["symbol_id"] != symbol_id_value:
                raise PersistenceConflictError("summary key does not match its symbol identity")
        base = {item["symbol_id"]: item for item in self.list_effective_security_summaries(base_snapshot_id)}
        expected: dict[str, tuple[str, str | None, dict[str, Any] | None]] = {}
        for symbol_id_value, data in incoming.items():
            if base.get(symbol_id_value) != data:
                expected[symbol_id_value] = (
                    "active",
                    str(data.get("content_hash", "")),
                    data,
                )
        for symbol_id_value in set(base) - set(incoming):
            expected[symbol_id_value] = ("deleted", None, None)

        existing_rows = (
            self.session.execute(
                select(OverlaySymbolSummaryRecord).where(OverlaySymbolSummaryRecord.snapshot_id == snapshot_id)
            )
            .scalars()
            .all()
        )
        existing = {item.symbol_id: item for item in existing_rows}
        if existing and set(existing) != set(expected):
            raise PersistenceConflictError("immutable summary overlay has a conflicting delta set")

        inserted = 0
        for symbol_id_value, (state, content_hash, data) in expected.items():
            prior = existing.get(symbol_id_value)
            if prior is not None:
                if (prior.summary_state, prior.content_hash, prior.summary_data) != (
                    state,
                    content_hash,
                    data,
                ):
                    raise PersistenceConflictError("immutable summary overlay has conflicting data")
                continue
            self.session.add(
                OverlaySymbolSummaryRecord(
                    summary_record_id=stable_id("overlay-summary", snapshot_id, symbol_id_value),
                    snapshot_id=snapshot_id,
                    symbol_id=symbol_id_value,
                    summary_state=state,
                    content_hash=content_hash,
                    summary_data=data,
                )
            )
            inserted += 1
        self.session.flush()
        return inserted

    def list_effective_security_summaries(self, snapshot_id: str) -> list[dict[str, Any]]:
        """Resolve immutable base and sparse child deltas, validating tenant ownership."""
        chain: list[str] = []
        current_id: str | None = snapshot_id
        while current_id is not None:
            record = self.session.scalar(
                select(SnapshotRecord).where(
                    SnapshotRecord.snapshot_id == current_id,
                    SnapshotRecord.tenant_id == self.tenant_id,
                )
            )
            if record is None:
                raise PersistenceConflictError("snapshot does not exist in the tenant scope")
            chain.append(current_id)
            current_id = record.parent_snapshot_id

        effective: dict[str, dict[str, Any]] = {}
        for revision_id in reversed(chain):
            base_rows = self.session.execute(
                select(SymbolSummaryRecord.symbol_id, SymbolSummaryRecord.summary_data).where(
                    SymbolSummaryRecord.snapshot_id == revision_id
                )
            ).all()
            for row in base_rows:
                effective[row.symbol_id] = dict(row.summary_data)
            overlay_rows = (
                self.session.execute(
                    select(OverlaySymbolSummaryRecord).where(OverlaySymbolSummaryRecord.snapshot_id == revision_id)
                )
                .scalars()
                .all()
            )
            for row in overlay_rows:
                if row.summary_state == "deleted":
                    effective.pop(row.symbol_id, None)
                elif row.summary_data is not None:
                    effective[row.symbol_id] = dict(row.summary_data)
        return [effective[key] for key in sorted(effective)]

    def list_symbol_identities(self, snapshot_id: str) -> list[SymbolIdentity]:
        rows = self.session.execute(
            select(
                SymbolRecord.symbol_id,
                SymbolRecord.stable_key,
                SymbolRecord.content_hash,
            ).where(SymbolRecord.snapshot_id == snapshot_id)
        ).all()
        return [SymbolIdentity(row.symbol_id, row.stable_key, row.content_hash) for row in rows]

    def findings_by_dependency_keys(
        self,
        codebase_id: str,
        dependency_keys: Iterable[str],
        *,
        dependency_type: str | None = None,
    ) -> list[str]:
        keys = set(dependency_keys)
        if not keys:
            return []
        filters = [
            FindingRecord.tenant_id == self.tenant_id,
            FindingRecord.codebase_id == codebase_id,
            FindingDependencyRecord.dependency_key.in_(keys),
        ]
        if dependency_type:
            filters.append(FindingDependencyRecord.dependency_type == dependency_type)
        rows = (
            self.session.execute(
                select(FindingDependencyRecord.finding_id)
                .join(FindingRecord, FindingRecord.finding_id == FindingDependencyRecord.finding_id)
                .where(*filters)
            )
            .scalars()
            .all()
        )
        return sorted(set(rows))

    def findings_requiring_revalidation(self, codebase_id: str, snapshot_id: str, hops: int = 3) -> list[str]:
        """A finding needs re-verification once a symbol it depends on -- directly, or
        transitively through a changed callee -- has a different `content_hash` than
        the one recorded the last time the finding was saved.

        Dependencies are addressed by `stable_key` (Rule 5: identity excludes content),
        so this compares each dependency's recorded `dependency_hash` against the
        current snapshot's `content_hash` for that same stable key, then walks the
        call graph backwards from every changed symbol via `reverse_dependencies` so a
        changed callee also revalidates its callers. Findings whose dependencies are
        untouched are left alone.
        """

        symbols = self.list_symbol_identities(snapshot_id)
        content_hash_by_stable_key = {item.stable_key: item.content_hash for item in symbols}
        symbol_id_by_stable_key = {item.stable_key: item.symbol_id for item in symbols}
        stable_key_by_symbol_id = {item.symbol_id: item.stable_key for item in symbols}

        recorded = self.session.execute(
            select(
                FindingDependencyRecord.finding_id,
                FindingDependencyRecord.dependency_key,
                FindingDependencyRecord.dependency_hash,
            )
            .join(
                FindingRecord,
                FindingRecord.finding_id == FindingDependencyRecord.finding_id,
            )
            .where(
                FindingRecord.tenant_id == self.tenant_id,
                FindingRecord.codebase_id == codebase_id,
                FindingDependencyRecord.dependency_type == "symbol",
            )
        ).all()

        missing_dependency_keys = {
            dependency_key
            for _finding_id, dependency_key, _dependency_hash in recorded
            if dependency_key not in content_hash_by_stable_key
        }
        removed_dependency_findings = set(
            self.findings_by_dependency_keys(codebase_id, missing_dependency_keys)
        )
        changed_symbol_ids = {
            symbol_id_by_stable_key[dependency_key]
            for _finding_id, dependency_key, dependency_hash in recorded
            if dependency_key in content_hash_by_stable_key
            and content_hash_by_stable_key[dependency_key] != dependency_hash
        }
        if not changed_symbol_ids:
            return sorted(removed_dependency_findings)

        affected_symbol_ids = self.reverse_dependencies(snapshot_id, changed_symbol_ids, hops)
        affected_stable_keys = {
            stable_key_by_symbol_id[symbol_id]
            for symbol_id in affected_symbol_ids
            if symbol_id in stable_key_by_symbol_id
        }
        return sorted(
            removed_dependency_findings
            | set(self.findings_by_dependency_keys(codebase_id, affected_stable_keys))
        )

    def findings_requiring_graph_revalidation(
        self, codebase_id: str, graph_snapshot: Any
    ) -> list[str]:
        """Invalidate findings when any explicitly linked Graphify fact changed or disappeared."""
        from ..graphify_adapter import graph_edge_identity, graph_node_neighborhood_hash

        nodes = {node.id: node for node in graph_snapshot.nodes}
        edges = {graph_edge_identity(edge): edge for edge in graph_snapshot.edges}
        rows = self.session.execute(
            select(
                FindingDependencyRecord.finding_id,
                FindingDependencyRecord.dependency_type,
                FindingDependencyRecord.dependency_key,
                FindingDependencyRecord.dependency_hash,
            )
            .join(
                FindingRecord,
                FindingRecord.finding_id == FindingDependencyRecord.finding_id,
            )
            .where(
                FindingRecord.tenant_id == self.tenant_id,
                FindingRecord.codebase_id == codebase_id,
                FindingDependencyRecord.dependency_type.in_(
                    (
                        "source_file",
                        "graph_node",
                        "graph_node_neighborhood",
                        "graph_edge",
                        "graph_dependency_unresolved",
                    )
                ),
            )
        ).all()
        stale: set[str] = set()
        for finding_id, dependency_type, dependency_key, dependency_hash in rows:
            if dependency_type == "source_file":
                current_hash = graph_snapshot.source_hashes.get(dependency_key)
            elif dependency_type == "graph_node":
                node = nodes.get(dependency_key)
                current_hash = node.source_hash if node else None
            elif dependency_type == "graph_node_neighborhood":
                current_hash = graph_node_neighborhood_hash(graph_snapshot, dependency_key)
            elif dependency_type == "graph_edge":
                edge = edges.get(dependency_key)
                current_hash = graph_edge_identity(edge) if edge else None
            else:
                current_hash = None
            if current_hash != dependency_hash:
                stale.add(finding_id)
        return sorted(stale)

    def flag_findings_for_revalidation(self, finding_ids: Iterable[str]) -> int:
        """Demote findings back to their pre-Deep-Hunt state so they are reviewed again.

        Mirrors `models.FindingState.DISCOVERED` as a plain string rather than
        importing the domain enum, matching how `state` is already handled as a
        plain `str` throughout this repository layer.
        """

        ids = list(finding_ids)
        if not ids:
            return 0
        result = self.session.execute(
            update(FindingRecord)
            .where(
                FindingRecord.finding_id.in_(ids),
                FindingRecord.tenant_id == self.tenant_id,
            )
            .values(state="discovered")
        )
        self.session.flush()
        return int(result.rowcount)

    def count_symbols(self, snapshot_id: str) -> int:
        return int(
            self.session.scalar(
                select(func.count()).select_from(SymbolRecord).where(SymbolRecord.snapshot_id == snapshot_id)
            )
            or 0
        )

    def list_symbols(
        self,
        snapshot_id: str,
        symbol_ids: Iterable[str] | None = None,
        paths: Iterable[str] | None = None,
    ) -> list[SymbolValue]:
        """Load a bounded symbol set from one immutable tenant-owned snapshot."""

        snapshot = self.get_snapshot(snapshot_id)
        if snapshot is None:
            raise PersistenceConflictError("snapshot does not exist in the tenant scope")
        query = select(SymbolRecord).where(SymbolRecord.snapshot_id == snapshot_id)
        selected_ids = list(dict.fromkeys(symbol_ids or []))
        selected_paths = list(dict.fromkeys(paths or []))
        if selected_ids:
            query = query.where(SymbolRecord.symbol_id.in_(selected_ids))
        if selected_paths:
            query = query.where(SymbolRecord.path.in_(selected_paths))
        rows = (
            self.session.execute(query.order_by(SymbolRecord.path, SymbolRecord.start_line, SymbolRecord.symbol_id))
            .scalars()
            .all()
        )
        return [
            SymbolValue(
                symbol_id=row.symbol_id,
                stable_key=row.stable_key,
                qualified_name=row.qualified_name,
                kind=row.kind,
                path=row.path,
                start_line=row.start_line,
                end_line=row.end_line,
                content_hash=row.content_hash,
                content=row.content,
            )
            for row in rows
        ]

    def reverse_dependencies(self, snapshot_id: str, changed_symbol_ids: Iterable[str], hops: int = 3) -> list[str]:
        """Walk call edges backwards so a changed callee revalidates its callers."""

        affected = set(changed_symbol_ids)
        frontier = set(affected)
        for _ in range(hops):
            if not frontier:
                break
            rows = (
                self.session.execute(
                    select(CodeEdgeRecord.source_symbol_id).where(
                        CodeEdgeRecord.snapshot_id == snapshot_id,
                        CodeEdgeRecord.target_symbol_id.in_(frontier),
                    )
                )
                .scalars()
                .all()
            )
            frontier = set(rows) - affected
            affected.update(frontier)
        return sorted(affected)

    def upsert_security_memory(
        self,
        memory_id: str,
        codebase_id: str | None,
        scope: str,
        category: str,
        statement: str,
        provenance: str,
        status: str = "active",
    ) -> SecurityMemoryValue:
        if codebase_id is not None and self.get_codebase(codebase_id) is None:
            raise PersistenceConflictError("memory codebase does not exist in the tenant scope")
        record = self.session.scalar(
            select(SecurityMemoryRecord).where(
                SecurityMemoryRecord.memory_id == memory_id,
                SecurityMemoryRecord.tenant_id == self.tenant_id,
            )
        )
        if record is None:
            record = SecurityMemoryRecord(
                memory_id=memory_id,
                tenant_id=self.tenant_id,
                codebase_id=codebase_id,
                scope=scope,
                category=category,
                statement=statement,
                provenance=provenance,
                status=status,
                version=1,
            )
            self.session.add(record)
        else:
            changed = (
                record.codebase_id != codebase_id
                or record.scope != scope
                or record.category != category
                or record.statement != statement
                or record.provenance != provenance
                or record.status != status
            )
            record.codebase_id = codebase_id
            record.scope = scope
            record.category = category
            record.statement = statement
            record.provenance = provenance
            record.status = status
            if changed:
                record.version += 1
        self.session.flush()
        return _security_memory_value(record)

    def active_security_memories(
        self,
        codebase_id: str,
        category: str,
    ) -> list[SecurityMemoryValue]:
        rows = (
            self.session.execute(
                select(SecurityMemoryRecord)
                .where(
                    SecurityMemoryRecord.tenant_id == self.tenant_id,
                    SecurityMemoryRecord.status == "active",
                    or_(
                        SecurityMemoryRecord.codebase_id == codebase_id,
                        SecurityMemoryRecord.codebase_id.is_(None),
                    ),
                    or_(
                        SecurityMemoryRecord.category == category,
                        SecurityMemoryRecord.category == "all",
                    ),
                )
                .order_by(SecurityMemoryRecord.memory_id)
            )
            .scalars()
            .all()
        )
        return [_security_memory_value(row) for row in rows]

    def link_finding_symbols(
        self,
        codebase_id: str,
        fingerprint: str,
        snapshot_id: str,
        symbol_ids: Iterable[str],
    ) -> None:
        finding = self.session.scalar(
            select(FindingRecord).where(
                FindingRecord.tenant_id == self.tenant_id,
                FindingRecord.codebase_id == codebase_id,
                FindingRecord.fingerprint == fingerprint,
            )
        )
        if finding is None:
            raise PersistenceConflictError("finding does not exist in the tenant scope")
        known = {item.symbol_id: item for item in self.list_symbols(snapshot_id, symbol_ids=symbol_ids)}
        for symbol_id in dict.fromkeys(symbol_ids):
            symbol = known.get(symbol_id)
            if symbol is None:
                continue
            dependency_key = symbol.stable_key
            existing = self.session.scalar(
                select(FindingDependencyRecord).where(
                    FindingDependencyRecord.finding_id == finding.finding_id,
                    FindingDependencyRecord.dependency_type == "symbol",
                    FindingDependencyRecord.dependency_key == dependency_key,
                )
            )
            if existing is None:
                self.session.add(
                    FindingDependencyRecord(
                        finding_dependency_id=f"dep-{_hash(finding.finding_id, 'symbol', dependency_key)}",
                        finding_id=finding.finding_id,
                        dependency_type="symbol",
                        dependency_key=dependency_key,
                        dependency_hash=symbol.content_hash,
                    )
                )
            else:
                existing.dependency_hash = symbol.content_hash
        self.session.flush()

    def prior_findings_for_symbols(
        self,
        codebase_id: str,
        snapshot_id: str,
        symbol_ids: Iterable[str],
    ) -> list[str]:
        symbols = self.list_symbols(snapshot_id, symbol_ids=symbol_ids)
        keys = [item.stable_key for item in symbols]
        if not keys:
            return []
        rows = (
            self.session.execute(
                select(FindingRecord.fingerprint)
                .join(
                    FindingDependencyRecord,
                    FindingDependencyRecord.finding_id == FindingRecord.finding_id,
                )
                .where(
                    FindingRecord.tenant_id == self.tenant_id,
                    FindingRecord.codebase_id == codebase_id,
                    FindingDependencyRecord.dependency_type == "symbol",
                    FindingDependencyRecord.dependency_key.in_(keys),
                )
                .distinct()
                .order_by(FindingRecord.fingerprint)
            )
            .scalars()
            .all()
        )
        return list(rows)

    def create_hunt_plan(
        self,
        plan_id: str,
        scan_id: str,
        strategy: str,
        context_hash: str,
        workflow_version: str,
    ) -> HuntPlanValue:
        existing = self.session.scalar(
            select(HuntPlanRecord).where(
                HuntPlanRecord.scan_id == scan_id,
                HuntPlanRecord.context_hash == context_hash,
            )
        )
        if existing:
            return _hunt_plan_value(existing)
        record = HuntPlanRecord(
            plan_id=plan_id,
            scan_id=scan_id,
            strategy=strategy,
            context_hash=context_hash,
            workflow_version=workflow_version,
        )
        self.session.add(record)
        self.session.flush()
        return _hunt_plan_value(record)

    def create_hunt_tasks(self, plan_id: str, tasks: Iterable[HuntTaskInput]) -> list[HuntTaskValue]:
        values: list[HuntTaskValue] = []
        for item in tasks:
            existing = self.session.scalar(
                select(HuntTaskRecord).where(
                    HuntTaskRecord.plan_id == plan_id,
                    HuntTaskRecord.task_key == item.task_key,
                )
            )
            if existing:
                values.append(_hunt_task_value(existing))
                continue
            record = HuntTaskRecord(
                task_id=f"task-{_hash(plan_id, item.task_key)}",
                plan_id=plan_id,
                task_key=item.task_key,
                title=item.title,
                objective=item.objective,
                task_data=item.task_data,
                state="planned",
                attempt_count=0,
            )
            self.session.add(record)
            self.session.flush()
            values.append(_hunt_task_value(record))
        return values

    def get_hunt_plan(self, plan_id: str) -> HuntPlanValue | None:
        record = self.session.get(HuntPlanRecord, plan_id)
        return _hunt_plan_value(record) if record else None

    def ensure_hunt_plan(
        self,
        plan_id: str,
        scan_id: str,
        workflow_version: str,
        strategy: str | None = None,
    ) -> HuntPlanValue:
        """Get-or-create a plan cache row; fills in `strategy` once it is known."""

        record = self.session.get(HuntPlanRecord, plan_id)
        if record is None:
            record = HuntPlanRecord(
                plan_id=plan_id,
                scan_id=scan_id,
                strategy=strategy or "",
                context_hash=f"pending-{plan_id}",
                workflow_version=workflow_version,
            )
            self.session.add(record)
            self.session.flush()
            return _hunt_plan_value(record)
        if strategy is not None and record.strategy != strategy:
            record.strategy = strategy
            self.session.flush()
        return _hunt_plan_value(record)

    def upsert_hunt_task(
        self,
        plan_id: str,
        task_key: str,
        title: str,
        objective: str,
        task_data: dict[str, Any],
    ) -> HuntTaskValue:
        """Get-or-create a task row, overwriting `title`/`objective`/`task_data` in place.

        Leasing state (`state`, `attempt_count`, `lease_owner`, `lease_expires_at`) is
        left untouched so this is safe to call again once knowledge resolution fills
        in a task's final `task_data`.
        """

        record = self.session.scalar(
            select(HuntTaskRecord).where(
                HuntTaskRecord.plan_id == plan_id,
                HuntTaskRecord.task_key == task_key,
            )
        )
        if record is None:
            record = HuntTaskRecord(
                task_id=f"task-{_hash(plan_id, task_key)}",
                plan_id=plan_id,
                task_key=task_key,
                title=title,
                objective=objective,
                task_data=task_data,
                state="planned",
                attempt_count=0,
            )
            self.session.add(record)
        else:
            record.title = title
            record.objective = objective
            record.task_data = task_data
        self.session.flush()
        return _hunt_task_value(record)

    def list_hunt_tasks(self, plan_id: str) -> list[HuntTaskValue]:
        rows = (
            self.session.execute(
                select(HuntTaskRecord).where(HuntTaskRecord.plan_id == plan_id).order_by(HuntTaskRecord.created_at)
            )
            .scalars()
            .all()
        )
        return [_hunt_task_value(row) for row in rows]

    def save_investigation(self, scan_id: str, value: Investigation) -> InvestigationValue:
        """Persist an immutable investigation identity/evidence version idempotently."""
        if not isinstance(value, Investigation):
            raise TypeError("value must be an Investigation")
        validate_investigation(value)
        scan = self.session.scalar(
            select(ScanRunRecord).where(
                ScanRunRecord.scan_id == scan_id,
                ScanRunRecord.tenant_id == self.tenant_id,
            )
        )
        if scan is None or scan.codebase_id != value.codebase_id or scan.snapshot_id != value.snapshot_id:
            raise PersistenceConflictError("investigation scan/snapshot is outside the tenant scope")
        identity = select(InvestigationRecord).where(
            InvestigationRecord.tenant_id == self.tenant_id,
            InvestigationRecord.scan_id == scan_id,
            InvestigationRecord.stable_key == value.stable_key,
            InvestigationRecord.evidence_hash == value.evidence_hash,
        )
        existing = self.session.scalar(identity)
        if existing is not None:
            if existing.investigation_data != value.payload():
                raise PersistenceConflictError("investigation evidence identity has conflicting content")
            return _investigation_value(existing)
        shared_identity = self.session.scalar(
            select(InvestigationRecord).where(
                InvestigationRecord.investigation_id == value.investigation_id,
                InvestigationRecord.tenant_id == self.tenant_id,
            )
        )
        if shared_identity is not None:
            stored_payload = dict(shared_identity.investigation_data)
            incoming_payload = value.payload()
            for lifecycle_field in ("state", "revision", "checkpoint_ref"):
                stored_payload.pop(lifecycle_field, None)
                incoming_payload.pop(lifecycle_field, None)
            if (
                shared_identity.codebase_id != value.codebase_id
                or shared_identity.snapshot_id != value.snapshot_id
                or shared_identity.stable_key != value.stable_key
                or shared_identity.evidence_hash != value.evidence_hash
                or stored_payload != incoming_payload
            ):
                raise PersistenceConflictError(
                    "investigation identity conflicts with an immutable prior record"
                )
            return _investigation_value(shared_identity)
        record = InvestigationRecord(
            investigation_id=value.investigation_id,
            tenant_id=self.tenant_id,
            scan_id=scan_id,
            codebase_id=value.codebase_id,
            snapshot_id=value.snapshot_id,
            stable_key=value.stable_key,
            evidence_hash=value.evidence_hash,
            investigation_data=value.payload(),
            state=value.state,
            checkpoint_ref=value.checkpoint_ref,
            revision=value.revision,
            attempt_count=0,
        )
        self.session.add(record)
        self.session.flush()
        return _investigation_value(record)

    def transition_investigation(
        self,
        investigation_id: str,
        new_state: str,
        *,
        expected_revision: int,
        checkpoint_ref: str | None = None,
    ) -> InvestigationValue:
        """Compare-and-swap lifecycle update; transitions are configured as runtime data."""
        record = self.session.scalar(
            select(InvestigationRecord).where(
                InvestigationRecord.investigation_id == investigation_id,
                InvestigationRecord.tenant_id == self.tenant_id,
            )
        )
        if record is None:
            raise PersistenceConflictError("investigation does not exist in the tenant scope")
        if record.revision != expected_revision:
            raise PersistenceConflictError("investigation revision changed during update")
        transitions = load_json("runtime/investigation_states.json")["transitions"]
        if new_state not in transitions.get(record.state, []):
            raise PersistenceConflictError(f"invalid investigation transition: {record.state} -> {new_state}")
        next_revision = record.revision + 1
        next_checkpoint = checkpoint_ref if checkpoint_ref is not None else record.checkpoint_ref
        data = dict(record.investigation_data)
        data.update(state=new_state, revision=next_revision, checkpoint_ref=next_checkpoint)
        result = self.session.execute(
            update(InvestigationRecord)
            .where(
                InvestigationRecord.investigation_id == investigation_id,
                InvestigationRecord.tenant_id == self.tenant_id,
                InvestigationRecord.revision == expected_revision,
                InvestigationRecord.state == record.state,
            )
            .values(
                state=new_state,
                revision=next_revision,
                attempt_count=InvestigationRecord.attempt_count + int(new_state == "running"),
                checkpoint_ref=next_checkpoint,
                investigation_data=data,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            raise PersistenceConflictError("investigation revision changed during update")
        self.session.expire(record)
        return _investigation_value(record)

    def list_investigations(self, scan_id: str) -> list[InvestigationValue]:
        rows = self.session.scalars(
            select(InvestigationRecord)
            .where(
                InvestigationRecord.tenant_id == self.tenant_id,
                InvestigationRecord.scan_id == scan_id,
            )
            .order_by(InvestigationRecord.created_at, InvestigationRecord.investigation_id)
        ).all()
        return [_investigation_value(row) for row in rows]

    def list_investigations_for_snapshot(
        self, codebase_id: str, snapshot_id: str
    ) -> list[InvestigationValue]:
        """Load immutable investigation identities attached to a codebase snapshot."""
        rows = self.session.scalars(
            select(InvestigationRecord)
            .where(
                InvestigationRecord.tenant_id == self.tenant_id,
                InvestigationRecord.codebase_id == codebase_id,
                InvestigationRecord.snapshot_id == snapshot_id,
            )
            .order_by(InvestigationRecord.created_at, InvestigationRecord.investigation_id)
        ).all()
        return [_investigation_value(row) for row in rows]

    def list_investigations_for_codebase(
        self, codebase_id: str
    ) -> list[InvestigationValue]:
        """List this tenant's prior investigations newest-first for safe rebase lookup."""
        rows = self.session.scalars(
            select(InvestigationRecord)
            .where(
                InvestigationRecord.tenant_id == self.tenant_id,
                InvestigationRecord.codebase_id == codebase_id,
            )
            .order_by(
                InvestigationRecord.created_at.desc(),
                InvestigationRecord.investigation_id,
            )
        ).all()
        return [_investigation_value(row) for row in rows]

    def list_reusable_no_candidate_investigations(
        self, codebase_id: str, workflow_version: str
    ) -> list[InvestigationValue]:
        """Load terminal negative investigations from successful, same-workflow scans."""
        rows = self.session.scalars(
            select(InvestigationRecord)
            .join(ScanRunRecord, ScanRunRecord.scan_id == InvestigationRecord.scan_id)
            .where(
                InvestigationRecord.tenant_id == self.tenant_id,
                InvestigationRecord.codebase_id == codebase_id,
                InvestigationRecord.state == "no_candidate",
                ScanRunRecord.tenant_id == self.tenant_id,
                ScanRunRecord.workflow_version == workflow_version,
                ScanRunRecord.scan_status == "SUCCESSFUL",
            )
            .order_by(InvestigationRecord.created_at.desc())
        ).all()
        return [_investigation_value(row) for row in rows]

    def save_graphify_snapshot(
        self, scan_id: str, snapshot_id: str, graph_snapshot: Any
    ) -> GraphifySnapshotValue:
        """Persist one immutable Graphify graph, rejecting conflicting scan retries."""
        from ..graphify_adapter import CodeGraphSnapshot, graph_edge_identity

        if not isinstance(graph_snapshot, CodeGraphSnapshot):
            raise TypeError("graph_snapshot must be a CodeGraphSnapshot")
        scan = self.session.scalar(
            select(ScanRunRecord).where(
                ScanRunRecord.scan_id == scan_id,
                ScanRunRecord.tenant_id == self.tenant_id,
            )
        )
        if scan is None or scan.snapshot_id != snapshot_id:
            raise PersistenceConflictError("Graphify snapshot is outside the tenant scan scope")
        existing = self.session.scalar(
            select(GraphifySnapshotRecord).where(
                GraphifySnapshotRecord.scan_id == scan_id,
                GraphifySnapshotRecord.tenant_id == self.tenant_id,
            )
        )
        if existing is not None:
            value = self.get_graphify_snapshot(existing.graphify_record_id)
            if value is None or value.graph_snapshot != graph_snapshot:
                raise PersistenceConflictError("Graphify snapshot changed during scan resume")
            return value

        graphify_record_id = stable_id(
            "graphify", scan_id, graph_snapshot.snapshot_id
        )
        record = GraphifySnapshotRecord(
            graphify_record_id=graphify_record_id,
            tenant_id=self.tenant_id,
            codebase_id=scan.codebase_id,
            scan_id=scan_id,
            snapshot_id=snapshot_id,
            graph_snapshot_id=graph_snapshot.snapshot_id,
            extractor_version=graph_snapshot.extractor_version,
            source_hashes=dict(graph_snapshot.source_hashes),
            unresolved_edges=graph_snapshot.unresolved_edges,
            unindexed_files=list(graph_snapshot.unindexed_files),
        )
        self.session.add(record)
        self.session.add_all(
            GraphifyNodeRecord(
                graphify_record_id=graphify_record_id,
                node_id=node.id,
                path=node.path,
                line=node.line,
                label=node.label,
                source_hash=node.source_hash,
            )
            for node in graph_snapshot.nodes
        )
        self.session.add_all(
            GraphifyEdgeRecord(
                graphify_record_id=graphify_record_id,
                edge_id=graph_edge_identity(edge),
                source_id=edge.source_id,
                target_id=edge.target_id,
                relation=edge.relation,
                provenance=edge.provenance,
                path=edge.path,
                line=edge.line,
                source_hash=edge.source_hash,
            )
            for edge in graph_snapshot.edges
        )
        self.session.flush()
        value = self.get_graphify_snapshot(graphify_record_id)
        if value is None:
            raise PersistenceConflictError("saved Graphify snapshot could not be read back")
        return value

    def get_graphify_snapshot(self, graphify_record_id: str) -> GraphifySnapshotValue | None:
        from ..graphify_adapter import CodeEdge, CodeGraphSnapshot, CodeNode

        record = self.session.scalar(
            select(GraphifySnapshotRecord).where(
                GraphifySnapshotRecord.graphify_record_id == graphify_record_id,
                GraphifySnapshotRecord.tenant_id == self.tenant_id,
            )
        )
        if record is None:
            return None
        nodes = self.session.scalars(
            select(GraphifyNodeRecord)
            .where(GraphifyNodeRecord.graphify_record_id == graphify_record_id)
            .order_by(GraphifyNodeRecord.node_id)
        ).all()
        edges = self.session.scalars(
            select(GraphifyEdgeRecord)
            .where(GraphifyEdgeRecord.graphify_record_id == graphify_record_id)
            .order_by(GraphifyEdgeRecord.edge_id)
        ).all()
        graph_snapshot = CodeGraphSnapshot(
            source_hashes=dict(record.source_hashes),
            nodes=tuple(
                CodeNode(row.node_id, row.path, row.line, row.label, row.source_hash)
                for row in nodes
            ),
            edges=tuple(
                CodeEdge(
                    row.source_id,
                    row.target_id,
                    row.relation,
                    row.provenance,
                    row.path,
                    row.line,
                    row.source_hash,
                )
                for row in edges
            ),
            unresolved_edges=record.unresolved_edges,
            unindexed_files=tuple(record.unindexed_files),
            extractor_version=record.extractor_version,
        )
        if graph_snapshot.snapshot_id != record.graph_snapshot_id:
            raise PersistenceConflictError("persisted Graphify snapshot identity is inconsistent")
        return GraphifySnapshotValue(
            graphify_record_id=record.graphify_record_id,
            tenant_id=record.tenant_id,
            codebase_id=record.codebase_id,
            scan_id=record.scan_id,
            snapshot_id=record.snapshot_id,
            graph_snapshot=graph_snapshot,
        )

    def latest_graphify_snapshot(
        self, codebase_id: str, *, excluding_scan_id: str | None = None
    ) -> GraphifySnapshotValue | None:
        query = (
            select(GraphifySnapshotRecord)
            .join(ScanRunRecord, ScanRunRecord.scan_id == GraphifySnapshotRecord.scan_id)
            .where(
                GraphifySnapshotRecord.tenant_id == self.tenant_id,
                GraphifySnapshotRecord.codebase_id == codebase_id,
            )
            .order_by(
                func.coalesce(
                    ScanRunRecord.finished_at, ScanRunRecord.created_at
                ).desc(),
                GraphifySnapshotRecord.created_at.desc(),
                ScanRunRecord.scan_id.desc(),
            )
        )
        if excluding_scan_id is not None:
            query = query.where(GraphifySnapshotRecord.scan_id != excluding_scan_id)
        record = self.session.scalars(query.limit(1)).first()
        return self.get_graphify_snapshot(record.graphify_record_id) if record else None

    def save_surface_planning(
        self, scan_id: str, snapshot_id: str, planning_data: dict[str, Any]
    ) -> SurfacePlanningValue:
        """Persist the immutable surface mapping/grouping ledger before AI planning."""
        scan = self.session.scalar(
            select(ScanRunRecord).where(
                ScanRunRecord.scan_id == scan_id,
                ScanRunRecord.tenant_id == self.tenant_id,
            )
        )
        if scan is None or scan.snapshot_id != snapshot_id:
            raise PersistenceConflictError(
                "surface planning scan/snapshot is outside the tenant scope"
            )
        existing = self.session.scalar(
            select(SurfacePlanningRecord).where(
                SurfacePlanningRecord.scan_id == scan_id,
                SurfacePlanningRecord.tenant_id == self.tenant_id,
            )
        )
        if existing is not None:
            if existing.snapshot_id != snapshot_id or _surface_plan_identity(
                existing.planning_data
            ) != _surface_plan_identity(planning_data):
                raise PersistenceConflictError(
                    "surface planning identity has conflicting snapshot or coverage data"
                )
            return _surface_planning_value(existing)
        record = SurfacePlanningRecord(
            scan_id=scan_id,
            tenant_id=self.tenant_id,
            snapshot_id=snapshot_id,
            state="planning",
            revision=1,
            planning_data=planning_data,
        )
        self.session.add(record)
        self.session.flush()
        return _surface_planning_value(record)

    def record_surface_planning_group(
        self,
        scan_id: str,
        snapshot_id: str,
        group_id: str,
        status: str,
        investigation_id: str | None = None,
    ) -> SurfacePlanningValue:
        """Persist one group's planning state without changing its coverage identity."""
        record = self.session.scalar(
            select(SurfacePlanningRecord).where(
                SurfacePlanningRecord.scan_id == scan_id,
                SurfacePlanningRecord.tenant_id == self.tenant_id,
            )
        )
        if record is None or record.snapshot_id != snapshot_id:
            raise PersistenceConflictError(
                "surface planning record does not exist for this tenant snapshot"
            )
        planning_data = dict(record.planning_data)
        groups = [dict(item) for item in planning_data.get("groups", [])]
        selected = next((item for item in groups if item.get("group_id") == group_id), None)
        if selected is None:
            raise PersistenceConflictError("surface planning group is not in the stored ledger")
        allowed_statuses = {"pending", "planning", "planned", "reused", "failed", "gap"}
        if status not in allowed_statuses:
            raise PersistenceConflictError("surface planning group status is invalid")
        current_status = str(selected.get("planning_status", "pending"))
        if current_status == "eligible_for_planning":
            current_status = "pending"
        allowed_transitions = {
            "pending": {"planning", "reused", "gap"},
            "planning": {"planning", "planned", "failed"},
            "failed": {"planning", "failed"},
            "planned": {"planned", "reused", "planning"},
            "reused": {"reused", "planning"},
            "gap": {"gap"},
        }
        if status not in allowed_transitions.get(current_status, set()):
            raise PersistenceConflictError(
                f"surface planning group cannot transition from {current_status} to {status}"
            )
        if status == current_status and selected.get("investigation_id") == investigation_id:
            return _surface_planning_value(record)
        selected["planning_status"] = status
        if investigation_id is not None:
            selected["investigation_id"] = investigation_id
        planning_data["groups"] = groups
        record.planning_data = planning_data
        record.revision += 1
        self.session.flush()
        return _surface_planning_value(record)

    def complete_surface_planning(
        self, scan_id: str, snapshot_id: str
    ) -> SurfacePlanningValue:
        """Mark the persisted grouping ledger complete after every bounded unit resolves."""
        record = self.session.scalar(
            select(SurfacePlanningRecord).where(
                SurfacePlanningRecord.scan_id == scan_id,
                SurfacePlanningRecord.tenant_id == self.tenant_id,
            )
        )
        if record is None or record.snapshot_id != snapshot_id:
            raise PersistenceConflictError(
                "surface planning record does not exist for this tenant snapshot"
            )
        nonterminal_groups = [
            str(group.get("group_id", ""))
            for group in record.planning_data.get("groups", [])
            if group.get("planning_status") not in {"planned", "reused", "gap"}
        ]
        if nonterminal_groups:
            raise PersistenceConflictError(
                "surface planning cannot complete while groups remain unresolved"
            )
        if record.state == "planning":
            record.state = "complete"
            record.revision += 1
            self.session.flush()
        return _surface_planning_value(record)

    def get_surface_planning(self, scan_id: str) -> SurfacePlanningValue | None:
        record = self.session.scalar(
            select(SurfacePlanningRecord).where(
                SurfacePlanningRecord.scan_id == scan_id,
                SurfacePlanningRecord.tenant_id == self.tenant_id,
            )
        )
        return _surface_planning_value(record) if record is not None else None

    def lease_next_task(
        self,
        plan_id: str,
        worker_id: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> HuntTaskValue | None:
        """Compare-and-swap lease: portable across PostgreSQL and the SQLite test adapter."""

        if not worker_id.strip():
            raise ValueError("worker_id is required")
        moment = now or datetime.now(UTC)
        considered: set[str] = set()
        while True:
            filters = [
                HuntTaskRecord.plan_id == plan_id,
                HuntTaskRecord.state.in_(("planned", "leased")),
                or_(
                    HuntTaskRecord.lease_expires_at.is_(None),
                    HuntTaskRecord.lease_expires_at <= moment,
                ),
            ]
            if considered:
                filters.append(HuntTaskRecord.task_id.not_in(considered))
            candidate_id = self.session.scalar(
                select(HuntTaskRecord.task_id).where(*filters).order_by(HuntTaskRecord.created_at).limit(1)
            )
            if candidate_id is None:
                return None
            considered.add(candidate_id)
            result = self.session.execute(
                update(HuntTaskRecord)
                .where(
                    HuntTaskRecord.task_id == candidate_id,
                    HuntTaskRecord.state.in_(("planned", "leased")),
                    or_(
                        HuntTaskRecord.lease_expires_at.is_(None),
                        HuntTaskRecord.lease_expires_at <= moment,
                    ),
                )
                .values(
                    state="leased",
                    lease_owner=worker_id,
                    lease_expires_at=moment + timedelta(seconds=lease_seconds),
                    attempt_count=HuntTaskRecord.attempt_count + 1,
                )
            )
            if result.rowcount == 1:
                self.session.flush()
                return _hunt_task_value(self.session.get(HuntTaskRecord, candidate_id))
            # Lost the race to another worker; retry against the next eligible candidate.

    def complete_task(self, task_id: str, worker_id: str) -> bool:
        """Idempotent: returns False if already completed or leased by someone else."""

        result = self.session.execute(
            update(HuntTaskRecord)
            .where(
                HuntTaskRecord.task_id == task_id,
                HuntTaskRecord.lease_owner == worker_id,
                HuntTaskRecord.state == "leased",
            )
            .values(state="completed", lease_owner=None, lease_expires_at=None)
        )
        self.session.flush()
        return result.rowcount == 1

    def release_task(self, task_id: str, worker_id: str) -> bool:
        """Return a leased task to the pool so another worker can retry it."""

        result = self.session.execute(
            update(HuntTaskRecord)
            .where(
                HuntTaskRecord.task_id == task_id,
                HuntTaskRecord.lease_owner == worker_id,
                HuntTaskRecord.state == "leased",
            )
            .values(state="planned", lease_owner=None, lease_expires_at=None)
        )
        self.session.flush()
        return result.rowcount == 1

    def save_finding(
        self,
        finding_id: str,
        codebase_id: str,
        scan_id: str,
        fingerprint: str,
        title: str,
        vulnerability_class: str,
        severity: str,
        state: str,
        confidence: float,
        summary: str,
        impact: str,
        remediation: str,
        validation: dict[str, Any],
        evidence: Iterable[FindingEvidenceInput],
        dependencies: Iterable[FindingDependencyInput],
    ) -> FindingValue:
        """Upsert by (codebase_id, fingerprint) so re-verification updates in place."""

        record = self.session.scalar(
            select(FindingRecord).where(
                FindingRecord.tenant_id == self.tenant_id,
                FindingRecord.codebase_id == codebase_id,
                FindingRecord.fingerprint == fingerprint,
            )
        )
        if record is None:
            record = FindingRecord(
                finding_id=finding_id,
                tenant_id=self.tenant_id,
                codebase_id=codebase_id,
                scan_id=scan_id,
                fingerprint=fingerprint,
                title=redact_payload(title),
                vulnerability_class=vulnerability_class,
                severity=severity,
                state=state,
                confidence=confidence,
                summary=redact_payload(summary),
                impact=redact_payload(impact),
                remediation=redact_payload(remediation),
                validation=redact_payload(validation),
            )
            self.session.add(record)
        else:
            record.scan_id = scan_id
            record.title = redact_payload(title)
            record.vulnerability_class = vulnerability_class
            record.severity = severity
            record.state = state
            record.confidence = confidence
            record.summary = redact_payload(summary)
            record.impact = redact_payload(impact)
            record.remediation = redact_payload(remediation)
            record.validation = redact_payload(validation)
        self.session.flush()

        self.session.execute(delete(FindingEvidenceRecord).where(FindingEvidenceRecord.finding_id == record.finding_id))
        self.session.execute(
            delete(FindingDependencyRecord).where(FindingDependencyRecord.finding_id == record.finding_id)
        )
        for sequence, item in enumerate(evidence):
            safe_content = str(redact_payload(item.redacted_content))
            self.session.add(
                FindingEvidenceRecord(
                    evidence_id=f"ev-{_hash(record.finding_id, str(sequence))}",
                    finding_id=record.finding_id,
                    sequence=sequence,
                    evidence_type=item.evidence_type,
                    path=item.path,
                    start_line=item.start_line,
                    end_line=item.end_line,
                    redacted_content=safe_content,
                    content_hash=hashlib.sha256(safe_content.encode("utf-8")).hexdigest(),
                    provenance=item.provenance,
                )
            )
        for item in dependencies:
            self.session.add(
                FindingDependencyRecord(
                    finding_dependency_id=f"dep-{_hash(record.finding_id, item.dependency_type, item.dependency_key)}",
                    finding_id=record.finding_id,
                    dependency_type=item.dependency_type,
                    dependency_key=item.dependency_key,
                    dependency_hash=item.dependency_hash,
                )
            )
        self.session.flush()
        found = self.get_finding(record.finding_id)
        assert found is not None
        return found

    def get_finding(self, finding_id: str) -> FindingValue | None:
        record = self.session.scalar(
            select(FindingRecord).where(
                FindingRecord.finding_id == finding_id,
                FindingRecord.tenant_id == self.tenant_id,
            )
        )
        if record is None:
            return None
        evidence_rows = (
            self.session.execute(
                select(FindingEvidenceRecord)
                .where(FindingEvidenceRecord.finding_id == finding_id)
                .order_by(FindingEvidenceRecord.sequence)
            )
            .scalars()
            .all()
        )
        dependency_rows = (
            self.session.execute(
                select(FindingDependencyRecord).where(FindingDependencyRecord.finding_id == finding_id)
            )
            .scalars()
            .all()
        )
        return FindingValue(
            finding_id=record.finding_id,
            tenant_id=record.tenant_id,
            codebase_id=record.codebase_id,
            scan_id=record.scan_id,
            fingerprint=record.fingerprint,
            title=record.title,
            vulnerability_class=record.vulnerability_class,
            severity=record.severity,
            state=record.state,
            confidence=record.confidence,
            summary=record.summary,
            impact=record.impact,
            remediation=record.remediation,
            validation=record.validation,
            evidence=[
                FindingEvidenceValue(
                    evidence_type=row.evidence_type,
                    path=row.path,
                    start_line=row.start_line,
                    end_line=row.end_line,
                    redacted_content=row.redacted_content,
                    content_hash=row.content_hash,
                    provenance=row.provenance,
                    evidence_id=row.evidence_id,
                    sequence=row.sequence,
                )
                for row in evidence_rows
            ],
            dependencies=[
                FindingDependencyValue(
                    dependency_type=row.dependency_type,
                    dependency_key=row.dependency_key,
                    dependency_hash=row.dependency_hash,
                    finding_dependency_id=row.finding_dependency_id,
                )
                for row in dependency_rows
            ],
        )

    def upsert_knowledge(self, item: KnowledgeInput) -> KnowledgeValue:
        """Content-addressed insert: identical content always resolves to the same row."""

        record = self.session.scalar(
            select(SecurityKnowledgeRecord).where(
                SecurityKnowledgeRecord.tenant_id == self.tenant_id,
                SecurityKnowledgeRecord.content_hash == item.content_hash,
            )
        )
        if record is not None:
            return _knowledge_value(record)
        record = SecurityKnowledgeRecord(
            knowledge_id=item.knowledge_id,
            tenant_id=self.tenant_id,
            topic=item.topic,
            vulnerability_class=item.vulnerability_class,
            ecosystem=item.ecosystem,
            framework=item.framework,
            content=item.content,
            source_url=item.source_url,
            source_title=item.source_title,
            source_updated_at=item.source_updated_at,
            provenance=item.provenance,
            confidence=item.confidence,
            content_hash=item.content_hash,
            claims=item.claims,
            status="active",
        )
        self.session.add(record)
        self.session.flush()
        return _knowledge_value(record)

    def search_knowledge(self, query: str, limit: int) -> list[KnowledgeValue]:
        runtime = load_json("runtime/agent.json")
        minimum_length = int(runtime["knowledge_search_min_token_characters"])
        stop_words = {str(item).lower() for item in runtime["knowledge_search_stop_words"]}
        tokens = [
            token
            for token in re.findall(r"[a-zA-Z0-9_.+-]+", query.lower())
            if len(token) >= minimum_length and token not in stop_words
        ]
        search_values = [value for value in dict.fromkeys([query.strip(), *tokens]) if value]

        rows_by_id: dict[str, SecurityKnowledgeRecord] = {}
        matches: dict[str, int] = {}
        for value in search_values:
            term = f"%{value}%"
            rows = (
                self.session.execute(
                    select(SecurityKnowledgeRecord).where(
                        SecurityKnowledgeRecord.tenant_id == self.tenant_id,
                        SecurityKnowledgeRecord.status == "active",
                        or_(
                            SecurityKnowledgeRecord.topic.ilike(term),
                            SecurityKnowledgeRecord.content.ilike(term),
                            SecurityKnowledgeRecord.vulnerability_class.ilike(term),
                            SecurityKnowledgeRecord.ecosystem.ilike(term),
                            SecurityKnowledgeRecord.framework.ilike(term),
                        ),
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                rows_by_id[row.knowledge_id] = row
                matches[row.knowledge_id] = matches.get(row.knowledge_id, 0) + 1

        ranked = sorted(
            rows_by_id.values(),
            key=lambda row: (-matches[row.knowledge_id], -row.confidence, row.topic),
        )
        return [_knowledge_value(row) for row in ranked[:limit]]

    def record_knowledge_usage(
        self,
        usage_id: str,
        scan_id: str,
        task_id: str,
        knowledge_id: str | None,
        query: str,
        decision: str,
        decision_confidence: float,
        reason: str,
    ) -> None:
        record = self.session.get(KnowledgeUsageRecord, usage_id)
        if record is None:
            record = KnowledgeUsageRecord(
                usage_id=usage_id,
                scan_id=scan_id,
                task_id=task_id,
                knowledge_id=knowledge_id,
                query=query,
                decision=decision,
                decision_confidence=decision_confidence,
                reason=reason,
            )
            self.session.add(record)
        else:
            if record.scan_id != scan_id or record.task_id != task_id:
                raise PersistenceConflictError("usage_id already identifies another hunt task")
            record.knowledge_id = knowledge_id
            record.query = query
            record.decision = decision
            record.decision_confidence = decision_confidence
            record.reason = reason
        self.session.flush()


def security_ir_inputs(
    root: Path, graph: StructuralGraph
) -> tuple[list[SourceFileInput], list[SymbolInput], list[EdgeInput]]:
    """Adapt a Tree-sitter Security IR graph into ORM-ready, stable-identity records.

    Symbol identity excludes content: ordinary symbols use path, kind, and
    qualified name. Only true overloads add a normalized signature digest and
    occurrence, so body and line changes preserve identity.
    """

    source_files: list[SourceFileInput] = []
    symbol_inputs: list[SymbolInput] = []
    stable_keys_by_path_name: dict[tuple[str, str], list[str]] = {}
    stable_keys_by_name: dict[str, list[str]] = {}
    symbols_by_path: dict[str, list[Symbol]] = {}
    for symbol in graph.symbols + graph.routes:
        symbols_by_path.setdefault(symbol.path, []).append(symbol)

    for file_ir in sorted(graph.files, key=lambda item: item.path):
        path = root / file_ir.path
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            size_bytes = path.stat().st_size
        except OSError:
            continue
        source_files.append(SourceFileInput(file_ir.path, file_ir.language, file_ir.content_hash, size_bytes))
        lines = text.splitlines()
        entries = sorted(symbols_by_path.get(file_ir.path, []), key=lambda item: item.line)
        if not any(entry.kind != "route" for entry in entries):
            # Routes alone leave module-level code unowned; keep the file symbol too.
            entries = [
                *entries,
                Symbol(Path(file_ir.path).stem, file_ir.path, 1, max(1, len(lines)), "file"),
            ]
        stable_key_by_symbol = stable_symbol_keys(entries)
        for entry in entries:
            name = entry.qualified_name or entry.name
            line = entry.line
            end = max(line, entry.end_line)
            content = "\n".join(line_text.rstrip() for line_text in lines[line - 1 : min(end, len(lines))]).strip()
            stable_key = stable_key_by_symbol[id(entry)]
            symbol_inputs.append(
                SymbolInput(
                    stable_key=stable_key,
                    qualified_name=name,
                    kind=entry.kind,
                    path=file_ir.path,
                    start_line=line,
                    end_line=max(line, end),
                    content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    content=content,
                    signature=entry.signature,
                )
            )
            aliases = {
                entry.name,
                name,
                entry.name.rsplit(".", 1)[-1],
                name.rsplit(".", 1)[-1],
            }
            for alias in aliases:
                stable_keys_by_path_name.setdefault((file_ir.path, alias), []).append(stable_key)
                stable_keys_by_name.setdefault(alias, []).append(stable_key)

    edge_inputs: list[EdgeInput] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for call in graph.calls:
        source_keys = stable_keys_by_path_name.get((call.path, call.caller), [])
        callee_name = call.callee.rsplit(".", 1)[-1]
        for source_key in source_keys:
            for target_key in stable_keys_by_name.get(callee_name, []):
                edge_key = (source_key, target_key, "calls")
                if source_key == target_key or edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)
                edge_inputs.append(EdgeInput(source_key, target_key, "calls", "tree_sitter"))

    for reference in graph.references:
        source_keys = stable_keys_by_path_name.get((reference.path, reference.source), [])
        target_name = reference.target.rsplit(".", 1)[-1]
        for source_key in source_keys:
            for target_key in stable_keys_by_name.get(target_name, []):
                edge_key = (source_key, target_key, "references")
                if source_key == target_key or edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)
                edge_inputs.append(
                    EdgeInput(
                        source_key,
                        target_key,
                        "references",
                        "tree_sitter",
                        0.9,
                    )
                )

    return source_files, symbol_inputs, edge_inputs


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
        record.scan_status,
        record.scan_parameters,
        record.result_summary,
    )


def _scan_finding_value(record: ScanFindingRecord) -> ScanFindingValue:
    return ScanFindingValue(
        scan_finding_id=record.scan_finding_id,
        tenant_id=record.tenant_id,
        scan_id=record.scan_id,
        finding_id=record.finding_id,
        fingerprint=record.fingerprint,
        severity=record.severity,
        category=record.category,
        cwe_id=record.cwe_id,
        owasp_category=record.owasp_category,
        report_schema_version=record.report_schema_version,
        report_data=record.report_data,
    )


def _has_complete_graph_finding_dependencies(validation: Any) -> bool:
    return (
        isinstance(validation, dict)
        and validation.get("graph_dependency_version") == 1
        and validation.get("graph_dependencies_complete") is True
    )


def _tenant_control_value(record: TenantControlRecord) -> TenantControlValue:
    return TenantControlValue(
        record.tenant_id,
        record.maximum_concurrent_jobs,
        record.maximum_daily_jobs,
        record.maximum_monthly_model_cost_usd,
        record.completed_scan_retention_days,
        record.failed_scan_retention_days,
    )


def _scan_job_value(record: ScanJobRecord) -> ScanJobValue:
    return ScanJobValue(
        record.job_id,
        record.tenant_id,
        record.request_key,
        record.codebase_external_key,
        record.revision,
        record.snapshot_uri,
        record.output_uri,
        dict(record.job_data),
        record.state,
        record.priority,
        record.attempt_count,
        record.maximum_attempts,
        record.lease_owner,
        record.lease_expires_at,
        record.failure_code,
        dict(record.result_summary),
    )


def _hunt_plan_value(record: HuntPlanRecord) -> HuntPlanValue:
    return HuntPlanValue(
        record.plan_id,
        record.scan_id,
        record.strategy,
        record.context_hash,
        record.workflow_version,
    )


def _knowledge_value(record: SecurityKnowledgeRecord) -> KnowledgeValue:
    return KnowledgeValue(
        knowledge_id=record.knowledge_id,
        topic=record.topic,
        vulnerability_class=record.vulnerability_class,
        ecosystem=record.ecosystem,
        framework=record.framework,
        content=record.content,
        source_url=record.source_url,
        source_title=record.source_title,
        source_updated_at=record.source_updated_at,
        provenance=record.provenance,
        confidence=record.confidence,
        content_hash=record.content_hash,
        claims=list(record.claims),
        tenant_id=record.tenant_id,
        status=record.status,
    )


def _security_memory_value(record: SecurityMemoryRecord) -> SecurityMemoryValue:
    return SecurityMemoryValue(
        memory_id=record.memory_id,
        codebase_id=record.codebase_id,
        scope=record.scope,
        category=record.category,
        statement=record.statement,
        provenance=record.provenance,
        status=record.status,
        version=record.version,
    )


def _hunt_task_value(record: HuntTaskRecord) -> HuntTaskValue:
    return HuntTaskValue(
        record.task_id,
        record.plan_id,
        record.task_key,
        record.title,
        record.objective,
        record.task_data,
        record.state,
        record.attempt_count,
        record.lease_owner,
        record.lease_expires_at,
    )


def _investigation_value(record: InvestigationRecord) -> InvestigationValue:
    return InvestigationValue(
        investigation_id=record.investigation_id,
        scan_id=record.scan_id,
        codebase_id=record.codebase_id,
        snapshot_id=record.snapshot_id,
        stable_key=record.stable_key,
        evidence_hash=record.evidence_hash,
        investigation_data=dict(record.investigation_data),
        state=record.state,
        checkpoint_ref=record.checkpoint_ref,
        revision=record.revision,
        attempt_count=record.attempt_count,
    )


def _surface_planning_value(record: SurfacePlanningRecord) -> SurfacePlanningValue:
    return SurfacePlanningValue(
        scan_id=record.scan_id,
        tenant_id=record.tenant_id,
        snapshot_id=record.snapshot_id,
        state=record.state,
        revision=record.revision,
        planning_data=dict(record.planning_data),
    )


def _surface_plan_identity(value: dict[str, Any]) -> dict[str, Any]:
    """Remove mutable progress fields before comparing immutable plan identity."""
    result = dict(value)
    result["groups"] = [
        {
            key: item_value
            for key, item_value in item.items()
            if key not in {"planning_status", "investigation_id"}
        }
        for item in value.get("groups", [])
    ]
    return result
