"""Typed SQLAlchemy mappings owned exclusively by Code Scanning."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class CodebaseRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_codebases"
    __table_args__ = (UniqueConstraint("tenant_id", "external_key", name="uq_code_scanning_codebase_key"),)

    codebase_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    external_key: Mapped[str] = mapped_column(String(512), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")


class SnapshotRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_snapshots"
    __table_args__ = (
        UniqueConstraint("codebase_id", "revision", name="uq_code_scanning_snapshot_revision"),
        Index("ix_code_scanning_snapshot_current", "codebase_id", "state", "created_at"),
    )

    snapshot_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    codebase_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_codebases.codebase_id", ondelete="CASCADE"), nullable=False
    )
    revision: Mapped[str] = mapped_column(String(128), nullable=False)
    tree_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="indexed")
    parent_snapshot_id: Mapped[str | None] = mapped_column(
        ForeignKey("code_scanning_snapshots.snapshot_id", ondelete="SET NULL")
    )
    context_version: Mapped[str] = mapped_column(String(64), nullable=False)


class RepositoryContextRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_repository_contexts"
    __table_args__ = (Index("ix_code_scanning_repository_context", "tenant_id", "codebase_id", "created_at"),)

    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_snapshots.snapshot_id", ondelete="CASCADE"), primary_key=True
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    codebase_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_codebases.codebase_id", ondelete="CASCADE"), nullable=False
    )
    context_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    context_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class SourceFileRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_source_files"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "path", name="uq_code_scanning_source_file_path"),
        CheckConstraint("size_bytes >= 0", name="ck_code_scanning_source_file_size"),
    )

    source_file_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_snapshots.snapshot_id", ondelete="CASCADE"), nullable=False, index=True
    )
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    language: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_uri: Mapped[str | None] = mapped_column(Text)


class SymbolRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_symbols"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "stable_key", name="uq_code_scanning_symbol_stable_key"),
        Index("ix_code_scanning_symbol_path", "snapshot_id", "path", "start_line"),
    )

    symbol_version_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    symbol_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_snapshots.snapshot_id", ondelete="CASCADE"), nullable=False
    )
    source_file_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_source_files.source_file_id", ondelete="CASCADE"), nullable=False
    )
    stable_key: Mapped[str] = mapped_column(String(2300), nullable=False)
    qualified_name: Mapped[str] = mapped_column(String(1024), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)


class CodeEdgeRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_edges"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id", "source_symbol_id", "target_symbol_id", "relation", name="uq_code_scanning_edge"
        ),
        Index("ix_code_scanning_edge_reverse", "snapshot_id", "target_symbol_id", "relation"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_code_scanning_edge_confidence"),
    )

    edge_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_snapshots.snapshot_id", ondelete="CASCADE"), nullable=False
    )
    source_symbol_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_symbol_id: Mapped[str] = mapped_column(String(64), nullable=False)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ThreatStatementRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_threat_statements"
    __table_args__ = (Index("ix_code_scanning_threat_scope", "tenant_id", "codebase_id", "status"),)

    threat_statement_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    codebase_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_codebases.codebase_id", ondelete="CASCADE"), nullable=False
    )
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    provenance: Mapped[str] = mapped_column(String(128), nullable=False)
    source_reference: Mapped[str] = mapped_column(Text, nullable=False, default="")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")


class SecurityMemoryRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_security_memories"
    __table_args__ = (Index("ix_code_scanning_memory_scope", "tenant_id", "codebase_id", "category", "status"),)

    memory_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    codebase_id: Mapped[str | None] = mapped_column(
        ForeignKey("code_scanning_codebases.codebase_id", ondelete="CASCADE")
    )
    scope: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    provenance: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class SecurityKnowledgeRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_security_knowledge"
    __table_args__ = (
        UniqueConstraint("tenant_id", "content_hash", name="uq_code_scanning_knowledge_hash"),
        Index("ix_code_scanning_knowledge_lookup", "tenant_id", "ecosystem", "framework", "status"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_code_scanning_knowledge_confidence"),
    )

    knowledge_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, default="global")
    topic: Mapped[str] = mapped_column(Text, nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    ecosystem: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    framework: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    source_title: Mapped[str] = mapped_column(Text, nullable=False)
    source_updated_at: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    provenance: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    claims: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")


class ScanRunRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_scan_runs"
    __table_args__ = (Index("ix_code_scanning_scan_lookup", "tenant_id", "codebase_id", "created_at"),)

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    codebase_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_codebases.codebase_id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_snapshots.snapshot_id", ondelete="RESTRICT"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    workflow_version: Mapped[str] = mapped_column(String(64), nullable=False)
    coverage_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    failure_code: Mapped[str] = mapped_column(String(128), nullable=False, default="")


class HuntPlanRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_hunt_plans"
    __table_args__ = (UniqueConstraint("scan_id", "context_hash", name="uq_code_scanning_hunt_plan_context"),)

    plan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_scan_runs.scan_id", ondelete="CASCADE"), nullable=False
    )
    strategy: Mapped[str] = mapped_column(Text, nullable=False)
    context_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    workflow_version: Mapped[str] = mapped_column(String(64), nullable=False)


class HuntTaskRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_hunt_tasks"
    __table_args__ = (
        UniqueConstraint("plan_id", "task_key", name="uq_code_scanning_hunt_task_key"),
        Index("ix_code_scanning_hunt_task_lease", "state", "lease_expires_at"),
    )

    task_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    plan_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_hunt_plans.plan_id", ondelete="CASCADE"), nullable=False
    )
    task_key: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    task_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="planned")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class KnowledgeUsageRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_knowledge_usage"
    __table_args__ = (Index("ix_code_scanning_knowledge_usage_task", "scan_id", "task_id"),)

    usage_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_scan_runs.scan_id", ondelete="CASCADE"), nullable=False
    )
    task_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_hunt_tasks.task_id", ondelete="CASCADE"), nullable=False
    )
    knowledge_id: Mapped[str | None] = mapped_column(
        ForeignKey("code_scanning_security_knowledge.knowledge_id", ondelete="SET NULL")
    )
    query: Mapped[str] = mapped_column(Text, nullable=False)
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)


class ModelInvocationRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_model_invocations"
    __table_args__ = (Index("ix_code_scanning_model_scan", "scan_id", "stage", "created_at"),)

    invocation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_scan_runs.scan_id", ondelete="CASCADE"), nullable=False
    )
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("code_scanning_hunt_tasks.task_id", ondelete="SET NULL")
    )
    stage: Mapped[str] = mapped_column(String(128), nullable=False)
    model_tier: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_request_id: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    prompt_asset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class PromptCacheMetricRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_prompt_cache_metrics"

    metric_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    invocation_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_model_invocations.invocation_id", ondelete="CASCADE"), nullable=False, unique=True
    )
    cache_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    cache_hit: Mapped[bool] = mapped_column(Boolean, nullable=False)
    cached_input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tokens_avoided: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class FindingRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_findings"
    __table_args__ = (
        UniqueConstraint("codebase_id", "fingerprint", name="uq_code_scanning_finding_fingerprint"),
        Index("ix_code_scanning_finding_scan", "scan_id", "state", "severity"),
    )

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    codebase_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_codebases.codebase_id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_scan_runs.scan_id", ondelete="CASCADE"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    validation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class FindingEvidenceRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_finding_evidence"
    __table_args__ = (Index("ix_code_scanning_evidence_finding", "finding_id", "sequence"),)

    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_findings.finding_id", ondelete="CASCADE"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    start_line: Mapped[int | None] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer)
    redacted_content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance: Mapped[str] = mapped_column(String(128), nullable=False)


class FindingDependencyRecord(TimestampMixin, Base):
    __tablename__ = "code_scanning_finding_dependencies"
    __table_args__ = (
        UniqueConstraint(
            "finding_id", "dependency_type", "dependency_key", name="uq_code_scanning_finding_dependency"
        ),
        Index("ix_code_scanning_finding_dependency_reverse", "dependency_type", "dependency_key"),
    )

    finding_dependency_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("code_scanning_findings.finding_id", ondelete="CASCADE"), nullable=False
    )
    dependency_type: Mapped[str] = mapped_column(String(64), nullable=False)
    dependency_key: Mapped[str] = mapped_column(String(2300), nullable=False)
    dependency_hash: Mapped[str] = mapped_column(String(64), nullable=False)
