"""SQLAlchemy mappings owned exclusively by SCM Integration.

A separate declarative `Base` from `plaidnox_sast.persistence.models.Base`
-- these tables live in their own migration/schema, deliberately not
foreign-keyed into Code Scanning's tables, keeping the two "separate
service and package" per docs/IMPLEMENTATION_PLAN.md's boundary rule.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Index, Integer, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ApplicationContextRecord(Base):
    """Cached Layer-1 ApplicationContext for one codebase (Contextual Review Plan v2, Layer 1).

    Keyed per `baseline_revision`, not just per codebase -- two concurrently
    open PRs against different base commits must not overwrite each other's
    cached context.
    """

    __tablename__ = "scm_application_contexts"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    codebase_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    baseline_revision: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_tree_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    builder_version: Mapped[str] = mapped_column(String(64), nullable=False)
    application_type: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    entry_points: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    components: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    security_controls: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    routes: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    sensitive_effects: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    environment_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    identity_provider: Mapped[str | None] = mapped_column(String(128))
    prior_finding_refs: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    context_version: Mapped[str] = mapped_column(String(64), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class FindingBaselineRecord(Base):
    """Immutable verified-finding state for one exact base revision."""

    __tablename__ = "scm_finding_baselines"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    codebase_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    baseline_revision: Mapped[str] = mapped_column(String(64), primary_key=True)
    root_cause_fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    root_cause_path: Mapped[str] = mapped_column(String, nullable=False)
    root_cause_symbol: Mapped[str] = mapped_column(String, nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class FindingTriageRecord(Base):
    """Current triage lifecycle state for one finding (Wave 12).

    Keyed by `(tenant_id, finding_id)`, not by review or revision -- unlike
    `FindingBaselineRecord`, triage state is a property of the finding
    itself and must survive across re-reviews of the same PR (new pushes)
    and across the finding moving between `EXISTING`/`MODIFIED_EXISTING`
    baseline relationships.
    """

    __tablename__ = "scm_finding_triage"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    actor: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class FindingTriageEventRecord(Base):
    """Append-only audit trail of every triage command actually applied (Wave 12)."""

    __tablename__ = "scm_finding_triage_events"
    __table_args__ = (Index("ix_scm_finding_triage_events_finding", "tenant_id", "finding_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False)
    review_id: Mapped[str] = mapped_column(String(64), nullable=False)
    command: Mapped[str] = mapped_column(String(32), nullable=False)
    previous_state: Mapped[str] = mapped_column(String(32), nullable=False)
    new_state: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ReviewAttemptRecord(Base):
    """Durable idempotency/lease record for one `POST /v1/reviews` attempt.

    Keyed by the same deterministic `review_id` hash `api_service._review_id`
    already computes -- a completed row lets a duplicate delivery (retried
    webhook) replay the stored result instead of re-running the review, and
    an unexpired `running` row makes a genuinely concurrent duplicate
    delivery fail fast instead of racing on the same baseline/context writes.
    """

    __tablename__ = "scm_review_attempts"
    __table_args__ = (
        Index("ix_scm_review_attempt_lease", "state", "lease_expires_at"),
        Index("ix_scm_review_attempt_codebase", "tenant_id", "codebase_id", "created_at"),
    )

    review_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    codebase_id: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    repository_id: Mapped[int] = mapped_column(Integer, nullable=False)
    review_number: Mapped[int] = mapped_column(Integer, nullable=False)
    base_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    delivery_id: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    outcome: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[str | None] = mapped_column(String)
    incomplete_reason: Mapped[str | None] = mapped_column(String)
    counters: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    findings: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    error_type: Mapped[str | None] = mapped_column(String(128))
    error_message: Mapped[str | None] = mapped_column(String)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
