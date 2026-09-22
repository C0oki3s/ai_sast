"""Cached ApplicationContext persistence (Contextual Review Plan v2, Layer 1).

Follows the same `unit_of_work` transaction pattern as
`plaidnox_sast.persistence.repositories`, but as its own small repository
scoped to one table -- this package owns its persistence independently of
Code Scanning's.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .baseline_models import BaselineFinding
from .models import ApplicationContextRecord, FindingBaselineRecord


@dataclass(frozen=True, slots=True)
class ApplicationContext:
    codebase_id: str
    tenant_id: str
    baseline_revision: str
    source_tree_hash: str
    builder_version: str
    application_type: str
    entry_points: tuple[Any, ...]
    components: tuple[Any, ...]
    security_controls: tuple[Any, ...]
    routes: tuple[Any, ...]
    sensitive_effects: tuple[Any, ...]
    environment_metadata: dict[str, Any]
    identity_provider: str | None
    prior_finding_refs: tuple[str, ...]
    confidence: float
    context_version: str
    computed_at: datetime


class ApplicationContextRepository:
    """Tenant-scoped cache for the Layer-1 ApplicationContext of one codebase."""

    def __init__(self, session: Session, tenant_id: str) -> None:
        self._session = session
        self._tenant_id = tenant_id

    def get_context(
        self,
        codebase_id: str,
        baseline_revision: str | None = None,
        *,
        builder_version: str | None = None,
        context_version: str | None = None,
    ) -> ApplicationContext | None:
        record = self._session.get(ApplicationContextRecord, (self._tenant_id, codebase_id))
        if record is None:
            return None
        if baseline_revision is not None and record.baseline_revision != baseline_revision:
            return None
        if builder_version is not None and record.builder_version != builder_version:
            return None
        if context_version is not None and record.context_version != context_version:
            return None
        return _to_value(record)

    def upsert_context(self, context: ApplicationContext) -> ApplicationContext:
        record = self._session.get(ApplicationContextRecord, (self._tenant_id, context.codebase_id))
        if record is None:
            record = ApplicationContextRecord(codebase_id=context.codebase_id, tenant_id=self._tenant_id)
            self._session.add(record)
        record.baseline_revision = context.baseline_revision
        record.source_tree_hash = context.source_tree_hash
        record.builder_version = context.builder_version
        record.application_type = context.application_type
        record.entry_points = list(context.entry_points)
        record.components = list(context.components)
        record.security_controls = list(context.security_controls)
        record.routes = list(context.routes)
        record.sensitive_effects = list(context.sensitive_effects)
        record.environment_metadata = dict(context.environment_metadata)
        record.identity_provider = context.identity_provider
        record.prior_finding_refs = list(context.prior_finding_refs)
        record.confidence = context.confidence
        record.context_version = context.context_version
        record.computed_at = context.computed_at
        self._session.flush()
        return _to_value(record)

    def get_or_compute(
        self,
        codebase_id: str,
        baseline_revision: str,
        compute: Callable[[], ApplicationContext],
        *,
        builder_version: str | None = None,
        context_version: str | None = None,
    ) -> ApplicationContext:
        """Reuse context only for the same immutable baseline revision."""

        cached = self.get_context(
            codebase_id,
            baseline_revision,
            builder_version=builder_version,
            context_version=context_version,
        )
        if cached is not None:
            return cached
        return self.upsert_context(compute())

    def list_baseline_findings(
        self,
        codebase_id: str,
        baseline_revision: str,
    ) -> tuple[BaselineFinding, ...]:
        rows = self._session.scalars(
            select(FindingBaselineRecord)
            .where(
                FindingBaselineRecord.tenant_id == self._tenant_id,
                FindingBaselineRecord.codebase_id == codebase_id,
                FindingBaselineRecord.baseline_revision == baseline_revision,
            )
            .order_by(
                FindingBaselineRecord.root_cause_path,
                FindingBaselineRecord.root_cause_symbol,
                FindingBaselineRecord.root_cause_fingerprint,
            )
        ).all()
        return tuple(_to_baseline_value(row) for row in rows)

    def upsert_baseline_finding(self, finding: BaselineFinding) -> BaselineFinding:
        if finding.codebase_id == "" or finding.baseline_revision == "":
            raise ValueError("baseline finding requires codebase and revision identities")
        key = (
            self._tenant_id,
            finding.codebase_id,
            finding.baseline_revision,
            finding.root_cause_fingerprint,
        )
        record = self._session.get(FindingBaselineRecord, key)
        if record is None:
            record = FindingBaselineRecord(
                tenant_id=self._tenant_id,
                codebase_id=finding.codebase_id,
                baseline_revision=finding.baseline_revision,
                root_cause_fingerprint=finding.root_cause_fingerprint,
            )
            self._session.add(record)
        record.finding_fingerprint = finding.finding_fingerprint
        record.lifecycle_state = finding.lifecycle_state
        record.root_cause_path = finding.root_cause_path
        record.root_cause_symbol = finding.root_cause_symbol
        record.vulnerability_class = finding.vulnerability_class
        record.title = finding.title
        record.severity = finding.severity
        record.confidence = finding.confidence
        self._session.flush()
        return _to_baseline_value(record)


def _to_value(record: ApplicationContextRecord) -> ApplicationContext:
    return ApplicationContext(
        codebase_id=record.codebase_id,
        tenant_id=record.tenant_id,
        baseline_revision=record.baseline_revision,
        source_tree_hash=record.source_tree_hash,
        builder_version=record.builder_version,
        application_type=record.application_type,
        entry_points=tuple(record.entry_points),
        components=tuple(record.components),
        security_controls=tuple(record.security_controls),
        routes=tuple(record.routes),
        sensitive_effects=tuple(record.sensitive_effects),
        environment_metadata=dict(record.environment_metadata),
        identity_provider=record.identity_provider,
        prior_finding_refs=tuple(record.prior_finding_refs),
        confidence=record.confidence,
        context_version=record.context_version,
        computed_at=record.computed_at,
    )


def _to_baseline_value(record: FindingBaselineRecord) -> BaselineFinding:
    return BaselineFinding(
        codebase_id=record.codebase_id,
        baseline_revision=record.baseline_revision,
        root_cause_fingerprint=record.root_cause_fingerprint,
        finding_fingerprint=record.finding_fingerprint,
        lifecycle_state=record.lifecycle_state,
        root_cause_path=record.root_cause_path,
        root_cause_symbol=record.root_cause_symbol,
        vulnerability_class=record.vulnerability_class,
        title=record.title,
        severity=record.severity,
        confidence=record.confidence,
    )


@contextmanager
def unit_of_work(factory: sessionmaker[Session], tenant_id: str) -> Iterator[ApplicationContextRepository]:
    """Commit one domain operation or roll the complete transaction back."""

    session = factory()
    try:
        with session.begin():
            yield ApplicationContextRepository(session, tenant_id)
    finally:
        session.close()
