"""SCM persistence checks against the deployable PostgreSQL migrations."""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_scm.baseline_models import BaselineFinding
from plaidnox_scm.context_store import unit_of_work

TEST_DATABASE_URL = os.environ.get("PLAIDNOX_TEST_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="set PLAIDNOX_TEST_DATABASE_URL to a disposable PostgreSQL instance to run this test",
)


def test_baseline_finding_round_trips_through_deployable_postgresql_schema() -> None:
    suffix = uuid.uuid4().hex[:12]
    tenant_id = f"tenant-scm-{suffix}"
    codebase_id = f"codebase-scm-{suffix}"
    revision = f"revision-scm-{suffix}"
    engine = create_engine(TEST_DATABASE_URL)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    finding = BaselineFinding(
        codebase_id=codebase_id,
        baseline_revision=revision,
        root_cause_fingerprint=f"root-{suffix}",
        finding_fingerprint=f"finding-{suffix}",
        lifecycle_state="open",
        root_cause_path="middleware/ValidateToken.js",
        root_cause_symbol="ValidateToken",
        vulnerability_class="authentication bypass",
        title="Protected routes accept forged identity claims",
        severity="high",
        confidence=0.97,
    )

    try:
        with unit_of_work(factory, tenant_id) as repository:
            repository.upsert_baseline_finding(finding)
        with unit_of_work(factory, tenant_id) as repository:
            assert repository.list_baseline_findings(codebase_id, revision) == (finding,)
    finally:
        engine.dispose()
