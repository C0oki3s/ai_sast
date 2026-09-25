from dataclasses import replace
import hashlib

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.investigations import (
    Investigation,
    InvestigationContractError,
    investigation_evidence_hash,
    validate_investigation,
)
from plaidnox_sast.persistence.models import Base
from plaidnox_sast.persistence.repositories import (
    PersistenceConflictError,
    stable_id,
    unit_of_work,
)


def _investigation(*, excerpt: str = "return account;") -> Investigation:
    source_hash = hashlib.sha256(excerpt.encode()).hexdigest()
    initial = Investigation(
        investigation_id="pending",
        schema_version=1,
        stable_key="surface:account-update",
        codebase_id="codebase-1",
        snapshot_id="snapshot-1",
        target_ref={"kind": "route", "path": "routes/account.py", "name": "update_account"},
        reason="Review identity binding before account mutation.",
        security_questions=("Can the caller modify another principal's account?",),
        graph_refs=({"node_id": "node-account-update", "provenance": "EXTRACTED", "snapshot_id": "snapshot-1"},),
        source_windows=(
            {
                "path": "routes/account.py",
                "start_line": 10,
                "end_line": 10,
                "content_hash": source_hash,
                "excerpt": excerpt,
                "redaction_state": "not_required",
            },
        ),
        context_dependencies=({"kind": "graph_node", "key": "node-account-update", "hash": source_hash},),
        coverage_notes=(),
        prior_evidence_refs=(),
        evidence_hash="0" * 64,
    )
    initial = replace(initial, evidence_hash=investigation_evidence_hash(initial))
    return replace(initial, investigation_id=stable_id("investigation", initial.codebase_id, initial.stable_key, initial.evidence_hash))


def test_investigation_contract_hashes_evidence_and_accepts_open_security_questions():
    investigation = _investigation()
    validate_investigation(investigation)

    changed = _investigation(excerpt="return account.save();")
    assert changed.stable_key == investigation.stable_key
    assert changed.investigation_id != investigation.investigation_id
    assert changed.evidence_hash != investigation.evidence_hash


def test_investigation_contract_rejects_unredacted_secrets_and_unsafe_paths():
    synthetic_secret = "sk-" + ("x" * 20)
    investigation = _investigation(excerpt=f"const token = '{synthetic_secret}';")
    with pytest.raises(InvestigationContractError, match="must be redacted"):
        validate_investigation(investigation)

    unsafe = replace(_investigation(), source_windows=({
        "path": "../secrets.py",
        "start_line": 1,
        "end_line": 1,
        "content_hash": hashlib.sha256(b"x").hexdigest(),
        "excerpt": "x",
        "redaction_state": "not_required",
    },))
    unsafe = replace(unsafe, evidence_hash=investigation_evidence_hash(unsafe))
    with pytest.raises(InvestigationContractError, match="repository-relative"):
        validate_investigation(unsafe)


def test_investigation_repository_is_tenant_scoped_idempotent_and_resumable():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-1", "local/example", "Example")
        repository.add_snapshot("snapshot-1", "codebase-1", "revision-1", "tree-hash", "context-v1")
        repository.start_scan("scan-1", "codebase-1", "snapshot-1", "deep", "workflow-v1")
        investigation = _investigation()
        saved = repository.save_investigation("scan-1", investigation)
        duplicate = repository.save_investigation("scan-1", investigation)
        newer_evidence = repository.save_investigation("scan-1", _investigation(excerpt="return account.save();"))
        running = repository.transition_investigation(
            saved.investigation_id, "running", expected_revision=1, checkpoint_ref="checkpoint/unit-1"
        )
        candidate = repository.transition_investigation(
            saved.investigation_id, "candidate", expected_revision=2
        )

        assert duplicate.investigation_id == saved.investigation_id
        assert newer_evidence.investigation_id != saved.investigation_id
        assert newer_evidence.evidence_hash != saved.evidence_hash
        assert running.attempt_count == 1
        assert candidate.state == "candidate"
        assert candidate.revision == 3
        assert len(repository.list_investigations("scan-1")) == 2
        with pytest.raises(PersistenceConflictError, match="revision changed"):
            repository.transition_investigation(saved.investigation_id, "running", expected_revision=2)
        with pytest.raises(PersistenceConflictError, match="invalid investigation transition"):
            repository.transition_investigation(saved.investigation_id, "failed", expected_revision=3)

    with unit_of_work(factory, "tenant-b") as repository:
        assert repository.list_investigations("scan-1") == []


def test_investigation_schema_is_a_deployable_orm_table():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    assert "code_scanning_investigations" in Base.metadata.tables
