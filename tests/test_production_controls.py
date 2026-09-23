from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.persistence.models import AuditEventRecord, Base, ScanJobRecord, UsageEventRecord
from plaidnox_sast.persistence.repositories import ProductionControlError, unit_of_work
from plaidnox_sast.worker import ScanWorker, WorkerExecutionError, WorkerPaths


@pytest.fixture
def factory():
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


def _controls(repository, *, concurrent=1, daily=10, cost=10.0):
    repository.upsert_tenant_controls(
        maximum_concurrent_jobs=concurrent,
        maximum_daily_jobs=daily,
        maximum_monthly_model_cost_usd=cost,
        completed_scan_retention_days=90,
        failed_scan_retention_days=30,
    )


def _enqueue(repository, key="request-1", attempts=3):
    return repository.enqueue_scan_job(
        key,
        "owner/service",
        "revision-1",
        "file:///snapshots/service",
        f"file:///outputs/{key}",
        job_data={"snapshot_tree_hash": "a" * 64},
        maximum_attempts=attempts,
    )


def test_scan_job_lease_honors_tenant_concurrency_and_completion(factory) -> None:
    with unit_of_work(factory, "tenant-a") as repository:
        _controls(repository, concurrent=1)
        first = _enqueue(repository, "first")
        queued_second = _enqueue(repository, "second")
        leased = repository.lease_next_scan_job("worker-1", 60)
        blocked = repository.lease_next_scan_job("worker-2", 60)

    assert leased is not None
    assert blocked is None

    with unit_of_work(factory, "tenant-a") as repository:
        assert repository.complete_scan_job(leased.job_id, "worker-1", {"findings": 2})
        second = repository.lease_next_scan_job("worker-2", 60)

    assert second is not None
    assert {leased.job_id, second.job_id} == {first.job_id, queued_second.job_id}


def test_failed_scan_job_requeues_until_maximum_attempts(factory) -> None:
    with unit_of_work(factory, "tenant-a") as repository:
        _controls(repository)
        job = _enqueue(repository, attempts=2)
        first = repository.lease_next_scan_job("worker", 60)
        assert first is not None
        assert repository.fail_scan_job(job.job_id, "worker", "provider_unavailable")

    with factory() as session:
        assert session.get(ScanJobRecord, job.job_id).state == "queued"

    with unit_of_work(factory, "tenant-a") as repository:
        second = repository.lease_next_scan_job("worker", 60)
        assert second is not None
        assert repository.fail_scan_job(job.job_id, "worker", "provider_unavailable")

    with factory() as session:
        assert session.get(ScanJobRecord, job.job_id).state == "failed"


def test_tenant_model_cost_quota_fails_closed(factory) -> None:
    with unit_of_work(factory, "tenant-a") as repository:
        _controls(repository, cost=1.0)
        queued = _enqueue(repository, "before-quota")
        repository.record_model_usage("usage-1", None, "deep", 10, 5, 0.75)
        # Already-incurred spend is always recorded, even past the quota.
        repository.record_model_usage("usage-2", None, "deep", 10, 5, 0.5)
        assert repository.monthly_model_cost_exceeded()

    with factory() as session:
        assert session.scalar(select(func.count()).select_from(UsageEventRecord)) == 2

    with pytest.raises(ProductionControlError, match="cost quota"), unit_of_work(
        factory, "tenant-a"
    ) as repository:
        _enqueue(repository, "after-quota")

    with unit_of_work(factory, "tenant-a") as repository:
        assert repository.lease_next_scan_job("worker", 60) is None
    with factory() as session:
        assert session.get(ScanJobRecord, queued.job_id).state == "queued"


def test_expired_final_attempt_lease_is_failed_not_stuck(factory) -> None:
    start = datetime.now(UTC)
    with unit_of_work(factory, "tenant-a") as repository:
        _controls(repository, concurrent=2)
        job = _enqueue(repository, attempts=1)
        assert repository.lease_next_scan_job("crashed-worker", 60, now=start) is not None

    with unit_of_work(factory, "tenant-a") as repository:
        assert repository.lease_next_scan_job("worker-2", 60, now=start + timedelta(seconds=120)) is None

    with factory() as session:
        record = session.get(ScanJobRecord, job.job_id)
        assert record.state == "failed"
        assert record.failure_code == "lease_expired_attempts_exhausted"
        assert record.lease_owner is None


def test_audit_event_redacts_credentials_and_is_idempotent(factory) -> None:
    with unit_of_work(factory, "tenant-a") as repository:
        first_hash = repository.append_audit_event(
            "audit-1",
            "scan_job_completed",
            "worker",
            "worker-1",
            "scan_job",
            "job-1",
            "success",
            {"authorization": "Bearer abcdefghijklmnopqrstuvwxyz"},
        )
        second_hash = repository.append_audit_event(
            "audit-1",
            "ignored",
            "worker",
            "worker-1",
            "scan_job",
            "job-1",
            "success",
            {},
        )

    with factory() as session:
        event = session.get(AuditEventRecord, "audit-1")

    assert first_hash == second_hash == event.event_hash
    assert event.details["authorization"] == "<redacted-bearer-token>"


def test_artifact_lifecycle_requires_encryption_and_marks_expired(factory) -> None:
    now = datetime.now(UTC)
    with pytest.raises(ProductionControlError, match="encryption"), unit_of_work(
        factory, "tenant-a"
    ) as repository:
        repository.register_artifact("artifact-1", None, "report", "s3://bucket/report", "a" * 64, "", now)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.register_artifact(
            "artifact-1",
            None,
            "report",
            "s3://bucket/report",
            "a" * 64,
            "kms://key/reporting",
            now - timedelta(seconds=1),
        )
        assert repository.artifacts_due_for_deletion(now=now) == ["artifact-1"]
        assert repository.mark_artifact_deleted("artifact-1", now=now)
        assert repository.artifacts_due_for_deletion(now=now) == []


def test_worker_completes_a_leased_job_and_writes_audit(factory) -> None:
    with unit_of_work(factory, "tenant-a") as repository:
        _controls(repository)
        job = _enqueue(repository)
    worker = ScanWorker(
        factory,
        "tenant-a",
        "worker-1",
        lambda _job: {"decision": "pass", "findings": 0},
        lease_seconds=10,
        heartbeat_seconds=1,
    )

    processed = worker.run_once()

    assert processed is not None
    assert processed.job_id == job.job_id
    with factory() as session:
        record = session.get(ScanJobRecord, job.job_id)
        assert record.state == "completed"
        assert record.result_summary["decision"] == "pass"
        events = session.scalars(select(AuditEventRecord)).all()
        assert [event.event_type for event in events] == ["scan_job_completed"]


def test_worker_failure_is_requeued_and_audited(factory) -> None:
    with unit_of_work(factory, "tenant-a") as repository:
        _controls(repository)
        job = _enqueue(repository)

    def fail(_job):
        raise WorkerExecutionError("provider_unavailable")

    worker = ScanWorker(
        factory,
        "tenant-a",
        "worker-1",
        fail,
        lease_seconds=10,
        heartbeat_seconds=1,
    )

    with pytest.raises(WorkerExecutionError, match="provider_unavailable"):
        worker.run_once()

    with factory() as session:
        record = session.get(ScanJobRecord, job.job_id)
        assert record.state == "queued"
        assert record.failure_code == "provider_unavailable"


def test_worker_paths_reject_escape_and_symbolic_links(tmp_path) -> None:
    snapshots = tmp_path / "snapshots"
    outputs = tmp_path / "outputs"
    snapshot = snapshots / "service"
    snapshot.mkdir(parents=True)
    outputs.mkdir()
    paths = WorkerPaths.from_environment(
        {"PLAIDNOX_SNAPSHOT_ROOT": str(snapshots), "PLAIDNOX_OUTPUT_ROOT": str(outputs)}
    )

    with pytest.raises(WorkerExecutionError, match="escapes"):
        paths.resolve_snapshot((tmp_path / "outside").resolve().as_uri())

    target = tmp_path / "target.txt"
    target.write_text("data", encoding="utf-8")
    (snapshot / "link.txt").symlink_to(target)
    with pytest.raises(WorkerExecutionError, match="symbolic link"):
        paths.resolve_snapshot(snapshot.as_uri())
