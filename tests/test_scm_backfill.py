from __future__ import annotations

import hashlib
import io
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from botocore.exceptions import ClientError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_scm.api_models import ReviewFinding
from plaidnox_scm.backfill import REBUILT_GAP, backfill_trace_code
from plaidnox_scm.models import Base, ReviewAttemptRecord, WebhookDeliveryRecord


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _setup(tmp_path: Path):
    mirror = tmp_path / "github" / "42"
    mirror.mkdir(parents=True)
    _git(mirror, "init", "-q")
    _git(mirror, "config", "user.email", "t@example.com")
    _git(mirror, "config", "user.name", "t")
    (mirror / "app.py").write_text("\n".join(f"line {number}" for number in range(1, 50)))
    _git(mirror, "add", ".")
    _git(mirror, "commit", "-qm", "head")
    head = _git(mirror, "rev-parse", "HEAD")
    finding = {
        "finding_id": "f-1", "root_cause_fingerprint": "r-1", "title": "Resource exhaustion",
        "severity": "medium", "confidence": 0.9, "description": "d", "root_cause_path": "app.py",
        "root_cause_symbol": "handler", "root_cause_start_line": 20, "root_cause_end_line": 20,
        "root_cause_changed_in_pr": True, "baseline_relationship": "introduced",
        "tenant_id": "tenant-a", "repository_id": 42, "base_revision": "a" * 40,
        "head_revision": head, "verified_at": datetime.now(UTC).isoformat(),
        "evidence": [{"role": "ATTACKER_ORIGIN", "source": "deep_hunt", "path": "app.py",
                      "start_line": 20, "end_line": 20, "summary": "request body enters handler"}],
    }
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory.begin() as session:
        session.add(ReviewAttemptRecord(
            review_id="review-1", tenant_id="tenant-a", codebase_id="github:repository:42",
            provider="github", repository_id=42, review_number=9, base_sha="a" * 40,
            head_sha=head, delivery_id="delivery-1", state="completed", attempt_count=1,
            findings=[finding], started_at=datetime.now(UTC),
        ))
    return factory


def _stored(factory):
    with factory() as session:
        return session.get(ReviewAttemptRecord, "review-1").findings[0]


def test_backfill_is_dry_run_then_writes_exact_commit_code(tmp_path: Path) -> None:
    factory = _setup(tmp_path)
    dry = backfill_trace_code(factory, tmp_path)
    assert dry.findings_updated == 1 and dry.traces_rebuilt == 1
    assert "vulnerable_snippet" not in _stored(factory)

    applied = backfill_trace_code(factory, tmp_path, apply=True)
    finding = _stored(factory)
    assert applied.snippets_filled == 1
    assert finding["vulnerable_snippet"]["code"] == "line 20"
    trace = finding["evidence_trace"]
    assert trace["nodes"][0]["code_start_line"] == 17
    assert trace["nodes"][0]["code_end_line"] == 23
    assert trace["complete"] is False and trace["evidence_gaps"] == [REBUILT_GAP]
    ReviewFinding.model_validate(finding)
    assert backfill_trace_code(factory, tmp_path, apply=True).findings_updated == 0


def test_missing_snapshot_is_reported_without_writing(tmp_path: Path) -> None:
    factory = _setup(tmp_path)
    (tmp_path / "github" / "42" / ".git").rename(tmp_path / "unavailable-git")
    report = backfill_trace_code(factory, tmp_path, apply=True)
    assert report.missing_snapshots == 1 and report.findings_updated == 0
    assert "vulnerable_snippet" not in _stored(factory)


def test_backfill_recovers_the_exact_review_bundle_from_s3(tmp_path: Path) -> None:
    factory = _setup(tmp_path)
    mirror = tmp_path / "github" / "42"
    bundle = tmp_path / "review.bundle"
    _git(mirror, "bundle", "create", str(bundle), "--all")
    data = bundle.read_bytes()
    key = f"reviews/123/42/{hashlib.sha256(b'delivery-1').hexdigest()}.bundle"
    with factory.begin() as session:
        session.add(WebhookDeliveryRecord(
            delivery_id="delivery-1", provider="github", installation_id=123, repository_id=42,
            event_name="pull_request", tenant_id="tenant-a", state="accepted",
        ))
    (mirror / ".git").rename(tmp_path / "unavailable-git")

    class FakeS3:
        def head_object(self, *, Bucket: str, Key: str):
            assert (Bucket, Key) == ("review-bundles", key)
            return {"ContentLength": len(data)}

        def get_object(self, *, Bucket: str, Key: str):
            assert (Bucket, Key) == ("review-bundles", key)
            return {"Body": io.BytesIO(data)}

    report = backfill_trace_code(
        factory, tmp_path, apply=True, bundle_bucket="review-bundles", s3_client=FakeS3()
    )
    assert report.bundles_downloaded == 1 and report.findings_updated == 1
    assert _stored(factory)["vulnerable_snippet"]["code"] == "line 20"


def test_inaccessible_bundle_is_reported_without_aborting_other_reviews(tmp_path: Path) -> None:
    factory = _setup(tmp_path)
    (tmp_path / "github" / "42" / ".git").rename(tmp_path / "unavailable-git")
    with factory.begin() as session:
        session.add(WebhookDeliveryRecord(
            delivery_id="delivery-1", provider="github", installation_id=123, repository_id=42,
            event_name="pull_request", tenant_id="tenant-a", state="accepted",
        ))

    class FakeS3:
        def head_object(self, *, Bucket: str, Key: str):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "HeadObject")

    report = backfill_trace_code(factory, tmp_path, apply=True, bundle_bucket="review-bundles", s3_client=FakeS3())
    assert report.bundle_access_denied == 1 and report.missing_snapshots == 1
    assert report.findings_updated == 0
    assert "vulnerable_snippet" not in _stored(factory)
