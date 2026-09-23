"""Wave 8 correctness hardening: stale-base review identity, lease heartbeat,
and rejecting a result published after the lease was lost mid-scan.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from plaidnox_scm import attempts
from plaidnox_scm.api_service import ReviewService, _review_id
from plaidnox_scm.assets import load_json
from plaidnox_scm.attempts import ReviewAttemptConflictError
from plaidnox_scm.models import Base
from plaidnox_scm.api_models import ReviewRequest
from plaidnox_scm.source_broker import RepositoryMirrorBroker


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def _repository(repo: Path) -> tuple[str, str]:
    repo.mkdir(parents=True)
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.name", "PlaidNox Tests")
    _git(repo, "config", "user.email", "tests@plaidnox.local")
    (repo / "README.md").write_text("# Fixture\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text("# Fixture\n\nDocumentation.\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "docs")
    return base, _git(repo, "rev-parse", "HEAD")


def _request(base: str, head: str) -> dict[str, object]:
    return {
        "provider": "github",
        "installation_id": 12345,
        "repository_full_name": "C0oki3s/NSTCTF",
        "repository_id": 899377752,
        "review_number": 7,
        "base_sha": base,
        "head_sha": head,
        "base_ref": "main",
        "head_ref": "feature/security-test",
        "delivery_id": "delivery-1",
    }


def _factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _pass_result() -> SimpleNamespace:
    return SimpleNamespace(
        outcome="pass_no_verified_finding",
        policy=SimpleNamespace(decision="PASS", reasons=()),
        counters=SimpleNamespace(blocking=0, in_triage=0),
        candidates=(),
        verifications=(),
        baseline_classifications=(),
        coverage_gaps=(),
        detail="ok",
    )


def test_review_id_changes_when_base_sha_changes_even_with_the_same_head_sha() -> None:
    """If `main` advances while a PR's head is unchanged, `base...head` names a
    different diff -- replaying the old review's result would be silently wrong.
    """

    same_head = "a" * 40
    original_base_request = ReviewRequest.model_validate(_request("1" * 40, same_head))
    advanced_base_request = ReviewRequest.model_validate(_request("2" * 40, same_head))

    assert _review_id(original_base_request) != _review_id(advanced_base_request)


def test_heartbeat_renews_the_lease_so_a_scan_longer_than_the_lease_still_completes(monkeypatch, tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    runtime = dict(load_json("runtime/review.json"))
    runtime["review_attempt_lease_seconds"] = 1
    runtime["review_attempt_heartbeat_seconds"] = 0.2

    def slow_review_pull_request(*args: object, **kwargs: object) -> SimpleNamespace:
        # Longer than the 1s lease but well within reach of a 0.2s heartbeat.
        time.sleep(0.6)
        return _pass_result()

    monkeypatch.setattr("plaidnox_scm.api_service.load_json", lambda path: runtime)
    monkeypatch.setattr("plaidnox_scm.api_service.review_pull_request", slow_review_pull_request)
    factory = _factory()
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        factory,
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    request = ReviewRequest.model_validate(_request(base, head))

    response = service.run(request)

    assert response.action.value == "allow"
    with attempts.unit_of_work(factory, f"{request.provider}:installation:{request.installation_id}") as repository:
        attempt = repository.get(_review_id(request))
    assert attempt is not None
    assert attempt.state == "completed"


def test_completion_is_rejected_once_another_worker_has_reclaimed_the_lease(monkeypatch, tmp_path: Path) -> None:
    """A worker that stalls past its lease must not publish once someone else has taken over."""

    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    runtime = dict(load_json("runtime/review.json"))
    runtime["review_attempt_lease_seconds"] = 0  # always instantly reclaimable
    factory = _factory()
    request = ReviewRequest.model_validate(_request(base, head))
    review_id = _review_id(request)
    codebase_id = f"{request.provider}:repository:{request.repository_id}"
    tenant_id = f"{request.provider}:installation:{request.installation_id}"

    def steals_the_lease_then_succeeds(*args: object, **kwargs: object) -> SimpleNamespace:
        with attempts.unit_of_work(factory, tenant_id) as repository:
            repository.claim(
                review_id,
                codebase_id,
                provider=request.provider,
                repository_id=request.repository_id,
                review_number=request.review_number,
                base_sha=request.base_sha,
                head_sha=request.head_sha,
                delivery_id="a-retried-delivery",
                lease_owner="thief",
                lease_seconds=600,
                max_attempts=3,
            )
        return _pass_result()

    monkeypatch.setattr("plaidnox_scm.api_service.load_json", lambda path: runtime)
    monkeypatch.setattr("plaidnox_scm.api_service.review_pull_request", steals_the_lease_then_succeeds)
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        factory,
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )

    try:
        service.run(request)
        raise AssertionError("expected the lost lease to be rejected with a conflict")
    except ReviewAttemptConflictError:
        pass

    with attempts.unit_of_work(factory, tenant_id) as repository:
        attempt = repository.get(review_id)
    assert attempt is not None
    assert attempt.lease_owner == "thief"
    assert attempt.state == "running"  # the thief's in-progress attempt, not worker A's stale result
