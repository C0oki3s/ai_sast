from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from plaidnox_scm.attempts import (
    ReviewAttemptConflictError,
    ReviewAttemptExhaustedError,
    unit_of_work,
)
from plaidnox_scm.models import Base


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _claim_kwargs(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "provider": "github",
        "repository_id": 899377752,
        "review_number": 7,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "delivery_id": "delivery-1",
        "lease_owner": "worker-1",
        "lease_seconds": 600,
        "max_attempts": 3,
    }
    kwargs.update(overrides)
    return kwargs


def test_fresh_claim_starts_running() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        attempt = repository.claim("review-1", "codebase-1", **_claim_kwargs())

    assert attempt.state == "running"
    assert attempt.attempt_count == 1
    assert attempt.lease_owner == "worker-1"


def test_second_claim_while_unexpired_raises_conflict() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-1"))

    with pytest.raises(ReviewAttemptConflictError):
        with unit_of_work(factory, "tenant-a") as repository:
            repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-2"))


def test_claim_after_lease_expires_is_reclaimed_with_incremented_attempt_count() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)
    past = datetime.now(UTC) - timedelta(hours=1)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim(
            "review-1",
            "codebase-1",
            **_claim_kwargs(lease_owner="worker-1", lease_seconds=1, now=past),
        )

    with unit_of_work(factory, "tenant-a") as repository:
        attempt = repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-2"))

    assert attempt.state == "running"
    assert attempt.lease_owner == "worker-2"
    assert attempt.attempt_count == 2


def test_complete_then_fresh_claim_returns_completed_row_unchanged() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-1"))
        completed = repository.complete(
            "review-1",
            "worker-1",
            outcome="pass_no_verified_finding",
            action="allow",
            summary="No new verified finding requires merge action. Policy decision: PASS.",
            incomplete_reason=None,
            counters={"verified": 0},
            findings=[],
        )
    assert completed is True

    with unit_of_work(factory, "tenant-a") as repository:
        attempt = repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-2"))

    assert attempt.state == "completed"
    assert attempt.action == "allow"
    assert attempt.attempt_count == 1  # unchanged: no re-run/reclaim happened


def test_claim_exhausted_after_max_attempts_raises() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)
    epoch = datetime(2024, 1, 1, tzinfo=UTC)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim(
            "review-1",
            "codebase-1",
            **_claim_kwargs(lease_owner="worker-1", lease_seconds=1, now=epoch),
        )
    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim(
            "review-1",
            "codebase-1",
            **_claim_kwargs(lease_owner="worker-2", lease_seconds=1, now=epoch + timedelta(seconds=10)),
        )

    with pytest.raises(ReviewAttemptExhaustedError):
        with unit_of_work(factory, "tenant-a") as repository:
            repository.claim(
                "review-1",
                "codebase-1",
                **_claim_kwargs(
                    lease_owner="worker-3",
                    max_attempts=2,
                    now=epoch + timedelta(seconds=20),
                ),
            )


def test_complete_after_lease_stolen_is_a_noop() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)
    past = datetime.now(UTC) - timedelta(hours=1)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim(
            "review-1",
            "codebase-1",
            **_claim_kwargs(lease_owner="worker-1", lease_seconds=1, now=past),
        )
    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-2"))

    with unit_of_work(factory, "tenant-a") as repository:
        result = repository.complete(
            "review-1",
            "worker-1",
            outcome="pass_no_verified_finding",
            action="allow",
            summary="stale",
            incomplete_reason=None,
            counters=None,
            findings=[],
        )
    assert result is False

    with unit_of_work(factory, "tenant-a") as repository:
        attempt = repository.get("review-1")
    assert attempt is not None
    assert attempt.state == "running"
    assert attempt.lease_owner == "worker-2"


def test_fail_after_lease_stolen_is_a_noop() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)
    past = datetime.now(UTC) - timedelta(hours=1)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim(
            "review-1",
            "codebase-1",
            **_claim_kwargs(lease_owner="worker-1", lease_seconds=1, now=past),
        )
    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-2"))

    with unit_of_work(factory, "tenant-a") as repository:
        result = repository.fail("review-1", "worker-1", error_type="RuntimeError", error_message="stale")
    assert result is False

    with unit_of_work(factory, "tenant-a") as repository:
        attempt = repository.get("review-1")
    assert attempt is not None
    assert attempt.state == "running"


def test_fail_then_reclaim_and_complete() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-1"))
        failed = repository.fail("review-1", "worker-1", error_type="RuntimeError", error_message="boom")
    assert failed is True

    with unit_of_work(factory, "tenant-a") as repository:
        attempt = repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-2"))
    assert attempt.state == "running"
    assert attempt.attempt_count == 2


def test_renew_extends_an_owned_lease_so_a_short_lease_survives_a_long_scan() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)
    epoch = datetime(2024, 1, 1, tzinfo=UTC)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim(
            "review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-1", lease_seconds=60, now=epoch)
        )
        renewed = repository.renew("review-1", "worker-1", 60, now=epoch + timedelta(seconds=50))
    assert renewed is True

    # Without the renewal this claim (at +70s, past the original 60s lease)
    # would have reclaimed the lease from worker-1; the heartbeat pushed
    # expiry to +110s, so it is still owned and must conflict instead.
    with pytest.raises(ReviewAttemptConflictError):
        with unit_of_work(factory, "tenant-a") as repository:
            repository.claim(
                "review-1",
                "codebase-1",
                **_claim_kwargs(lease_owner="worker-2", now=epoch + timedelta(seconds=70)),
            )


def test_renew_after_lease_stolen_is_a_noop() -> None:
    factory = sessionmaker(bind=_engine(), expire_on_commit=False)
    past = datetime.now(UTC) - timedelta(hours=1)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim(
            "review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-1", lease_seconds=1, now=past)
        )
    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-2"))

    with unit_of_work(factory, "tenant-a") as repository:
        renewed = repository.renew("review-1", "worker-1", 60)
    assert renewed is False


def test_concurrent_first_claim_race_is_resolved_by_refetch_not_a_500(monkeypatch) -> None:
    """Two workers both reading "no row" before either INSERTs must not surface a raw IntegrityError."""

    factory = sessionmaker(bind=_engine(), expire_on_commit=False)

    with unit_of_work(factory, "tenant-a") as repository:
        repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-winner"))

    real_get = Session.get
    seen = {"count": 0}

    def fake_get(self: Session, entity: object, ident: object, *args: object, **kwargs: object) -> object:
        seen["count"] += 1
        if seen["count"] == 1:
            # Simulate the race: this worker's read happened before
            # worker-winner's row was visible to it.
            return None
        return real_get(self, entity, ident, *args, **kwargs)

    monkeypatch.setattr(Session, "get", fake_get)

    with pytest.raises(ReviewAttemptConflictError):
        with unit_of_work(factory, "tenant-a") as repository:
            repository.claim("review-1", "codebase-1", **_claim_kwargs(lease_owner="worker-loser"))
