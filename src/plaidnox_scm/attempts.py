"""Review-attempt persistence: idempotency + lease semantics for `POST /v1/reviews`.

Reuses the exact compare-and-swap lease pattern already proven by
`HuntTaskRecord`/`lease_next_task` in `plaidnox_sast.persistence.repositories`,
as its own small tenant-scoped repository -- this table and module belong to
`plaidnox_scm` only, per the standing package boundary.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .models import ReviewAttemptRecord


class ReviewAttemptError(RuntimeError):
    """Base error for review-attempt persistence failures."""


class ReviewAttemptConflictError(ReviewAttemptError):
    """An unexpired lease is held by someone else -- a genuine concurrent duplicate delivery."""


class ReviewAttemptExhaustedError(ReviewAttemptError):
    """A non-completed review_id has exhausted its bounded retry budget (rule 14)."""


@dataclass(frozen=True, slots=True)
class ReviewAttempt:
    review_id: str
    tenant_id: str
    codebase_id: str
    provider: str
    repository_id: int
    review_number: int
    base_sha: str
    head_sha: str
    delivery_id: str
    state: str
    lease_owner: str | None
    lease_expires_at: datetime | None
    attempt_count: int
    outcome: str | None
    action: str | None
    summary: str | None
    incomplete_reason: str | None
    counters: dict[str, Any] | None
    findings: tuple[Any, ...]
    error_type: str | None
    error_message: str | None
    started_at: datetime
    completed_at: datetime | None


class ReviewAttemptRepository:
    """Tenant-scoped idempotency/lease store for one review attempt per `review_id`."""

    def __init__(self, session: Session, tenant_id: str) -> None:
        self._session = session
        self._tenant_id = tenant_id

    def get(self, review_id: str) -> ReviewAttempt | None:
        """Look up a review attempt by its globally-unique id.

        Unlike `ApplicationContext` (keyed by tenant + codebase_id, which is
        only unique per tenant), `review_id` already hashes the full request
        identity (provider, installation, repository, review number, head
        sha), so it needs no tenant filter here -- this is what lets the
        status endpoint resolve a review without first knowing its tenant.
        """

        record = self._session.get(ReviewAttemptRecord, review_id)
        return _to_value(record) if record is not None else None

    def claim(
        self,
        review_id: str,
        codebase_id: str,
        *,
        provider: str,
        repository_id: int,
        review_number: int,
        base_sha: str,
        head_sha: str,
        delivery_id: str,
        lease_owner: str,
        lease_seconds: int,
        max_attempts: int,
        now: datetime | None = None,
    ) -> ReviewAttempt:
        """Get-or-create by `review_id`, enforcing bounded-retry lease semantics.

        - Already `"completed"`: returned as-is so the caller can replay it
          without re-running the review.
        - `"running"` with an unexpired lease: `ReviewAttemptConflictError`.
        - Otherwise (`"failed"`, or `"running"` with an expired lease):
          reclaimed via the same compare-and-swap `UPDATE ... WHERE` idiom as
          `lease_next_task`, retried once on a lost race.
        """

        if not lease_owner.strip():
            raise ValueError("lease_owner is required")
        moment = now or datetime.now(UTC)
        lease_until = moment + timedelta(seconds=lease_seconds)

        record = self._session.get(ReviewAttemptRecord, review_id)
        if record is None:
            new_record = ReviewAttemptRecord(
                review_id=review_id,
                tenant_id=self._tenant_id,
                codebase_id=codebase_id,
                provider=provider,
                repository_id=repository_id,
                review_number=review_number,
                base_sha=base_sha,
                head_sha=head_sha,
                delivery_id=delivery_id,
                state="running",
                lease_owner=lease_owner,
                lease_expires_at=lease_until,
                attempt_count=1,
                findings=[],
                started_at=moment,
            )
            try:
                with self._session.begin_nested():
                    self._session.add(new_record)
                    self._session.flush()
            except IntegrityError:
                # Lost the create race: two workers both read no row for this
                # review_id, and the other one's INSERT committed first. Fall
                # through to the reclaim/replay/conflict path below against
                # the row that actually won, instead of surfacing a 500.
                self._session.expire_all()
                record = self._session.get(ReviewAttemptRecord, review_id)
                assert record is not None
            else:
                return _to_value(new_record)

        # `lease_expires_at` is compared to `moment` only inside the SQL WHERE
        # below, never as a fetched Python datetime -- SQLite drops tzinfo on
        # read, so a Python-side comparison against a tz-aware `moment` would
        # raise. This mirrors `lease_next_task`'s portable idiom exactly.
        for _ in range(2):
            if record.state == "completed":
                return _to_value(record)
            if record.attempt_count >= max_attempts:
                raise ReviewAttemptExhaustedError(f"review {review_id} exhausted {max_attempts} attempt(s)")

            result = self._session.execute(
                update(ReviewAttemptRecord)
                .where(
                    ReviewAttemptRecord.review_id == review_id,
                    or_(
                        ReviewAttemptRecord.state != "running",
                        ReviewAttemptRecord.lease_expires_at <= moment,
                    ),
                )
                .values(
                    state="running",
                    lease_owner=lease_owner,
                    lease_expires_at=lease_until,
                    attempt_count=ReviewAttemptRecord.attempt_count + 1,
                    started_at=moment,
                    completed_at=None,
                    outcome=None,
                    action=None,
                    summary=None,
                    incomplete_reason=None,
                    counters=None,
                    findings=[],
                    error_type=None,
                    error_message=None,
                )
                # The already-loaded `record` sits in the identity map with a
                # naive `lease_expires_at` (SQLite drops tzinfo on read); the
                # default "evaluate" sync strategy would re-run this WHERE
                # clause in Python against it and hit the same naive/aware
                # TypeError. The row is re-read explicitly below instead.
                .execution_options(synchronize_session=False)
            )
            self._session.expire_all()
            if result.rowcount == 1:
                refreshed = self._session.get(ReviewAttemptRecord, review_id)
                assert refreshed is not None
                return _to_value(refreshed)
            # Lost the race (still running under an unexpired lease, or another
            # caller changed state/attempt_count first); refresh and retry once.
            refreshed = self._session.get(ReviewAttemptRecord, review_id)
            assert refreshed is not None
            record = refreshed

        raise ReviewAttemptConflictError(f"review {review_id} is already running under an unexpired lease")

    def renew(
        self,
        review_id: str,
        lease_owner: str,
        lease_seconds: int,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Heartbeat: push the lease's expiry out. False (no-op) if the lease was lost.

        Lets a long-running review keep a short, fast-reclaimable lease
        instead of needing one long enough to cover the slowest possible
        scan up front.
        """

        moment = now or datetime.now(UTC)
        result = self._session.execute(
            update(ReviewAttemptRecord)
            .where(
                ReviewAttemptRecord.review_id == review_id,
                ReviewAttemptRecord.lease_owner == lease_owner,
                ReviewAttemptRecord.state == "running",
            )
            .values(lease_expires_at=moment + timedelta(seconds=lease_seconds))
        )
        self._session.flush()
        return result.rowcount == 1

    def complete(
        self,
        review_id: str,
        lease_owner: str,
        *,
        outcome: str,
        action: str,
        summary: str,
        incomplete_reason: str | None,
        counters: dict[str, Any] | None,
        findings: list[Any],
    ) -> bool:
        """Idempotent: returns False (no-op) if the lease was lost in the meantime."""

        result = self._session.execute(
            update(ReviewAttemptRecord)
            .where(
                ReviewAttemptRecord.review_id == review_id,
                ReviewAttemptRecord.lease_owner == lease_owner,
                ReviewAttemptRecord.state == "running",
            )
            .values(
                state="completed",
                lease_owner=None,
                lease_expires_at=None,
                outcome=outcome,
                action=action,
                summary=summary,
                incomplete_reason=incomplete_reason,
                counters=counters,
                findings=list(findings),
                completed_at=datetime.now(UTC),
            )
        )
        self._session.flush()
        return result.rowcount == 1

    def update_policy(
        self,
        review_id: str,
        *,
        action: str,
        summary: str,
        counters: dict[str, Any] | None,
    ) -> bool:
        """Re-publishes a completed review's policy after triage; never touches running rows."""

        result = self._session.execute(
            update(ReviewAttemptRecord)
            .where(
                ReviewAttemptRecord.review_id == review_id,
                ReviewAttemptRecord.state == "completed",
            )
            .values(action=action, summary=summary, counters=counters)
        )
        self._session.flush()
        return result.rowcount == 1

    def fail(
        self,
        review_id: str,
        lease_owner: str,
        *,
        error_type: str,
        error_message: str,
    ) -> bool:
        """Idempotent: returns False (no-op) if the lease was lost in the meantime."""

        result = self._session.execute(
            update(ReviewAttemptRecord)
            .where(
                ReviewAttemptRecord.review_id == review_id,
                ReviewAttemptRecord.lease_owner == lease_owner,
                ReviewAttemptRecord.state == "running",
            )
            .values(
                state="failed",
                lease_owner=None,
                lease_expires_at=None,
                error_type=error_type,
                error_message=error_message,
                completed_at=datetime.now(UTC),
            )
        )
        self._session.flush()
        return result.rowcount == 1


def _to_value(record: ReviewAttemptRecord) -> ReviewAttempt:
    return ReviewAttempt(
        review_id=record.review_id,
        tenant_id=record.tenant_id,
        codebase_id=record.codebase_id,
        provider=record.provider,
        repository_id=record.repository_id,
        review_number=record.review_number,
        base_sha=record.base_sha,
        head_sha=record.head_sha,
        delivery_id=record.delivery_id,
        state=record.state,
        lease_owner=record.lease_owner,
        lease_expires_at=record.lease_expires_at,
        attempt_count=record.attempt_count,
        outcome=record.outcome,
        action=record.action,
        summary=record.summary,
        incomplete_reason=record.incomplete_reason,
        counters=dict(record.counters) if record.counters is not None else None,
        findings=tuple(record.findings),
        error_type=record.error_type,
        error_message=record.error_message,
        started_at=record.started_at,
        completed_at=record.completed_at,
    )


@contextmanager
def unit_of_work(factory: sessionmaker[Session], tenant_id: str) -> Iterator[ReviewAttemptRepository]:
    """Commit one domain operation or roll the complete transaction back."""

    session = factory()
    try:
        with session.begin():
            yield ReviewAttemptRepository(session, tenant_id)
    finally:
        session.close()
