"""Per-scope finding status: one row per finding per pull request and on the default branch."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .lifecycle import CARRIED_OUTCOMES, FIXED_OUTCOMES, KnownFinding, KnownOutcome
from .models import FindingOccurrenceRecord, PullRequestStateRecord

OPEN: Final = "open"
FIXED: Final = "fixed"
DUPLICATE: Final = "duplicate"  # same bug as another tracked finding
CLOSED: Final = "closed"   # PR closed without merging (Semgrep: "Removed")
MERGED: Final = "merged"   # PR merged; the finding is now tracked on the branch
BRANCH: Final = "branch"


def pr_scope(review_number: int) -> str:
    return f"pr:{review_number}"


@dataclass(frozen=True, slots=True)
class MergeOutcome:
    promoted: tuple[str, ...]       # open in the PR -> open on the branch
    resolved: tuple[str, ...]       # fixed in the PR -> fixed on the branch
    closed: tuple[str, ...]         # PR closed unmerged


class FindingOccurrenceRepository:
    def __init__(self, session: Session, tenant_id: str) -> None:
        self._session = session
        self._tenant_id = tenant_id

    def known(self, codebase_id: str, scope: str, *, statuses: Iterable[str] = (OPEN,)) -> tuple[KnownFinding, ...]:
        rows = self._rows(codebase_id, scope, statuses)
        kind = "branch" if scope == BRANCH else "pr"
        return tuple(
            KnownFinding(kind, dict(row.finding), row.last_seen_head or "")  # type: ignore[arg-type]
            for row in rows
            if row.finding
        )

    def has_scope(self, codebase_id: str, scope: str) -> bool:
        return self._session.scalar(
            select(FindingOccurrenceRecord.finding_id)
            .where(
                FindingOccurrenceRecord.tenant_id == self._tenant_id,
                FindingOccurrenceRecord.codebase_id == codebase_id,
                FindingOccurrenceRecord.scope == scope,
            )
            .limit(1)
        ) is not None

    def record_run(
        self,
        codebase_id: str,
        review_number: int,
        *,
        review_id: str,
        head: str,
        observed: Iterable[dict[str, Any]],
        outcomes: Iterable[KnownOutcome],
        run_started_at: datetime | None = None,
    ) -> bool:
        """Apply one completed run of a pull request to its finding statuses.

        Returns False, writing nothing, when the PR was closed or merged first: a run that
        finishes after the PR closed must not set its findings back to open.
        """

        if self._lock_pull_request(codebase_id, review_number).state != OPEN:
            return False
        scope = pr_scope(review_number)

        def current(record: FindingOccurrenceRecord) -> bool:
            # Runs can finish out of order (two quick pushes). Never let an older run
            # overwrite what a newer run already decided.
            if run_started_at is None:
                return True
            if record.last_run_at is not None and _aware(run_started_at) < _aware(record.last_run_at):
                return False
            record.last_run_at = run_started_at
            return True

        for finding in observed:
            record = self._get_or_new(codebase_id, scope, str(finding["finding_id"]), review_id)
            if not current(record):
                continue
            if record.status == FIXED:
                record.reopened_count = (record.reopened_count or 0) + 1  # fixed earlier, back now
            record.status = OPEN
            record.finding = dict(finding)
            record.last_seen_review_id = review_id
            record.last_seen_head = head
            record.fixed_review_id = record.fixed_head = record.fixed_reason = None

        for outcome in outcomes:
            existing = self._session.get(FindingOccurrenceRecord, (self._tenant_id, codebase_id, scope, outcome.finding_id))
            if existing is not None and not current(existing):
                continue
            if outcome.outcome == "duplicate":
                record = existing or self._get_or_new(codebase_id, scope, outcome.finding_id, review_id)
                if not record.finding:
                    record.finding = dict(outcome.finding)
                record.status = DUPLICATE
                record.fixed_reason = outcome.reason
                record.last_run_at = run_started_at
            elif outcome.outcome in FIXED_OUTCOMES:
                # A default-branch finding fixed in this PR is recorded on the PR, so
                # merging the PR is what marks it fixed on the branch.
                record = self._get_or_new(codebase_id, scope, outcome.finding_id, review_id)
                record.last_run_at = run_started_at
                if not record.finding:
                    record.finding = dict(outcome.finding)
                record.status = FIXED
                record.fixed_review_id = review_id
                record.fixed_head = head
                record.fixed_reason = outcome.reason
            elif outcome.outcome == "carried_unchanged" and outcome.scope == "pr":
                record = self._session.get(FindingOccurrenceRecord, (self._tenant_id, codebase_id, scope, outcome.finding_id))
                if record is not None and record.status == OPEN:
                    # Root-cause file is byte-identical, so the finding is verified present at this head too.
                    record.last_seen_review_id = review_id
                    record.last_seen_head = head
            elif outcome.outcome in CARRIED_OUTCOMES and outcome.scope == "pr":
                # Make sure a finding seeded from an older run has a row; never advance it.
                record = self._session.get(FindingOccurrenceRecord, (self._tenant_id, codebase_id, scope, outcome.finding_id))
                if record is None:
                    record = self._get_or_new(codebase_id, scope, outcome.finding_id, review_id)
                    record.finding = dict(outcome.finding)
                    record.last_seen_head = None
        self._session.flush()
        return True

    def close_pull_request(self, codebase_id: str, review_number: int, *, merged: bool, head: str | None) -> MergeOutcome:
        """PR merged: open findings move to the branch, fixes close branch findings. Closed: retire."""

        pull_request = self._lock_pull_request(codebase_id, review_number)
        if pull_request.state == MERGED or (pull_request.state == CLOSED and not merged):
            return MergeOutcome((), (), ())  # already applied
        pull_request.state = MERGED if merged else CLOSED
        scope = pr_scope(review_number)
        promoted: list[str] = []
        resolved: list[str] = []
        closed: list[str] = []
        for row in self._rows(codebase_id, scope, (OPEN, FIXED)):
            if not merged:
                if row.status == OPEN:
                    row.status = CLOSED
                    closed.append(row.finding_id)
                continue
            if row.status == OPEN:
                branch = self._get_or_new(codebase_id, BRANCH, row.finding_id, row.last_seen_review_id)
                branch.status = OPEN
                branch.finding = dict(row.finding)
                branch.last_seen_review_id = row.last_seen_review_id
                branch.last_seen_head = head or row.last_seen_head
                branch.fixed_review_id = branch.fixed_head = branch.fixed_reason = None
                row.status = MERGED
                promoted.append(row.finding_id)
            else:
                branch = self._session.get(FindingOccurrenceRecord, (self._tenant_id, codebase_id, BRANCH, row.finding_id))
                if branch is not None and branch.status == OPEN:
                    branch.status = FIXED
                    branch.fixed_review_id = row.fixed_review_id
                    branch.fixed_head = head or row.fixed_head
                    branch.fixed_reason = f"Fix merged from PR #{review_number}: {row.fixed_reason or ''}".strip()
                resolved.append(row.finding_id)
        self._session.flush()
        return MergeOutcome(tuple(promoted), tuple(resolved), tuple(closed))

    def reopen_pull_request(self, codebase_id: str, review_number: int) -> tuple[str, ...]:
        """A closed (not merged) PR reopened: its closed findings are open and tracked again."""

        pull_request = self._lock_pull_request(codebase_id, review_number)
        if pull_request.state != CLOSED:
            return ()
        pull_request.state = OPEN
        reopened: list[str] = []
        for row in self._rows(codebase_id, pr_scope(review_number), (CLOSED,)):
            row.status = OPEN
            reopened.append(row.finding_id)
        self._session.flush()
        return tuple(reopened)

    def pull_request_state(self, codebase_id: str, review_number: int) -> str:
        record = self._session.get(PullRequestStateRecord, (self._tenant_id, codebase_id, review_number))
        return record.state if record is not None else OPEN

    def _lock_pull_request(self, codebase_id: str, review_number: int) -> PullRequestStateRecord:
        """Get-or-create the PR's state row and lock it until this transaction ends.

        Runs and close events for one PR serialize on this row (PostgreSQL row lock), so
        a run that commits after a close sees the closed state and writes nothing.
        """

        key = {"tenant_id": self._tenant_id, "codebase_id": codebase_id, "review_number": review_number}
        if self._session.get(PullRequestStateRecord, tuple(key.values())) is None:
            try:
                with self._session.begin_nested():
                    self._session.add(PullRequestStateRecord(**key, state=OPEN))
                    self._session.flush()
            except IntegrityError:
                pass  # created concurrently; lock the existing row below
        record = self._session.scalars(
            select(PullRequestStateRecord)
            .filter_by(**key)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).one()
        return record

    def _rows(self, codebase_id: str, scope: str, statuses: Iterable[str]) -> list[FindingOccurrenceRecord]:
        return list(self._session.scalars(
            select(FindingOccurrenceRecord)
            .where(
                FindingOccurrenceRecord.tenant_id == self._tenant_id,
                FindingOccurrenceRecord.codebase_id == codebase_id,
                FindingOccurrenceRecord.scope == scope,
                FindingOccurrenceRecord.status.in_(tuple(statuses)),
            )
            .order_by(FindingOccurrenceRecord.updated_at.desc(), FindingOccurrenceRecord.finding_id)
        ))

    def _get_or_new(self, codebase_id: str, scope: str, finding_id: str, review_id: str | None) -> FindingOccurrenceRecord:
        key = (self._tenant_id, codebase_id, scope, finding_id)
        record = self._session.get(FindingOccurrenceRecord, key)
        if record is None:
            record = FindingOccurrenceRecord(
                tenant_id=self._tenant_id, codebase_id=codebase_id, scope=scope, finding_id=finding_id,
                status=OPEN, finding={}, first_seen_review_id=review_id, reopened_count=0,
            )
            self._session.add(record)
        return record


def _aware(value: datetime) -> datetime:
    # SQLite drops tzinfo on read; PostgreSQL keeps it.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@contextmanager
def unit_of_work(factory: sessionmaker[Session], tenant_id: str) -> Iterator[FindingOccurrenceRepository]:
    session = factory()
    try:
        with session.begin():
            yield FindingOccurrenceRepository(session, tenant_id)
    finally:
        session.close()
