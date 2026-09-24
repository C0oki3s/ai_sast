"""Finding triage lifecycle: `!valid`/`!fp`/`!accepted_risk`/`!fixed` (Wave 12).

Implements only the persistence + state-machine half of
`docs/PRODUCT_WORKSTREAMS.md`'s "Triage commands" section. Webhook
verification, comment parsing, and GitHub-permission-based actor
authorization are the bot's job (`PlaidNox/plaidnox-github-bot`) -- this
module takes an already-parsed command and an already-authorized actor
identity, and only owns the deterministic state transition and its
append-only audit trail.

`!fixed` intentionally never reaches `resolved`: per the design doc,
"`RESOLVED` cannot be set only because somebody writes `!fixed`; it
requires fix validation against a new revision". `!fixed` only records
`fix_pending`. `record_fix_validation` is the only path to `resolved`, and
it is driven by a later review whose baseline classification independently
proved the finding gone (`RESOLVED`) -- or reopens a `fix_pending` finding
that the later review verified again.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .models import FindingTriageEventRecord, FindingTriageRecord

OPEN: Final = "open"
CONFIRMED: Final = "confirmed"
ACCEPTED_RISK: Final = "accepted_risk"
FALSE_POSITIVE: Final = "false_positive"
FIX_PENDING: Final = "fix_pending"
FIX_VALIDATING: Final = "fix_validating"
RESOLVED: Final = "resolved"

COMMAND_VALID: Final = "valid"
COMMAND_FP: Final = "fp"
COMMAND_ACCEPTED_RISK: Final = "accepted_risk"
COMMAND_FIXED: Final = "fixed"
COMMANDS: Final = (COMMAND_VALID, COMMAND_FP, COMMAND_ACCEPTED_RISK, COMMAND_FIXED)

# Scanner-originated transitions; never accepted from the triage HTTP contract.
SYSTEM_ACTOR: Final = "plaidnox"
EVENT_FIX_VALIDATED: Final = "fix_validated"
EVENT_FIX_REJECTED: Final = "fix_rejected"
# A human `false_positive` verdict is not overridden by a later rejection.
_RESOLVABLE_STATES: Final = frozenset({OPEN, CONFIRMED, ACCEPTED_RISK, FIX_PENDING, FIX_VALIDATING})
_REOPENABLE_STATES: Final = frozenset({FIX_PENDING, FIX_VALIDATING})

_REASON_REQUIRED: Final = frozenset({COMMAND_FP, COMMAND_ACCEPTED_RISK})

_TRANSITIONS: Final[dict[str, dict[str, str]]] = {
    COMMAND_VALID: {OPEN: CONFIRMED},
    COMMAND_FP: {OPEN: FALSE_POSITIVE, CONFIRMED: FALSE_POSITIVE},
    COMMAND_ACCEPTED_RISK: {OPEN: ACCEPTED_RISK, CONFIRMED: ACCEPTED_RISK},
    COMMAND_FIXED: {OPEN: FIX_PENDING, CONFIRMED: FIX_PENDING, ACCEPTED_RISK: FIX_PENDING},
}
# A command replayed once the finding already sits at (or past) its own
# target state is a no-op, not a conflict -- a retried triage webhook must
# not 409 just because it already landed.
_IDEMPOTENT_TARGETS: Final[dict[str, frozenset[str]]] = {
    COMMAND_VALID: frozenset({CONFIRMED}),
    COMMAND_FP: frozenset({FALSE_POSITIVE}),
    COMMAND_ACCEPTED_RISK: frozenset({ACCEPTED_RISK}),
    COMMAND_FIXED: frozenset({FIX_PENDING, FIX_VALIDATING, RESOLVED}),
}


class TriageError(RuntimeError):
    """Base error for triage command failures."""


class UnknownTriageCommandError(TriageError):
    """Raised for a command outside `COMMANDS` (the HTTP contract already restricts this)."""


class TriageReasonRequiredError(TriageError):
    """Raised when `!fp`/`!accepted_risk` is applied without a reason."""


class TriageConflictError(TriageError):
    """The requested command cannot apply from the finding's current state."""


@dataclass(frozen=True, slots=True)
class FindingTriage:
    tenant_id: str
    finding_id: str
    state: str
    actor: str | None
    reason: str | None
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class TriageEvent:
    finding_id: str
    review_id: str
    command: str
    previous_state: str
    new_state: str
    actor: str
    reason: str | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class TriageOutcome:
    triage: FindingTriage
    previous_state: str
    applied: bool  # False when the command was an idempotent no-op


class FindingTriageRepository:
    """Tenant-scoped triage state + append-only history for one codebase's findings."""

    def __init__(self, session: Session, tenant_id: str) -> None:
        self._session = session
        self._tenant_id = tenant_id

    def get(self, finding_id: str) -> FindingTriage | None:
        record = self._session.get(FindingTriageRecord, (self._tenant_id, finding_id))
        return _to_value(record) if record is not None else None

    def get_states(self, finding_ids: Iterable[str]) -> dict[str, str]:
        ids = sorted(set(finding_ids))
        if not ids:
            return {}
        rows = self._session.execute(
            select(FindingTriageRecord.finding_id, FindingTriageRecord.state).where(
                FindingTriageRecord.tenant_id == self._tenant_id,
                FindingTriageRecord.finding_id.in_(ids),
            )
        ).all()
        return {finding_id: state for finding_id, state in rows}

    def record_fix_validation(self, finding_id: str, review_id: str, *, resolved: bool) -> TriageOutcome | None:
        """Apply a later review's independent verdict; returns None when nothing changes."""

        record = self._session.get(FindingTriageRecord, (self._tenant_id, finding_id))
        current_state = record.state if record is not None else OPEN
        if resolved:
            if current_state not in _RESOLVABLE_STATES:
                return None
            new_state, event = RESOLVED, EVENT_FIX_VALIDATED
        else:
            if current_state not in _REOPENABLE_STATES:
                return None
            new_state, event = OPEN, EVENT_FIX_REJECTED
        return self._transition(record, finding_id, review_id, event, current_state, new_state, SYSTEM_ACTOR, None)

    def list_events(self, finding_id: str) -> tuple[TriageEvent, ...]:
        rows = self._session.scalars(
            select(FindingTriageEventRecord)
            .where(
                FindingTriageEventRecord.tenant_id == self._tenant_id,
                FindingTriageEventRecord.finding_id == finding_id,
            )
            .order_by(FindingTriageEventRecord.created_at, FindingTriageEventRecord.id)
        ).all()
        return tuple(_to_event(row) for row in rows)

    def apply_command(
        self,
        finding_id: str,
        review_id: str,
        command: str,
        *,
        actor: str,
        reason: str | None,
    ) -> TriageOutcome:
        if command not in COMMANDS:
            raise UnknownTriageCommandError(f"unsupported triage command: {command!r}")
        if not actor.strip():
            raise ValueError("actor is required")
        if command in _REASON_REQUIRED and not (reason or "").strip():
            raise TriageReasonRequiredError(f"triage command {command!r} requires a reason")

        record = self._session.get(FindingTriageRecord, (self._tenant_id, finding_id))
        current_state = record.state if record is not None else OPEN

        if current_state in _IDEMPOTENT_TARGETS.get(command, frozenset()):
            assert record is not None
            return TriageOutcome(triage=_to_value(record), previous_state=current_state, applied=False)

        table = _TRANSITIONS[command]
        if current_state not in table:
            raise TriageConflictError(
                f"cannot apply {command!r} to finding {finding_id} in state {current_state!r}"
            )
        return self._transition(
            record, finding_id, review_id, command, current_state, table[current_state], actor, reason
        )

    def _transition(
        self,
        record: FindingTriageRecord | None,
        finding_id: str,
        review_id: str,
        command: str,
        current_state: str,
        new_state: str,
        actor: str,
        reason: str | None,
    ) -> TriageOutcome:
        if record is None:
            record = FindingTriageRecord(tenant_id=self._tenant_id, finding_id=finding_id, state=new_state)
            self._session.add(record)
        else:
            record.state = new_state
        record.actor = actor
        record.reason = reason
        self._session.flush()

        self._session.add(
            FindingTriageEventRecord(
                tenant_id=self._tenant_id,
                finding_id=finding_id,
                review_id=review_id,
                command=command,
                previous_state=current_state,
                new_state=new_state,
                actor=actor,
                reason=reason,
            )
        )
        self._session.flush()
        return TriageOutcome(triage=_to_value(record), previous_state=current_state, applied=True)


def _to_value(record: FindingTriageRecord) -> FindingTriage:
    return FindingTriage(
        tenant_id=record.tenant_id,
        finding_id=record.finding_id,
        state=record.state,
        actor=record.actor,
        reason=record.reason,
        updated_at=record.updated_at,
    )


def _to_event(record: FindingTriageEventRecord) -> TriageEvent:
    return TriageEvent(
        finding_id=record.finding_id,
        review_id=record.review_id,
        command=record.command,
        previous_state=record.previous_state,
        new_state=record.new_state,
        actor=record.actor,
        reason=record.reason,
        created_at=record.created_at,
    )


@contextmanager
def unit_of_work(factory: sessionmaker[Session], tenant_id: str) -> Iterator[FindingTriageRepository]:
    """Commit one domain operation or roll the complete transaction back."""

    session = factory()
    try:
        with session.begin():
            yield FindingTriageRepository(session, tenant_id)
    finally:
        session.close()
