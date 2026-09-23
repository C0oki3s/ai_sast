"""Performance regression guard for review-attempt lease semantics (priority item 12).

`claim`/`complete` are keyed entirely by the `review_id` primary key and the
`(state, lease_expires_at)` lease index, so the number of SQL statements they
issue for one review must stay constant regardless of how many unrelated
attempt rows already exist -- no full-table scan, no N+1 growth as delivery
volume increases. This asserts on statement counts rather than wall-clock
time to stay deterministic under CI load.
"""

from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from plaidnox_scm.attempts import unit_of_work
from plaidnox_scm.models import Base

_SEEDED_ATTEMPT_COUNT = 500
_MAX_STATEMENTS_PER_CLAIM_COMPLETE_CYCLE = 8


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _claim_kwargs(review_id: str) -> dict[str, object]:
    return {
        "provider": "github",
        "repository_id": 899377752,
        "review_number": 7,
        "base_sha": "a" * 40,
        "head_sha": review_id,
        "delivery_id": f"delivery-{review_id}",
        "lease_owner": "worker-1",
        "lease_seconds": 600,
        "max_attempts": 3,
    }


def test_claim_complete_cycle_issues_a_bounded_number_of_statements_regardless_of_table_size() -> None:
    engine = _engine()
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    with unit_of_work(factory, "tenant-perf") as repository:
        for index in range(_SEEDED_ATTEMPT_COUNT):
            review_id = f"review-seed-{index}"
            repository.claim(review_id, "codebase-seed", **_claim_kwargs(review_id))
            repository.complete(
                review_id,
                "worker-1",
                outcome="pass_no_verified_finding",
                action="allow",
                summary="ok",
                incomplete_reason=None,
                counters={"verified": 0},
                findings=[],
            )

    statement_count = 0

    def _count_statements(*_args: object, **_kwargs: object) -> None:
        nonlocal statement_count
        statement_count += 1

    event.listen(engine, "before_cursor_execute", _count_statements)
    try:
        with unit_of_work(factory, "tenant-perf") as repository:
            repository.claim("review-under-test", "codebase-under-test", **_claim_kwargs("review-under-test"))
            repository.complete(
                "review-under-test",
                "worker-1",
                outcome="pass_no_verified_finding",
                action="allow",
                summary="ok",
                incomplete_reason=None,
                counters={"verified": 0},
                findings=[],
            )
    finally:
        event.remove(engine, "before_cursor_execute", _count_statements)

    assert statement_count <= _MAX_STATEMENTS_PER_CLAIM_COMPLETE_CYCLE
