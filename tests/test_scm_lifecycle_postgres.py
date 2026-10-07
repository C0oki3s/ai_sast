"""Concurrency of finding-status writes on real PostgreSQL (opt-in).

Set PLAIDNOX_TEST_POSTGRES_URL (e.g. postgresql+psycopg://postgres@127.0.0.1:5432/scm)
to run. SQLite has no row locks, so the close/review race can only be shown here.
"""

from __future__ import annotations

import os
import threading
import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from plaidnox_scm import occurrences
from plaidnox_scm.models import Base

URL = os.environ.get("PLAIDNOX_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not URL, reason="PLAIDNOX_TEST_POSTGRES_URL not set")

TENANT = "tenant-pg"
CODEBASE = "github:repository:1"


@pytest.fixture()
def factory():
    engine = create_engine(URL)
    Base.metadata.drop_all(engine, tables=[Base.metadata.tables["scm_finding_occurrences"],
                                           Base.metadata.tables["scm_pull_request_states"]])
    Base.metadata.create_all(engine, tables=[Base.metadata.tables["scm_finding_occurrences"],
                                             Base.metadata.tables["scm_pull_request_states"]])
    yield sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
    engine.dispose()


def _finding(finding_id: str) -> dict:
    return {"finding_id": finding_id, "root_cause_fingerprint": f"root-{finding_id}", "root_cause_path": "a.py"}


def _status(factory, scope: str, finding_id: str) -> str | None:
    with factory() as session:
        return session.execute(
            text("SELECT status FROM scm_finding_occurrences WHERE scope = :s AND finding_id = :f"),
            {"s": scope, "f": finding_id},
        ).scalar()


def test_a_review_write_racing_a_close_waits_for_it_and_then_writes_nothing(factory) -> None:
    with occurrences.unit_of_work(factory, TENANT) as repository:
        repository.record_run(CODEBASE, 7, review_id="r1", head="h1", observed=[_finding("A")], outcomes=())

    closing = factory()
    closing.begin()
    occurrences.FindingOccurrenceRepository(closing, TENANT).close_pull_request(CODEBASE, 7, merged=False, head=None)
    # The close is applied but not committed yet; a late review now tries to write.

    result: dict[str, object] = {}

    def late_review() -> None:
        with occurrences.unit_of_work(factory, TENANT) as repository:
            result["applied"] = repository.record_run(
                CODEBASE, 7, review_id="r2", head="h2", observed=[_finding("A"), _finding("B")], outcomes=(),
            )

    worker = threading.Thread(target=late_review)
    worker.start()
    time.sleep(0.5)
    assert worker.is_alive(), "the review write must wait for the in-flight close"
    closing.commit()
    closing.close()
    worker.join(timeout=10)

    assert result == {"applied": False}
    assert _status(factory, "pr:7", "A") == "closed"
    assert _status(factory, "pr:7", "B") is None


def test_a_close_racing_a_review_write_applies_after_it(factory) -> None:
    with occurrences.unit_of_work(factory, TENANT) as repository:
        repository.record_run(CODEBASE, 7, review_id="r1", head="h1", observed=[_finding("A")], outcomes=())

    reviewing = factory()
    reviewing.begin()
    occurrences.FindingOccurrenceRepository(reviewing, TENANT).record_run(
        CODEBASE, 7, review_id="r2", head="h2", observed=[_finding("A"), _finding("B")], outcomes=(),
    )

    def close() -> None:
        with occurrences.unit_of_work(factory, TENANT) as repository:
            repository.close_pull_request(CODEBASE, 7, merged=False, head=None)

    worker = threading.Thread(target=close)
    worker.start()
    time.sleep(0.5)
    assert worker.is_alive(), "the close must wait for the in-flight review write"
    reviewing.commit()
    reviewing.close()
    worker.join(timeout=10)

    assert (_status(factory, "pr:7", "A"), _status(factory, "pr:7", "B")) == ("closed", "closed")
