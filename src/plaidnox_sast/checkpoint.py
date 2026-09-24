"""Durable, resumable scan checkpoints.

Every expensive, individually-retryable unit of a scan (a discovery segment, a
candidate review, a variant or capability-chain sweep) is persisted the moment
it succeeds. A later run against the same snapshot replays completed units from
the store and only re-executes units that failed or never ran, so a scan can be
stopped at any point -- provider credit exhausted, crash, ^C -- and resumed with
new credits or a different model. Units move RUNNING -> COMPLETED, FAILED_RETRYABLE or FAILED_FINAL; only
completed units are ever replayed, and a unit still RUNNING when a new process opens the
store is recorded as abandoned (FAILED_RETRYABLE).

The store is bound to a scope (codebase, revision, tree hash, prompt version).
Models are deliberately not part of the scope: switching or falling back to a
different model must not discard finished work. A changed scope clears it.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .assets import load_json, load_text
from .models import Candidate, Evidence, Finding, FindingState, Severity


# Deterministic failures that replaying the identical request cannot fix. Everything
# else (rate limits, resets, timeouts, interrupts, exhausted credits) is retryable.
_FINAL_ERROR_TYPES = frozenset(
    {
        "BadRequestError",
        "AuthenticationError",
        "PermissionDeniedError",
        "NotFoundError",
        "UnprocessableEntityError",
        "AIResponseError",
    }
)


class CheckpointError(RuntimeError):
    """The checkpoint store could not be opened or written."""


class ScanCheckpoint:
    def __init__(self, path: Path, scope: str) -> None:
        self.path = path
        self.scope = hashlib.sha256(scope.encode("utf-8")).hexdigest()
        self.hits = 0
        self.writes = 0
        self.discarded = 0
        self._closed = False
        self._lock = threading.Lock()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_CREAT | os.O_APPEND, 0o600)
            os.close(descriptor)
            self._db = sqlite3.connect(path, check_same_thread=False)
            self._db.execute(load_text("sql/checkpoint/journal_mode.sql"))
            self._db.executescript(load_text("sql/checkpoint/schema.sql"))
            self._migrate_columns()
            self._restrict_permissions()
            row = self._db.execute(load_text("sql/checkpoint/select_scope.sql")).fetchone()
            if row is not None and row[0] != self.scope:
                self.discarded = self._db.execute(load_text("sql/checkpoint/count_units.sql")).fetchone()[0]
                self._db.execute(load_text("sql/checkpoint/delete_units.sql"))
            # This process owns the store: anything still "running" belongs to a dead one.
            self._db.execute(load_text("sql/checkpoint/abandon_running.sql"))
            self._db.execute(load_text("sql/checkpoint/upsert_scope.sql"), (self.scope,))
            self._db.commit()
            self._restrict_permissions()
        except sqlite3.Error as exc:
            raise CheckpointError(f"cannot open scan checkpoint {path}: {exc}") from exc

    def _migrate_columns(self) -> None:
        existing = {
            str(row[1])
            for row in self._db.execute(load_text("sql/checkpoint/table_info.sql"))
        }
        columns = [
            str(name)
            for name in load_json("sql/checkpoint/migrations/manifest.json")["columns"]
        ]
        for name in columns:
            if name not in existing:
                self._db.execute(load_text(f"sql/checkpoint/migrations/add_{name}.sql"))

    def _restrict_permissions(self) -> None:
        for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            if candidate.exists():
                os.chmod(candidate, 0o600)

    def get_record(self, stage: str, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(load_text("sql/checkpoint/select_record.sql"), (stage, key)).fetchone()
            if row is None or str(row[0]) != "completed":
                return None
            self.hits += 1
        return {
            "status": str(row[0]),
            "payload": json.loads(str(row[1])),
            "context": json.loads(str(row[2])),
            "context_hash": str(row[3]),
            "execution": json.loads(str(row[4])),
            "last_error_type": str(row[5]),
        }

    def get(self, stage: str, key: str) -> Any | None:
        record = self.get_record(stage, key)
        return record["payload"] if record is not None else None

    def begin(self, stage: str, key: str, context: Any, execution: Any) -> None:
        context_text = json.dumps(context, sort_keys=True, default=str)
        execution_text = json.dumps(execution, sort_keys=True, default=str)
        context_hash = hashlib.sha256(context_text.encode("utf-8")).hexdigest()
        try:
            with self._lock:
                self._db.execute(
                    load_text("sql/checkpoint/begin_unit.sql"),
                    (stage, key, context_text, context_hash, execution_text),
                )
                self._db.commit()
                self._restrict_permissions()
        except sqlite3.Error as exc:
            raise CheckpointError(f"cannot begin scan checkpoint unit in {self.path}: {exc}") from exc

    def fail(self, stage: str, key: str, error_type: str) -> None:
        try:
            with self._lock:
                self._db.execute(
                    load_text("sql/checkpoint/fail_unit.sql"),
                    (
                        "failed_final" if error_type in _FINAL_ERROR_TYPES else "failed_retryable",
                        error_type[:120],
                        stage,
                        key,
                    ),
                )
                self._db.commit()
                self._restrict_permissions()
        except sqlite3.Error as exc:
            raise CheckpointError(f"cannot update scan checkpoint failure in {self.path}: {exc}") from exc

    def complete(self, stage: str, key: str, payload: Any) -> None:
        text = json.dumps(payload, sort_keys=True, default=str)
        try:
            with self._lock:
                existing = self._db.execute(load_text("sql/checkpoint/unit_exists.sql"), (stage, key)).fetchone()
                if existing is None:
                    self._db.execute(
                        load_text("sql/checkpoint/insert_completed.sql"),
                        (stage, key, text),
                    )
                else:
                    self._db.execute(
                        load_text("sql/checkpoint/update_completed.sql"),
                        (text, stage, key),
                    )
                completed = self._db.execute(
                    load_text("sql/checkpoint/select_record.sql"), (stage, key)
                ).fetchone()
                if completed is not None:
                    execution = json.loads(str(completed[4]))
                    operation = str(execution.get("operation", ""))
                    work_identity = str(execution.get("work_identity", ""))
                    if operation and work_identity:
                        retryable = self._db.execute(
                            load_text("sql/checkpoint/select_retryable_by_stage.sql"),
                            (stage, key),
                        ).fetchall()
                        for old_key, old_execution_text in retryable:
                            try:
                                old_execution = json.loads(str(old_execution_text))
                            except json.JSONDecodeError:
                                continue
                            if (
                                old_execution.get("operation") == operation
                                and old_execution.get("work_identity") == work_identity
                            ):
                                self._db.execute(
                                    load_text("sql/checkpoint/supersede_unit.sql"),
                                    (stage, str(old_key)),
                                )
                self._db.commit()
                self._restrict_permissions()
                self.writes += 1
        except sqlite3.Error as exc:
            raise CheckpointError(f"cannot complete scan checkpoint unit in {self.path}: {exc}") from exc

    def put(self, stage: str, key: str, payload: Any) -> None:
        self.complete(stage, key, payload)

    def pending(self, stage: str, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(load_text("sql/checkpoint/select_pending.sql"), (stage, key)).fetchone()
        if row is None:
            return None
        return {
            "context": json.loads(str(row[0])),
            "context_hash": str(row[1]),
            "execution": json.loads(str(row[2])),
            "last_error_type": str(row[3]),
        }

    def counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._db.execute(load_text("sql/checkpoint/counts_by_stage.sql")).fetchall()
        return {stage: count for stage, count in rows}

    def status_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._db.execute(load_text("sql/checkpoint/counts_by_status.sql")).fetchall()
        return {str(status): int(count) for status, count in rows}

    def resume_cursor(self) -> dict[str, str]:
        """Return the last unfinished execution without exposing stored prompt context."""

        with self._lock:
            row = self._db.execute(load_text("sql/checkpoint/latest_pending.sql")).fetchone()
        if row is None:
            return {}
        execution = json.loads(str(row[2]))
        return {
            "stage": str(row[0]),
            "operation": str(execution.get("operation", "")),
            "last_error_type": str(row[1]),
        }

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True

    def __del__(self) -> None:
        try:
            self.close()
        except (AttributeError, sqlite3.Error):
            pass


def unit_key(*parts: object) -> str:
    text = json.dumps(parts, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def candidate_to_dict(candidate: Candidate) -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(candidate)


def candidate_from_dict(value: dict[str, Any]) -> Candidate:
    data = dict(value)
    data["evidence"] = Evidence(**data["evidence"])
    data["severity"] = Severity(data["severity"])
    return Candidate(**data)


def finding_from_dict(value: dict[str, Any]) -> Finding:
    data = dict(value)
    data["evidence"] = Evidence(**data["evidence"])
    data["severity"] = Severity(data["severity"])
    data["state"] = FindingState(data["state"])
    return Finding(**data)
