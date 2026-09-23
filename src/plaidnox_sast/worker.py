"""Leased production worker for immutable local Code Scanning snapshots."""

from __future__ import annotations

import ctypes
import json
import os
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from sqlalchemy.orm import Session, sessionmaker

from .assets import load_json
from .config import load_local_project_config
from .graph import build_structural_graph
from .persistence.repositories import (
    ProductionControlError,
    ScanJobValue,
    snapshot_tree_hash,
    unit_of_work,
)
from .redaction import redact


class WorkerConfigurationError(RuntimeError):
    pass


class WorkerExecutionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class WorkerPaths:
    snapshot_root: Path
    output_root: Path

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> WorkerPaths:
        values = environment if environment is not None else os.environ
        policy = load_json("runtime/production_controls.json")["worker"]
        snapshot = values.get(str(policy["snapshot_root_environment_variable"]), "").strip()
        output = values.get(str(policy["output_root_environment_variable"]), "").strip()
        if not snapshot or not output:
            raise WorkerConfigurationError("snapshot and output roots are required for a production worker")
        snapshot_root = Path(snapshot).resolve()
        output_root = Path(output).resolve()
        if not snapshot_root.is_dir() or not output_root.is_dir():
            raise WorkerConfigurationError("snapshot and output roots must exist and be directories")
        return cls(snapshot_root, output_root)

    def resolve_snapshot(self, uri: str) -> Path:
        path = _file_uri_path(uri)
        _require_within(path, self.snapshot_root, "snapshot")
        if not path.is_dir():
            raise WorkerExecutionError("snapshot URI does not identify a directory")
        for item in path.rglob("*"):
            if item.is_symlink():
                raise WorkerExecutionError("snapshot contains a symbolic link")
        return path

    def resolve_output(self, uri: str) -> Path:
        path = _file_uri_path(uri)
        _require_within(path, self.output_root, "output")
        path.mkdir(parents=True, exist_ok=True)
        return path


class LocalScanExecutor:
    def __init__(self, paths: WorkerPaths, *, timeout_seconds: int, jev: bool = True) -> None:
        self.paths = paths
        self.timeout_seconds = timeout_seconds
        self.jev = jev

    def __call__(self, job: ScanJobValue) -> dict[str, Any]:
        snapshot = self.paths.resolve_snapshot(job.snapshot_uri)
        output = self.paths.resolve_output(job.output_uri)
        expected_tree_hash = str(job.job_data.get("snapshot_tree_hash", ""))
        if not expected_tree_hash:
            raise WorkerExecutionError("snapshot_tree_hash_missing")
        config = load_local_project_config(snapshot)
        actual_tree_hash = snapshot_tree_hash(
            build_structural_graph(snapshot, exclude=config.exclude, max_file_bytes=config.max_file_bytes)
        )
        if actual_tree_hash != expected_tree_hash:
            raise WorkerExecutionError("immutable_snapshot_hash_mismatch")
        command = [
            sys.executable,
            "-m",
            "plaidnox_sast.cli",
            "scan-local",
            str(snapshot),
            "--codebase",
            job.codebase_external_key,
            "--revision",
            job.revision,
            "--output",
            str(output),
            "--tenant-id",
            job.tenant_id,
        ]
        if not self.jev:
            command.append("--no-jev")
        completed = subprocess.run(  # noqa: S603 - trusted scanner executable and fixed argument vector
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            env=os.environ.copy(),
            preexec_fn=_die_with_parent_preexec(),
        )
        if completed.returncode != 0:
            # The failure code stays bounded and content-free; the operator log
            # gets a redacted stderr tail so the cause is actually diagnosable.
            tail = redact((completed.stderr or "")[-2000:])
            print(json.dumps({"event": "scanner_failed", "job_id": job.job_id, "stderr_tail": tail}), file=sys.stderr)
            raise WorkerExecutionError(f"scanner_exit_{completed.returncode}")
        report_path = output / "report.json"
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkerExecutionError("scanner_report_missing_or_invalid") from exc
        findings = list(report.get("findings") or [])
        return {
            "codebase": str(report.get("codebase", job.codebase_external_key)),
            "revision": str(report.get("revision", job.revision)),
            "decision": str((report.get("policy") or {}).get("decision", "unknown")),
            "findings": len(findings),
            "report_uri": (output / "report.json").as_uri(),
        }


class ScanWorker:
    def __init__(
        self,
        factory: sessionmaker[Session],
        tenant_id: str,
        worker_id: str,
        executor: Callable[[ScanJobValue], dict[str, Any]],
        *,
        lease_seconds: int,
        heartbeat_seconds: int,
    ) -> None:
        if not tenant_id.strip() or not worker_id.strip():
            raise WorkerConfigurationError("tenant_id and worker_id are required")
        if lease_seconds <= 0 or heartbeat_seconds <= 0 or heartbeat_seconds >= lease_seconds:
            raise WorkerConfigurationError("heartbeat must be positive and shorter than the lease")
        self.factory = factory
        self.tenant_id = tenant_id
        self.worker_id = worker_id
        self.executor = executor
        self.lease_seconds = lease_seconds
        self.heartbeat_seconds = heartbeat_seconds

    def run_once(self) -> ScanJobValue | None:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            job = repository.lease_next_scan_job(self.worker_id, self.lease_seconds)
        if job is None:
            return None
        heartbeat = _LeaseHeartbeat(
            self.factory,
            self.tenant_id,
            job.job_id,
            self.worker_id,
            self.lease_seconds,
            self.heartbeat_seconds,
        )
        heartbeat.start()
        try:
            summary = self.executor(job)
            if heartbeat.lost:
                raise WorkerExecutionError("scan_job_lease_lost")
            with unit_of_work(self.factory, self.tenant_id) as repository:
                if not repository.complete_scan_job(job.job_id, self.worker_id, summary):
                    raise WorkerExecutionError("scan_job_completion_rejected")
                repository.append_audit_event(
                    f"audit-{job.job_id}-{job.attempt_count}-completed",
                    "scan_job_completed",
                    "worker",
                    self.worker_id,
                    "scan_job",
                    job.job_id,
                    "success",
                    summary,
                )
        except Exception as exc:
            failure_code = _failure_code(exc)
            with unit_of_work(self.factory, self.tenant_id) as repository:
                repository.fail_scan_job(job.job_id, self.worker_id, failure_code)
                repository.append_audit_event(
                    f"audit-{job.job_id}-{job.attempt_count}-failed",
                    "scan_job_failed",
                    "worker",
                    self.worker_id,
                    "scan_job",
                    job.job_id,
                    "failure",
                    {"failure_code": failure_code},
                )
            raise
        finally:
            heartbeat.stop()
        return job


class _LeaseHeartbeat:
    def __init__(
        self,
        factory: sessionmaker[Session],
        tenant_id: str,
        job_id: str,
        worker_id: str,
        lease_seconds: int,
        interval_seconds: int,
    ) -> None:
        self.factory = factory
        self.tenant_id = tenant_id
        self.job_id = job_id
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.interval_seconds = interval_seconds
        self.lost = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"lease-{job_id}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1, self.interval_seconds + 1))

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                with unit_of_work(self.factory, self.tenant_id) as repository:
                    renewed = repository.renew_scan_job_lease(
                        self.job_id,
                        self.worker_id,
                        self.lease_seconds,
                    )
                if not renewed:
                    self.lost = True
                    return
            except Exception:  # a failed heartbeat cannot be silently treated as ownership
                self.lost = True
                return


_PR_SET_PDEATHSIG = 1


def _die_with_parent_preexec() -> Callable[[], None] | None:
    """Kill the scanner if this worker dies (kill -9, OOM) instead of orphaning it.

    An orphaned scanner keeps spending model budget and writes a report into
    the job's output directory after the lease has passed to another worker.
    libc is resolved here, in the parent, so the forked child only makes the
    prctl syscall.
    """

    if not sys.platform.startswith("linux"):
        return None
    try:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    except (OSError, AttributeError):
        return None
    parent = os.getpid()

    def preexec() -> None:
        prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        if os.getppid() != parent:  # parent already died before prctl took effect
            os._exit(1)

    return preexec


def _file_uri_path(uri: str) -> Path:
    parsed = urlparse(uri)
    if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
        raise WorkerExecutionError("worker accepts only local file:// artifact URIs")
    return Path(unquote(parsed.path)).resolve()


def _require_within(path: Path, root: Path, label: str) -> None:
    if path != root and root not in path.parents:
        raise WorkerExecutionError(f"{label} path escapes its configured root")


def _failure_code(exc: Exception) -> str:
    if isinstance(exc, (WorkerExecutionError, ProductionControlError)):
        value = str(exc)
        if value and value.replace("_", "").isalnum():
            return value[:128]
    return type(exc).__name__[:128]
