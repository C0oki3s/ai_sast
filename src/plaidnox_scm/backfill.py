"""Dry-run-first repair of code windows in old, completed SCM review records."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from plaidnox_sast.redaction import redact

from .api_models import ReviewFinding
from .evidence import EvidenceRole
from .models import ReviewAttemptRecord
from .snapshots import SnapshotError, read_blob, resolve_revision
from .trace import _NODE_KIND, _ROLE_LAYER, _code_window, _label

MAX_FILE_BYTES = 2_000_000
REBUILT_GAP = "Trace rebuilt from stored locations; transitions were not machine-checked."
BlobReader = Callable[[Path, str, str], str | None]


@dataclass(slots=True)
class BackfillReport:
    attempts_scanned: int = 0
    attempts_updated: int = 0
    findings_updated: int = 0
    nodes_filled: int = 0
    traces_rebuilt: int = 0
    snippets_filled: int = 0
    missing_snapshots: int = 0
    unreadable_files: int = 0
    invalid_after_update: int = 0
    review_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {item.name: getattr(self, item.name) for item in fields(self)}


@dataclass(slots=True)
class _Changes:
    nodes: int = 0
    trace: int = 0
    snippet: int = 0


def backfill_trace_code(
    session_factory: sessionmaker[Session], repository_root: Path, *, apply: bool = False,
    tenant_id: str | None = None, limit: int | None = None, read: BlobReader | None = None,
) -> BackfillReport:
    """Read the exact reviewed commit. Never invent links or semantic explanations."""
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    report = BackfillReport()
    reader = read or _read_from_mirror
    root = repository_root.resolve()
    with session_factory.begin() as session:
        statement = (select(ReviewAttemptRecord)
                     .where(ReviewAttemptRecord.state == "completed")
                     .order_by(ReviewAttemptRecord.started_at.desc()))
        if tenant_id:
            statement = statement.where(ReviewAttemptRecord.tenant_id == tenant_id)
        if limit:
            statement = statement.limit(limit)
        for record in session.scalars(statement):
            if not record.findings:
                continue
            report.attempts_scanned += 1
            mirror = (root / record.provider / str(record.repository_id)).resolve()
            if root not in mirror.parents or not mirror.is_dir() or not _has_commit(mirror, record.head_sha):
                report.missing_snapshots += 1
                continue
            cache: dict[str, list[str] | None] = {}

            def lines_of(path: str) -> list[str] | None:
                if path not in cache:
                    source = reader(mirror, record.head_sha, path)
                    cache[path] = source.splitlines() if source is not None else None
                    if source is None:
                        report.unreadable_files += 1
                return cache[path]

            updated: list[Any] = []
            changed = False
            for finding in record.findings:
                if not isinstance(finding, dict):
                    updated.append(finding)
                    continue
                proposed, counts = _backfill_finding(finding, lines_of)
                if proposed is None:
                    updated.append(finding)
                    continue
                try:
                    ReviewFinding.model_validate(proposed)
                except ValidationError:
                    report.invalid_after_update += 1
                    updated.append(finding)
                    continue
                updated.append(proposed)
                report.findings_updated += 1
                report.nodes_filled += counts.nodes
                report.traces_rebuilt += counts.trace
                report.snippets_filled += counts.snippet
                changed = True
            if changed:
                report.attempts_updated += 1
                report.review_ids.append(record.review_id)
                if apply:
                    record.findings = updated
    return report


def _has_commit(mirror: Path, revision: str) -> bool:
    try:
        return resolve_revision(mirror, revision).lower() == revision.lower()
    except SnapshotError:
        return False


def _backfill_finding(
    finding: dict[str, Any], lines_of: Callable[[str], list[str] | None]
) -> tuple[dict[str, Any] | None, _Changes]:
    new = dict(finding)
    counts = _Changes()
    if not isinstance(new.get("vulnerable_snippet"), dict):
        snippet = _snippet(new, lines_of)
        if snippet:
            new["vulnerable_snippet"] = snippet
            counts.snippet = 1
    trace = new.get("evidence_trace")
    if isinstance(trace, dict) and isinstance(trace.get("nodes"), list) and trace["nodes"]:
        nodes = []
        for node in trace["nodes"]:
            filled = _fill_node(node, lines_of) if isinstance(node, dict) else None
            if filled:
                counts.nodes += 1
            nodes.append(filled or node)
        if counts.nodes:
            new["evidence_trace"] = {**trace, "nodes": nodes}
    else:
        rebuilt = _trace_from_evidence(new, lines_of)
        if rebuilt:
            new["evidence_trace"] = rebuilt
            counts.trace = 1
            counts.nodes = len(rebuilt["nodes"])
    return (new if counts.nodes or counts.trace or counts.snippet else None), counts


def _window(lines: list[str] | None, start: int, end: int) -> tuple[int, int, str] | None:
    if not lines or start < 1 or start > len(lines) or end < start:
        return None
    first, last, code = _code_window(lines, start, min(end, len(lines)))
    return (first, last, code) if code else None


def _fill_node(node: dict[str, Any], lines_of: Callable[[str], list[str] | None]) -> dict[str, Any] | None:
    if node.get("code") or not node.get("path") or not node.get("start_line"):
        return None
    start = int(node["start_line"])
    window = _window(lines_of(str(node["path"])), start, int(node.get("end_line") or start))
    if not window:
        return None
    first, last, code = window
    return {**node, "code": code, "code_start_line": first, "code_end_line": last}


def _snippet(finding: dict[str, Any], lines_of: Callable[[str], list[str] | None]) -> dict[str, Any] | None:
    path = str(finding.get("root_cause_path") or "")
    start = int(finding.get("root_cause_start_line") or 0)
    lines = lines_of(path) if path and start else None
    if not lines or start > len(lines):
        return None
    end = min(len(lines), max(start, int(finding.get("root_cause_end_line") or start)))
    return {"path": path, "start_line": start, "end_line": end,
            "code": redact("\n".join(lines[start - 1:end])[:4000])}


def _trace_from_evidence(
    finding: dict[str, Any], lines_of: Callable[[str], list[str] | None]
) -> dict[str, Any] | None:
    nodes: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, int]] = set()
    for item in finding.get("evidence") or ():
        if not isinstance(item, dict):
            continue
        try:
            role = EvidenceRole(str(item.get("role") or ""))
        except ValueError:
            continue
        if role not in _ROLE_LAYER or not item.get("path") or not item.get("start_line"):
            continue
        path = str(item["path"])
        start = int(item["start_line"])
        end = int(item.get("end_line") or start)
        key = (role.value, path, start, end)
        if key in seen:
            continue
        lines = lines_of(path)
        window = _window(lines, start, end)
        if not window or lines is None:
            continue
        seen.add(key)
        first, last, code = window
        summary = redact(str(item.get("summary") or "").strip())
        digest = hashlib.sha256("|".join(map(str, (*key, summary))).encode()).hexdigest()[:16]
        nodes.append({
            "node_id": f"trace_{digest}", "role": role.value, "kind": _NODE_KIND[role],
            "path": path, "start_line": start, "end_line": end,
            "symbol": str(finding.get("root_cause_symbol") or path) if role == EvidenceRole.ROOT_CAUSE_CHANGED_CODE else path,
            "expression": redact("\n".join(lines[start - 1:end])[:1200]),
            "label": _label(role), "summary": summary,
            "provenance": redact(str(item.get("source") or "stored_evidence")),
            "code": code, "code_start_line": first, "code_end_line": last,
        })
    if not nodes:
        return None
    nodes.sort(key=lambda node: _ROLE_LAYER[EvidenceRole(node["role"])])
    first_layer = _ROLE_LAYER[EvidenceRole(nodes[0]["role"])]
    last_layer = _ROLE_LAYER[EvidenceRole(nodes[-1]["role"])]
    capabilities = finding.get("capabilities") or []
    return {
        "trace_type": "taint_and_trust", "step_count": len(nodes),
        "file_count": len({node["path"] for node in nodes}), "nodes": nodes, "edges": [],
        "entry_nodes": [node["node_id"] for node in nodes if _ROLE_LAYER[EvidenceRole(node["role"])] == first_layer],
        "terminal_nodes": [node["node_id"] for node in nodes if _ROLE_LAYER[EvidenceRole(node["role"])] == last_layer],
        "attack_path": str(finding.get("attack_path") or ""),
        "gained_capability": str(capabilities[0]) if capabilities else "",
        "complete": False, "evidence_gaps": [REBUILT_GAP],
    }


def _read_from_mirror(mirror: Path, revision: str, path: str) -> str | None:
    try:
        return read_blob(mirror, revision, path, MAX_FILE_BYTES)
    except SnapshotError:
        return None
