"""Versioned, source-grounded investigation plans for Graphify-backed scans."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator

from .assets import load_json
from .redaction import redact_payload


class InvestigationContractError(ValueError):
    """Raised when an investigation violates the versioned runtime contract."""


@dataclass(frozen=True, slots=True)
class Investigation:
    investigation_id: str
    schema_version: int
    stable_key: str
    codebase_id: str
    snapshot_id: str
    target_ref: dict[str, Any]
    reason: str
    security_questions: tuple[str, ...]
    graph_refs: tuple[dict[str, Any], ...]
    source_windows: tuple[dict[str, Any], ...]
    context_dependencies: tuple[dict[str, Any], ...]
    coverage_notes: tuple[str, ...]
    prior_evidence_refs: tuple[str, ...]
    evidence_hash: str
    state: str = "planned"
    checkpoint_ref: str | None = None
    revision: int = 1

    def payload(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "schema_version": self.schema_version,
            "stable_key": self.stable_key,
            "codebase_id": self.codebase_id,
            "snapshot_id": self.snapshot_id,
            "target_ref": self.target_ref,
            "reason": self.reason,
            "security_questions": list(self.security_questions),
            "graph_refs": list(self.graph_refs),
            "source_windows": list(self.source_windows),
            "context_dependencies": list(self.context_dependencies),
            "coverage_notes": list(self.coverage_notes),
            "prior_evidence_refs": list(self.prior_evidence_refs),
            "evidence_hash": self.evidence_hash,
            "state": self.state,
            "checkpoint_ref": self.checkpoint_ref,
            "revision": self.revision,
        }


def investigation_evidence_hash(investigation: Investigation) -> str:
    """Hash source/graph evidence independently of the stable investigation identity."""
    value = {
        "snapshot_id": investigation.snapshot_id,
        "target_ref": investigation.target_ref,
        "graph_refs": investigation.graph_refs,
        "source_windows": investigation.source_windows,
        "context_dependencies": investigation.context_dependencies,
        "coverage_notes": investigation.coverage_notes,
        "prior_evidence_refs": investigation.prior_evidence_refs,
    }
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_investigation(
    *,
    stable_key: str,
    codebase_id: str,
    snapshot_id: str,
    target_ref: dict[str, Any],
    reason: str,
    security_questions: tuple[str, ...],
    graph_refs: tuple[dict[str, Any], ...],
    source_windows: tuple[dict[str, Any], ...],
    context_dependencies: tuple[dict[str, Any], ...],
    coverage_notes: tuple[str, ...] = (),
    prior_evidence_refs: tuple[str, ...] = (),
) -> Investigation:
    """Create a content-addressed investigation version from grounded evidence."""
    draft = Investigation(
        investigation_id="pending",
        schema_version=1,
        stable_key=stable_key,
        codebase_id=codebase_id,
        snapshot_id=snapshot_id,
        target_ref=target_ref,
        reason=reason,
        security_questions=security_questions,
        graph_refs=graph_refs,
        source_windows=source_windows,
        context_dependencies=context_dependencies,
        coverage_notes=coverage_notes,
        prior_evidence_refs=prior_evidence_refs,
        evidence_hash="0" * 64,
    )
    evidence_hash = investigation_evidence_hash(draft)
    identifier = hashlib.sha256(
        f"{codebase_id}\0{stable_key}\0{evidence_hash}".encode("utf-8")
    ).hexdigest()[:32]
    result = replace(draft, investigation_id=identifier, evidence_hash=evidence_hash)
    validate_investigation(result)
    return result


def validate_investigation(value: Investigation | dict[str, Any]) -> None:
    payload = value.payload() if isinstance(value, Investigation) else value
    errors = sorted(
        Draft202012Validator(load_json("schemas/investigation.json")).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "root"
        raise InvestigationContractError(f"investigation schema validation failed at {location}: {errors[0].message}")
    if redact_payload(payload) != payload:
        raise InvestigationContractError("investigation contains sensitive material that must be redacted")
    for window in payload.get("source_windows", []):
        path = PurePosixPath(window["path"])
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise InvestigationContractError("source window path must be a normalized repository-relative path")
        if window["end_line"] < window["start_line"]:
            raise InvestigationContractError("source window end_line precedes start_line")
    if isinstance(value, Investigation) and value.evidence_hash != investigation_evidence_hash(value):
        raise InvestigationContractError("investigation evidence_hash does not match its evidence")
