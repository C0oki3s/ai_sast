"""Versioned, source-grounded investigation plans for Graphify-backed scans."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Any, Mapping

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
    graph_snapshot_id: str = ""

    def payload(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "schema_version": self.schema_version,
            "stable_key": self.stable_key,
            "codebase_id": self.codebase_id,
            "snapshot_id": self.snapshot_id,
            **({"graph_snapshot_id": self.graph_snapshot_id} if self.graph_snapshot_id else {}),
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
    if investigation.graph_snapshot_id:
        value["graph_snapshot_id"] = investigation.graph_snapshot_id
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def planning_context_hash(
    repository_context: Mapping[str, Any],
    surface_context: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> str:
    """Fingerprint the business/security context that shapes model-authored plans."""
    value = redact_payload(
        {
            "repository_context": planner_repository_context(repository_context),
            "surface_context": list(surface_context),
        }
    )
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def planner_repository_context(repository_context: Mapping[str, Any]) -> dict[str, Any]:
    """Select the configured context fields supplied to graph planning prompts."""
    fields = load_json("runtime/code_intelligence.json")[
        "planner_repository_context_fields"
    ]
    return {field: repository_context[field] for field in fields if field in repository_context}


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
    graph_snapshot_id: str = "",
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
        graph_snapshot_id=graph_snapshot_id,
    )
    evidence_hash = investigation_evidence_hash(draft)
    identifier = hashlib.sha256(
        f"{codebase_id}\0{stable_key}\0{evidence_hash}".encode("utf-8")
    ).hexdigest()[:32]
    result = replace(draft, investigation_id=identifier, evidence_hash=evidence_hash)
    validate_investigation(result)
    return result


def bind_storage_snapshot(investigation: Investigation, snapshot_id: str) -> Investigation:
    """Bind graph evidence to its durable Code Scanning snapshot identity.

    Graphify's content/extractor identity remains in ``graph_snapshot_id`` and
    graph references. ORM foreign keys use the Code Scanning snapshot ID.
    """
    if not snapshot_id:
        raise InvestigationContractError("storage snapshot ID must not be empty")
    if investigation.snapshot_id == snapshot_id:
        return investigation
    draft = replace(investigation, snapshot_id=snapshot_id, evidence_hash="0" * 64)
    evidence_hash = investigation_evidence_hash(draft)
    identifier = hashlib.sha256(
        f"{draft.codebase_id}\0{draft.stable_key}\0{evidence_hash}".encode("utf-8")
    ).hexdigest()[:32]
    result = replace(draft, investigation_id=identifier, evidence_hash=evidence_hash)
    validate_investigation(result)
    return result


def rebase_investigation(
    investigation: Investigation,
    *,
    storage_snapshot_id: str,
    graph_snapshot_id: str,
) -> Investigation:
    """Carry a compatible prior plan onto a new immutable scan snapshot.

    Callers must first prove source-window and graph-neighborhood compatibility.
    This resets execution state: only the bounded planning result is reused; hunt
    and verification work must run again for the new revision.
    """
    if not storage_snapshot_id or not graph_snapshot_id:
        raise InvestigationContractError("rebase snapshot identities must not be empty")
    graph_refs = tuple(
        {
            **reference,
            **({"snapshot_id": graph_snapshot_id} if "snapshot_id" in reference else {}),
        }
        for reference in investigation.graph_refs
    )
    dependencies = tuple(
        {
            **dependency,
            **(
                {"key": graph_snapshot_id, "hash": graph_snapshot_id}
                if dependency.get("kind") == "graph_snapshot"
                else {}
            ),
        }
        for dependency in investigation.context_dependencies
    )
    draft = replace(
        investigation,
        snapshot_id=storage_snapshot_id,
        graph_snapshot_id=graph_snapshot_id,
        graph_refs=graph_refs,
        context_dependencies=dependencies,
        state="planned",
        checkpoint_ref=None,
        revision=1,
        evidence_hash="0" * 64,
    )
    evidence_hash = investigation_evidence_hash(draft)
    identifier = hashlib.sha256(
        f"{draft.codebase_id}\0{draft.stable_key}\0{evidence_hash}".encode("utf-8")
    ).hexdigest()[:32]
    result = replace(draft, investigation_id=identifier, evidence_hash=evidence_hash)
    validate_investigation(result)
    return result


def investigation_from_payload(value: dict[str, Any]) -> Investigation:
    """Restore and validate a serialized investigation from a durable store."""
    data = dict(value)
    for field in (
        "security_questions",
        "graph_refs",
        "source_windows",
        "context_dependencies",
        "coverage_notes",
        "prior_evidence_refs",
    ):
        data[field] = tuple(data[field])
    investigation = Investigation(**data)
    validate_investigation(investigation)
    return investigation


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
