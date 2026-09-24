"""Versioned contracts for bounded, graph-grounded security worksets.

These contracts do not make vulnerability decisions. They carry stable security
surface identity, exact source evidence, observed facts, and unresolved edges.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping

from .assets import load_json
from .redaction import redact


class SecurityWorksetContractError(ValueError):
    """A workset contract would lose or misidentify required evidence."""


class SecuritySliceTooLarge(SecurityWorksetContractError):
    """One source slice exceeds the configured maximum and cannot be split safely."""


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, Mapping):
        return {str(key): _redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(item) for item in value]
    return value


def _safe_relative_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    parsed = PurePosixPath(normalized)
    if (
        not normalized
        or "\0" in normalized
        or parsed.is_absolute()
        or re.match(r"^[a-zA-Z]:/", normalized)
        or ".." in parsed.parts
    ):
        raise SecurityWorksetContractError(
            "source evidence path must be a safe repository-relative path"
        )
    return parsed.as_posix()


@dataclass(frozen=True, slots=True)
class SourceLocation:
    path: str
    start_line: int
    end_line: int
    content_hash: str
    excerpt: str = ""
    symbol_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _safe_relative_path(self.path))
        if self.start_line < 1 or self.end_line < self.start_line:
            raise SecurityWorksetContractError("source evidence line range is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.content_hash):
            raise SecurityWorksetContractError(
                "source evidence requires a SHA-256 content hash"
            )
        object.__setattr__(self, "excerpt", redact(self.excerpt))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "content_hash": self.content_hash,
            "excerpt": self.excerpt,
            "symbol_id": self.symbol_id,
        }


@dataclass(frozen=True, slots=True)
class SecuritySlice:
    """Bounded evidence packet; partiality is explicit and never inferred as safety."""

    locations: tuple[SourceLocation, ...]
    facts: tuple[dict[str, Any], ...] = ()
    unresolved_edge_ids: tuple[str, ...] = ()
    omitted_fact_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.locations:
            raise SecurityWorksetContractError(
                "security slice must retain at least one source location"
            )
        if len(
            {(item.path, item.start_line, item.end_line) for item in self.locations}
        ) != len(self.locations):
            raise SecurityWorksetContractError(
                "security slice contains duplicate source locations"
            )
        object.__setattr__(
            self, "facts", tuple(_redact_value(item) for item in self.facts)
        )

    @property
    def slice_id(self) -> str:
        return _digest(
            {
                "locations": [item.to_dict() for item in self.locations],
                "facts": self.facts,
                "unresolved_edge_ids": sorted(set(self.unresolved_edge_ids)),
                "omitted_fact_ids": sorted(set(self.omitted_fact_ids)),
            }
        )[:32]

    @property
    def complete(self) -> bool:
        return not self.unresolved_edge_ids and not self.omitted_fact_ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "slice_id": self.slice_id,
            "locations": [item.to_dict() for item in self.locations],
            "facts": list(self.facts),
            "unresolved_edge_ids": sorted(set(self.unresolved_edge_ids)),
            "omitted_fact_ids": sorted(set(self.omitted_fact_ids)),
            "complete": self.complete,
        }


@dataclass(frozen=True, slots=True)
class SecuritySummary:
    """Content-versioned structural facts for one stable symbol identity."""

    symbol_id: str
    content_hash: str
    facts: tuple[dict[str, Any], ...] = ()
    dependency_symbol_ids: tuple[str, ...] = ()
    unresolved_relationship_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.symbol_id.strip():
            raise SecurityWorksetContractError(
                "security summary requires a stable symbol identity"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", self.content_hash):
            raise SecurityWorksetContractError(
                "security summary requires a SHA-256 content hash"
            )
        if self.symbol_id in self.dependency_symbol_ids:
            raise SecurityWorksetContractError(
                "security summary cannot depend on itself"
            )
        object.__setattr__(
            self, "facts", tuple(_redact_value(item) for item in self.facts)
        )

    @property
    def complete(self) -> bool:
        return not self.unresolved_relationship_ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol_id": self.symbol_id,
            "content_hash": self.content_hash,
            "facts": list(self.facts),
            "dependency_symbol_ids": sorted(set(self.dependency_symbol_ids)),
            "unresolved_relationship_ids": sorted(
                set(self.unresolved_relationship_ids)
            ),
            "complete": self.complete,
        }


@dataclass(frozen=True, slots=True)
class SecurityWorkset:
    """Stable security-surface identity with one or more source/IR evidence slices."""

    surface_type: str
    surface_id: str
    slices: tuple[SecuritySlice, ...]
    obligation_ids: tuple[str, ...] = ()
    unresolved_edge_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.surface_type.strip() or not self.surface_id.strip():
            raise SecurityWorksetContractError(
                "security workset requires a typed, stable surface identity"
            )
        if not self.slices:
            raise SecurityWorksetContractError(
                "security workset must contain at least one evidence slice"
            )
        if len({item.slice_id for item in self.slices}) != len(self.slices):
            raise SecurityWorksetContractError(
                "security workset contains duplicate evidence slices"
            )
        object.__setattr__(self, "metadata", _redact_value(self.metadata))

    @property
    def workset_id(self) -> str:
        # Content deliberately does not participate: edits invalidate evidence,
        # not the identity of the route/job/boundary being reviewed.
        return _digest(
            {"surface_type": self.surface_type, "surface_id": self.surface_id}
        )[:32]

    @property
    def evidence_hash(self) -> str:
        return _digest(
            {
                "slices": [item.slice_id for item in self.slices],
                "obligations": sorted(set(self.obligation_ids)),
                "unresolved_edges": sorted(set(self.unresolved_edge_ids)),
            }
        )

    @property
    def complete(self) -> bool:
        return not self.unresolved_edge_ids and all(
            item.complete for item in self.slices
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "workset_id": self.workset_id,
            "surface_type": self.surface_type,
            "surface_id": self.surface_id,
            "evidence_hash": self.evidence_hash,
            "slices": [item.to_dict() for item in self.slices],
            "obligation_ids": sorted(set(self.obligation_ids)),
            "unresolved_edge_ids": sorted(set(self.unresolved_edge_ids)),
            "complete": self.complete,
            "metadata": dict(self.metadata),
        }

    def batches(self, policy: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        """Partition all evidence under configured limits without dropping slices."""
        settings = dict(policy or load_json("runtime/security_worksets.json"))
        max_slices = int(settings["maximum_slices_per_batch"])
        max_characters = int(settings["maximum_batch_characters"])
        if max_slices < 1 or max_characters < 1:
            raise SecurityWorksetContractError("workset batch limits must be positive")

        serialized = [
            (item, json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True))
            for item in self.slices
        ]
        groups: list[list[tuple[SecuritySlice, str]]] = []
        current: list[tuple[SecuritySlice, str]] = []
        processed_count = 0

        def payload_size(
            group: list[tuple[SecuritySlice, str]],
            batch_index: int,
            remaining_count: int,
        ) -> int:
            payload = {
                "workset_id": self.workset_id,
                "evidence_hash": self.evidence_hash,
                "batch_index": batch_index,
                # Using the maximum possible count is conservative before
                # partitioning has determined the final number of batches.
                "batch_count": len(self.slices),
                "slices": [item.to_dict() for item, _ in group],
                "all_slices_count": len(self.slices),
                "remaining_slice_count": remaining_count,
                "obligation_ids": sorted(set(self.obligation_ids)),
                "unresolved_edge_ids": sorted(set(self.unresolved_edge_ids)),
                "workset_complete": self.complete,
                "batch_is_final": remaining_count == 0,
            }
            return len(json.dumps(payload, ensure_ascii=False, sort_keys=True))

        for pair in serialized:
            item, encoded = pair
            if (
                len(current) >= max_slices
                or payload_size(
                    current + [pair],
                    len(groups),
                    len(self.slices) - processed_count - len(current) - 1,
                )
                > max_characters
            ):
                if not current:
                    raise SecuritySliceTooLarge(
                        f"slice {item.slice_id} exceeds the configured batch budget; split the evidence slice explicitly"
                    )
                groups.append(current)
                processed_count += len(current)
                current = []
            if (
                payload_size(
                    current + [pair],
                    len(groups),
                    len(self.slices) - processed_count - len(current) - 1,
                )
                > max_characters
            ):
                raise SecuritySliceTooLarge(
                    f"slice {item.slice_id} exceeds the configured batch budget; split the evidence slice explicitly"
                )
            current.append(pair)
        if current:
            groups.append(current)

        batches: list[dict[str, Any]] = []
        processed_count = 0
        for index, group in enumerate(groups):
            processed_count += len(group)
            remaining_count = len(self.slices) - processed_count
            batch = {
                "workset_id": self.workset_id,
                "evidence_hash": self.evidence_hash,
                "batch_index": index,
                "batch_count": len(groups),
                "slices": [item.to_dict() for item, _ in group],
                "all_slices_count": len(self.slices),
                "remaining_slice_count": remaining_count,
                "obligation_ids": sorted(set(self.obligation_ids)),
                "unresolved_edge_ids": sorted(set(self.unresolved_edge_ids)),
                "workset_complete": self.complete,
                "batch_is_final": index == len(groups) - 1,
            }
            if (
                len(json.dumps(batch, ensure_ascii=False, sort_keys=True))
                > max_characters
            ):
                raise SecurityWorksetContractError(
                    "serialized workset batch exceeded its configured character budget"
                )
            batches.append(batch)
        return batches


def security_worksets_from_regions(
    regions: Iterable[Mapping[str, Any]],
) -> list[SecurityWorkset]:
    """Adapt current region payloads into stable, surface-owned worksets.

    Route/symbol regions sharing a path and structural anchor become evidence
    slices of one workset. Unanchored ranges retain their own bounded identity.
    This adapter preserves the current scan path; orchestration can migrate to
    workset batches only after downstream review/evidence contracts are ready.
    """
    grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for region in regions:
        path = _safe_relative_path(str(region.get("path", "")))
        surface_type = str(region.get("anchor_type", "line_range"))
        anchor_id = str(region.get("anchor_id", "")).strip()
        if not anchor_id:
            anchor_id = f"{int(region.get('start_line', 1))}:{int(region.get('end_line', region.get('start_line', 1)))}"
        # File scope prevents two unrelated symbols with equal display names
        # in different modules from collapsing into one security surface.
        surface_id = f"{path}::{anchor_id}"
        if surface_type == "line_range":
            surface_id = f"{path}::{anchor_id}::{region.get('start_line', 1)}-{region.get('end_line', region.get('start_line', 1))}"
        grouped.setdefault((surface_type, surface_id, path), []).append(region)

    worksets: list[SecurityWorkset] = []
    for (surface_type, surface_id, _path), members in sorted(grouped.items()):
        slices: list[SecuritySlice] = []
        slice_ids: set[str] = set()
        obligations: set[str] = set()
        unresolved_edges: set[str] = set()
        for region in sorted(
            members,
            key=lambda item: (
                str(item.get("path", "")),
                int(item.get("start_line", 1)),
            ),
        ):
            path = _safe_relative_path(str(region.get("path", "")))
            start = int(region.get("start_line", 1))
            end = int(region.get("end_line", start))
            excerpt = str(region.get("content", ""))
            content_hash = (
                str(region.get("content_hash", ""))
                or hashlib.sha256(excerpt.encode("utf-8")).hexdigest()
            )
            ir_slice = region.get("security_ir_slice", {})
            if not isinstance(ir_slice, Mapping):
                ir_slice = {}
            facts = (
                ({"kind": "security_ir_slice", "value": dict(ir_slice)},)
                if ir_slice
                else ()
            )
            raw_unresolved = region.get("unresolved_edge_ids", [])
            unresolved = tuple(str(item) for item in raw_unresolved)
            unresolved_edges.update(unresolved)
            evidence_slice = SecuritySlice(
                locations=(
                    SourceLocation(
                        path=path,
                        start_line=start,
                        end_line=end,
                        content_hash=content_hash,
                        excerpt=excerpt,
                        symbol_id=surface_id,
                    ),
                ),
                facts=facts,
                unresolved_edge_ids=unresolved,
            )
            if evidence_slice.slice_id not in slice_ids:
                slices.append(evidence_slice)
                slice_ids.add(evidence_slice.slice_id)
            obligations.update(str(item) for item in region.get("obligation_ids", []))
            obligations.update(str(item) for item in region.get("obligations", []))
        worksets.append(
            SecurityWorkset(
                surface_type=surface_type,
                surface_id=surface_id,
                slices=tuple(slices),
                obligation_ids=tuple(sorted(obligations)),
                unresolved_edge_ids=tuple(sorted(unresolved_edges)),
            )
        )
    return worksets


def validate_security_contract(name: str, value: Mapping[str, Any]) -> None:
    """Validate serialized contracts against versioned schemas in assets."""
    from jsonschema import Draft202012Validator

    schema = load_json(f"schemas/{name}.json")
    errors = sorted(
        Draft202012Validator(schema).iter_errors(dict(value)),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.absolute_path)
        suffix = f" at {location}" if location else ""
        raise SecurityWorksetContractError(
            f"{name} contract failed schema validation{suffix}: {first.message}"
        )
