"""Versioned contracts for bounded, graph-grounded security worksets.

These contracts do not make vulnerability decisions. They carry stable security
surface identity, exact source evidence, observed facts, and unresolved edges.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .graph import StructuralGraph, Symbol, stable_symbol_id, stable_symbol_keys

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


def security_worksets_from_graph(
    root: str | Path,
    graph: StructuralGraph,
    *,
    maximum_source_lines: int | None = None,
) -> list[SecurityWorkset]:
    """Build source-grounded route and standalone-symbol worksets from indexed facts.

    This planner only records syntax-tree observations. In particular, textual
    references in a route registration are not asserted to be middleware, and
    calls are not treated as proven data-flow or reachability edges.
    """
    root_path = Path(root).resolve()
    runtime = load_json("runtime/security_worksets.json")
    line_limit = (
        int(runtime["maximum_source_lines_per_slice"])
        if maximum_source_lines is None
        else maximum_source_lines
    )
    if line_limit < 1:
        raise SecurityWorksetContractError("maximum source lines must be positive")

    files = {item.path: item for item in graph.files}
    symbols_by_name: dict[str, list[Symbol]] = {}
    for symbol in graph.symbols:
        symbols_by_name.setdefault(symbol.name, []).append(symbol)
        if symbol.qualified_name:
            symbols_by_name.setdefault(symbol.qualified_name, []).append(symbol)

    references_by_path: dict[str, list[Any]] = {}
    for reference in graph.references:
        references_by_path.setdefault(reference.path, []).append(reference)
    routes = sorted(graph.routes, key=lambda item: (item.path, item.line, item.name))
    resolved_route_references: dict[tuple[str, int, str], list[tuple[Any, Symbol]]] = {}
    registration_references: list[tuple[Any, list[tuple[Any, Symbol]]]] = []
    relevant_paths = {route.path for route in routes}
    route_ranges = {
        (route.path, line)
        for route in routes
        for line in range(route.line, max(route.line, route.end_line or route.line) + 1)
    }
    for route in routes:
        end = max(route.line, route.end_line or route.line)
        resolved: list[tuple[Any, Symbol]] = []
        seen: set[tuple[str, str]] = set()
        for reference in references_by_path.get(route.path, []):
            if not route.line <= reference.line <= end:
                continue
            candidates = symbols_by_name.get(reference.target, [])
            unique = {
                (item.path, item.qualified_name or item.name): item for item in candidates
            }
            if len(unique) != 1:
                continue
            target = next(iter(unique.values()))
            target_key = (target.path, target.qualified_name or target.name)
            if target.kind == "route" or target_key in seen:
                continue
            seen.add(target_key)
            resolved.append((reference, target))
            relevant_paths.add(target.path)
        resolved_route_references[(route.path, route.line, route.name)] = resolved

    # Preserve generic top-level symbol registrations (workers, callbacks,
    # event handlers, and similar constructs) without guessing their role.
    for call in graph.calls:
        end = max(call.line, call.end_line or call.line)
        if call.caller != call.path or any((call.path, line) in route_ranges for line in range(call.line, end + 1)):
            continue
        resolved: list[tuple[Any, Symbol]] = []
        seen: set[tuple[str, str]] = set()
        for reference in references_by_path.get(call.path, []):
            if not call.line <= reference.line <= end:
                continue
            candidates = symbols_by_name.get(reference.target, [])
            unique = {
                (item.path, item.qualified_name or item.name): item for item in candidates
            }
            if len(unique) != 1:
                continue
            target = next(iter(unique.values()))
            target_key = (target.path, target.qualified_name or target.name)
            if target.kind == "route" or target_key in seen:
                continue
            seen.add(target_key)
            resolved.append((reference, target))
            relevant_paths.add(target.path)
        if resolved:
            registration_references.append((call, resolved))
            relevant_paths.add(call.path)

    contents: dict[str, tuple[str, list[str]]] = {}
    for relative in sorted(relevant_paths):
        safe_relative = _safe_relative_path(relative)
        file_ir = files.get(safe_relative)
        if file_ir is None:
            raise SecurityWorksetContractError(
                f"indexed source file is unavailable for a workset: {safe_relative}"
            )
        source_path = (root_path / safe_relative).resolve()
        if root_path not in source_path.parents or not source_path.is_file():
            raise SecurityWorksetContractError(
                f"indexed source file is no longer available: {safe_relative}"
            )
        try:
            raw = source_path.read_bytes()
        except OSError as exc:
            raise SecurityWorksetContractError(
                f"could not read indexed source file: {safe_relative}"
            ) from exc
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != file_ir.content_hash:
            raise SecurityWorksetContractError(
                f"indexed source changed after graph construction: {safe_relative}"
            )
        contents[safe_relative] = (
            actual_hash,
            raw.decode("utf-8", errors="replace").splitlines(),
        )

    def locations(path: str, start: int, end: int, identity: str) -> list[SourceLocation]:
        safe_path = _safe_relative_path(path)
        if safe_path not in contents:
            raise SecurityWorksetContractError(
                f"symbol refers to a source file absent from the index: {safe_path}"
            )
        file_hash, lines = contents[safe_path]
        bounded_start = max(1, start)
        bounded_end = min(max(end, bounded_start), len(lines))
        result: list[SourceLocation] = []
        for chunk_start in range(bounded_start, bounded_end + 1, line_limit):
            chunk_end = min(chunk_start + line_limit - 1, bounded_end)
            excerpt = "\n".join(lines[chunk_start - 1 : chunk_end])
            result.append(
                SourceLocation(
                    path=safe_path,
                    start_line=chunk_start,
                    end_line=chunk_end,
                    content_hash=file_hash,
                    excerpt=excerpt,
                    symbol_id=identity,
                )
            )
        return result

    def slices_for(path: str, start: int, end: int, surface: str) -> list[SecuritySlice]:
        source_locations = locations(path, start, end, surface)
        result: list[SecuritySlice] = []
        for location in source_locations:
            facts = facts_for(path, location.start_line, location.end_line, surface)
            result.append(
                SecuritySlice(locations=(location,), facts=tuple(facts))
            )
        return result

    def facts_for(path: str, start: int, end: int, surface: str) -> list[dict[str, Any]]:
        facts: list[dict[str, Any]] = []
        for call in graph.calls:
            if call.path == path and start <= call.line <= end:
                facts.append(
                    {
                        "kind": "tree_sitter_call_observation",
                        "caller": call.caller,
                        "callee_text": call.callee,
                        "path": call.path,
                        "line": call.line,
                        "scope": surface,
                        "provenance": "tree_sitter_syntax",
                    }
                )
        for reference in graph.references:
            if reference.path == path and start <= reference.line <= end:
                facts.append(
                    {
                        "kind": "tree_sitter_reference_observation",
                        "source": reference.source,
                        "target_text": reference.target,
                        "path": reference.path,
                        "line": reference.line,
                        "scope": surface,
                        "provenance": "tree_sitter_syntax",
                    }
                )
        return facts

    route_worksets: list[SecurityWorkset] = []
    for route in sorted(graph.routes, key=lambda item: (item.path, item.line, item.name)):
        end = max(route.line, route.end_line or route.line)
        surface_id = f"{route.path}::{route.qualified_name or route.name}"
        unresolved = (
            f"route-callback-roles:{route.path}:{route.line}",
            f"route-middleware-attachment:{route.path}:{route.line}",
        )
        route_slices = slices_for(route.path, route.line, end, surface_id)
        for reference, target in resolved_route_references[
            (route.path, route.line, route.name)
        ]:
            target_id = f"{target.path}::{target.qualified_name or target.name}"
            for target_slice in slices_for(
                target.path,
                target.line,
                max(target.line, target.end_line or target.line),
                target_id,
            ):
                route_slices.append(
                    SecuritySlice(
                        locations=target_slice.locations,
                        facts=(
                            *target_slice.facts,
                            {
                                "kind": "route_registration_symbol_reference",
                                "route_surface_id": surface_id,
                                "symbol_id": target_id,
                                "reference_path": reference.path,
                                "reference_line": reference.line,
                                "provenance": "tree_sitter_syntax",
                                "relationship_limit": "does not establish callback role or runtime reachability",
                            },
                            {
                                "kind": "callable_boundary_observation",
                                "symbol_id": target_id,
                                "signature_syntax": target.signature,
                                "provenance": "tree_sitter_syntax",
                                "trust_of_inputs": "unresolved",
                                "runtime_reachability": "unresolved",
                            },
                        ),
                    )
                )
        route_worksets.append(
            SecurityWorkset(
                surface_type="http_route",
                surface_id=surface_id,
                slices=tuple(
                    SecuritySlice(
                        locations=item.locations,
                        facts=item.facts,
                        unresolved_edge_ids=unresolved,
                    )
                    for item in route_slices
                ),
                unresolved_edge_ids=unresolved,
                metadata={
                    "display_name": route.name,
                    "source": "tree_sitter_route_registration",
                    "relationship_limitations": [
                        "route callback roles are not inferred",
                        "middleware attachment is not verified",
                        "calls do not imply data flow or runtime reachability",
                    ],
                },
            )
        )

    registration_worksets: list[SecurityWorkset] = []
    for call_record, references in sorted(
        registration_references,
        key=lambda item: (item[0].path, item[0].line, item[0].callee),
    ):
        end = max(call_record.line, call_record.end_line or call_record.line)
        surface_id = f"{call_record.path}::registration:{call_record.callee}@{call_record.line}"
        unresolved = (f"registration-role:{call_record.path}:{call_record.line}",)
        registration_slices = slices_for(
            call_record.path, call_record.line, end, surface_id
        )
        for reference, target in references:
            target_id = f"{target.path}::{target.qualified_name or target.name}"
            for target_slice in slices_for(
                target.path,
                target.line,
                max(target.line, target.end_line or target.line),
                target_id,
            ):
                registration_slices.append(
                    SecuritySlice(
                        locations=target_slice.locations,
                        facts=(
                            *target_slice.facts,
                            {
                                "kind": "top_level_call_symbol_reference",
                                "registration_surface_id": surface_id,
                                "symbol_id": target_id,
                                "reference_path": reference.path,
                                "reference_line": reference.line,
                                "provenance": "tree_sitter_syntax",
                                "relationship_limit": "does not establish registration semantics or runtime execution",
                            },
                            {
                                "kind": "callable_boundary_observation",
                                "symbol_id": target_id,
                                "signature_syntax": target.signature,
                                "provenance": "tree_sitter_syntax",
                                "trust_of_inputs": "unresolved",
                                "runtime_reachability": "unresolved",
                            },
                        ),
                    )
                )
        registration_worksets.append(
            SecurityWorkset(
                surface_type="symbol_registration",
                surface_id=surface_id,
                slices=tuple(
                    SecuritySlice(
                        locations=item.locations,
                        facts=item.facts,
                        unresolved_edge_ids=unresolved,
                    )
                    for item in registration_slices
                ),
                unresolved_edge_ids=unresolved,
                metadata={
                    "source": "tree_sitter_top_level_call_reference",
                    "callee_text": call_record.callee,
                    "relationship_limitations": [
                        "registration role is unresolved",
                        "referenced symbols are syntactic candidates only",
                        "registration does not establish runtime execution or security relevance",
                    ],
                },
            )
        )

    return route_worksets + registration_worksets


def security_summaries_from_graph(graph: StructuralGraph) -> list[SecuritySummary]:
    """Create composable syntax summaries; unresolved calls remain explicit."""
    files = {item.path: item for item in graph.files}
    stable_keys = stable_symbol_keys(graph.symbols + graph.routes)
    symbol_ids = {
        id(symbol): stable_symbol_id(stable_keys[id(symbol)])
        for symbol in graph.symbols + graph.routes
    }
    symbols_by_name: dict[str, list[Symbol]] = {}
    for symbol in graph.symbols:
        symbols_by_name.setdefault(symbol.name, []).append(symbol)
        if symbol.qualified_name:
            symbols_by_name.setdefault(symbol.qualified_name, []).append(symbol)

    summaries: list[SecuritySummary] = []
    for symbol in sorted(
        graph.symbols,
        key=lambda item: (item.path, item.line, item.qualified_name or item.name),
    ):
        if symbol.kind == "route":
            continue
        current_symbol_id = symbol_ids[id(symbol)]
        file_hash = files.get(symbol.path)
        symbol_content_hash = symbol.content_hash or hashlib.sha256(
            f"{file_hash.content_hash if file_hash else ''}:{symbol.path}:{symbol.line}:{symbol.end_line}:{symbol.signature}".encode()
        ).hexdigest()
        dependencies: set[str] = set()
        unresolved: set[str] = set()
        call_facts: list[dict[str, Any]] = []
        for call in graph.calls:
            if call.caller != (symbol.qualified_name or symbol.name):
                continue
            callee = call.callee.strip()
            terminal_name = callee.rsplit(".", 1)[-1]
            candidates = symbols_by_name.get(callee, []) or symbols_by_name.get(terminal_name, [])
            unique = {
                (item.path, item.qualified_name or item.name): item for item in candidates
            }
            if len(unique) == 1:
                target = next(iter(unique.values()))
                dependencies.add(symbol_ids[id(target)])
                target_id = symbol_ids[id(target)]
            else:
                target_id = ""
                unresolved.add(
                    f"call:{current_symbol_id}:{call.path}:{call.line}:{hashlib.sha256(callee.encode()).hexdigest()[:12]}"
                )
            call_facts.append(
                {
                    "kind": "tree_sitter_call_observation",
                    "callee_text": callee,
                    "target_symbol_id": target_id,
                    "path": call.path,
                    "line": call.line,
                    "provenance": "tree_sitter_syntax",
                    "relationship_limit": "does not establish data flow, side effect, or runtime reachability",
                }
            )
        content_hash = _digest(
            {
                "symbol_content_hash": symbol_content_hash,
                "dependency_symbol_ids": sorted(dependencies),
                "unresolved_relationship_ids": sorted(unresolved),
            }
        )
        summaries.append(
            SecuritySummary(
                symbol_id=current_symbol_id,
                content_hash=content_hash,
                facts=(
                    {
                        "kind": "indexed_symbol",
                        "symbol_kind": symbol.kind,
                        "name": symbol.name,
                        "path": symbol.path,
                        "start_line": symbol.line,
                        "end_line": symbol.end_line,
                        "signature_syntax": symbol.signature,
                        "symbol_content_hash": symbol_content_hash,
                        "provenance": "tree_sitter_syntax",
                    },
                    *call_facts,
                ),
                dependency_symbol_ids=tuple(sorted(dependencies)),
                unresolved_relationship_ids=tuple(sorted(unresolved)),
            )
        )
    return summaries


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
