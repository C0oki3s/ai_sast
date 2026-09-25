"""Map source-grounded repository context records onto observed Graphify nodes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .assets import load_json
from .graphify_adapter import CodeGraphSnapshot


class GraphTargetMappingStatus(StrEnum):
    MAPPED = "mapped"
    AMBIGUOUS = "ambiguous"
    UNMAPPED = "unmapped"
    STALE_SOURCE = "stale_source"
    UNVERIFIED_LOCATION = "unverified_location"
    NO_LOCATION = "no_location"


@dataclass(frozen=True, slots=True)
class GraphSurfaceTarget:
    surface_key: str
    collection: str
    label: str
    record: Mapping[str, Any]
    source_locations: tuple[dict[str, Any], ...]
    node_ids: tuple[str, ...]
    mapping_status: GraphTargetMappingStatus
    gap_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface_key": self.surface_key,
            "collection": self.collection,
            "label": self.label,
            "record": dict(self.record),
            "source_locations": list(self.source_locations),
            "node_ids": list(self.node_ids),
            "mapping_status": self.mapping_status.value,
            "gap_reason": self.gap_reason,
        }


@dataclass(frozen=True, slots=True)
class GraphTargetInventory:
    snapshot_id: str
    targets: tuple[GraphSurfaceTarget, ...]

    @property
    def graph_target_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted({node_id for target in self.targets for node_id in target.node_ids})
        )

    @property
    def mapping_counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in GraphTargetMappingStatus}
        for target in self.targets:
            counts[target.mapping_status.value] += 1
        return counts


@dataclass(frozen=True, slots=True)
class GraphSurfaceGroup:
    """Connected, source-grounded context surfaces suitable for one planning unit."""

    group_id: str
    surface_keys: tuple[str, ...]
    node_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GraphTargetGrouping:
    groups: tuple[GraphSurfaceGroup, ...]
    unmapped_surface_keys: tuple[str, ...]


def map_repository_surfaces_to_graph(
    repository_context: Mapping[str, Any],
    graph_snapshot: CodeGraphSnapshot,
) -> GraphTargetInventory:
    """Resolve only source-version-grounded context locations; never pick an ambiguous node."""
    config = load_json("runtime/graph_surface_collections.json")["collections"]
    nodes_by_path: dict[str, list[Any]] = {}
    for node in graph_snapshot.nodes:
        nodes_by_path.setdefault(node.path, []).append(node)

    targets: list[GraphSurfaceTarget] = []
    for collection_spec in config:
        collection = str(collection_spec["name"])
        records = repository_context.get(collection, [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, Mapping):
                continue
            normalized_record = dict(record)
            identity = next(
                (
                    str(record[key]).strip()
                    for key in collection_spec["identity_fields"]
                    if record.get(key)
                ),
                "",
            )
            if not identity:
                identity = json.dumps(
                    record, sort_keys=True, ensure_ascii=False, separators=(",", ":")
                )
            surface_key = hashlib.sha256(
                f"{collection}\0{identity}".encode("utf-8")
            ).hexdigest()[:32]
            label = " ".join(
                str(record[key]).strip()
                for key in collection_spec["label_fields"]
                if isinstance(record.get(key), str) and str(record[key]).strip()
            )
            locations = record.get("evidence_locations", [])
            if not isinstance(locations, list) or not locations:
                targets.append(
                    _target(
                        surface_key,
                        collection,
                        label,
                        normalized_record,
                        (),
                        (),
                        GraphTargetMappingStatus.NO_LOCATION,
                        "No source location was supplied.",
                    )
                )
                continue

            valid_locations: list[dict[str, Any]] = []
            matched_ids: set[str] = set()
            stale = False
            unverified = False
            for location in locations:
                if not isinstance(location, Mapping):
                    unverified = True
                    continue
                path = location.get("path")
                start = location.get("start_line")
                end = location.get("end_line")
                status = location.get("grounding_status")
                content_hash = location.get("source_content_hash")
                if status != "verified_source_location" or not isinstance(
                    content_hash, str
                ):
                    unverified = True
                    continue
                if graph_snapshot.source_hashes.get(str(path)) != content_hash:
                    stale = True
                    continue
                if (
                    isinstance(start, bool)
                    or isinstance(end, bool)
                    or not isinstance(start, int)
                    or not isinstance(end, int)
                    or start < 1
                    or end < start
                ):
                    unverified = True
                    continue
                valid_locations.append(
                    {
                        "path": str(path),
                        "start_line": start,
                        "end_line": end,
                        "source_hash": content_hash,
                    }
                )
                matched_ids.update(
                    node.id
                    for node in nodes_by_path.get(str(path), [])
                    if start <= node.line <= end and node.source_hash == content_hash
                )

            if matched_ids:
                match_status = (
                    GraphTargetMappingStatus.AMBIGUOUS
                    if len(matched_ids) > 1
                    else GraphTargetMappingStatus.MAPPED
                )
                reason = (
                    "Multiple Graphify nodes overlap the source evidence; preserve all until AI planning groups them."
                    if len(matched_ids) > 1
                    else ""
                )
                targets.append(
                    _target(
                        surface_key,
                        collection,
                        label,
                        normalized_record,
                        tuple(valid_locations),
                        tuple(sorted(matched_ids)),
                        match_status,
                        reason,
                    )
                )
            elif stale:
                targets.append(
                    _target(
                        surface_key,
                        collection,
                        label,
                        normalized_record,
                        (),
                        (),
                        GraphTargetMappingStatus.STALE_SOURCE,
                        "Grounded source evidence belongs to a different graph snapshot.",
                    )
                )
            elif unverified:
                targets.append(
                    _target(
                        surface_key,
                        collection,
                        label,
                        normalized_record,
                        (),
                        (),
                        GraphTargetMappingStatus.UNVERIFIED_LOCATION,
                        "No supplied location is verified against this immutable source snapshot.",
                    )
                )
            else:
                targets.append(
                    _target(
                        surface_key,
                        collection,
                        label,
                        normalized_record,
                        tuple(valid_locations),
                        (),
                        GraphTargetMappingStatus.UNMAPPED,
                        "Verified source locations do not overlap an indexed Graphify node.",
                    )
                )

    validator = Draft202012Validator(load_json("schemas/graph_surface_target.json"))
    for target in targets:
        errors = list(validator.iter_errors(target.to_dict()))
        if errors:
            raise ValueError(
                f"Graph surface target violated its schema: {errors[0].message}"
            )
    return GraphTargetInventory(graph_snapshot.snapshot_id, tuple(targets))


def group_connected_graph_targets(
    inventory: GraphTargetInventory,
    graph_snapshot: CodeGraphSnapshot,
) -> GraphTargetGrouping:
    """Group mapped context surfaces by shared or directly connected Graphify nodes.

    Mapping gaps are returned separately and never promoted to planner targets.
    Graphify edges are used for grouping only; their provenance remains available
    from the graph snapshot and is not interpreted as security evidence.
    """
    if inventory.snapshot_id != graph_snapshot.snapshot_id:
        raise ValueError(
            "Graph target inventory belongs to a different source snapshot"
        )

    eligible = [target for target in inventory.targets if target.node_ids]
    unmapped = tuple(
        sorted(
            target.surface_key for target in inventory.targets if not target.node_ids
        )
    )
    if not eligible:
        return GraphTargetGrouping((), unmapped)

    node_to_targets: dict[str, set[int]] = {}
    for index, target in enumerate(eligible):
        for node_id in target.node_ids:
            node_to_targets.setdefault(node_id, set()).add(index)

    parent = list(range(len(eligible)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for indices in node_to_targets.values():
        ordered = sorted(indices)
        for index in ordered[1:]:
            union(ordered[0], index)

    for edge in graph_snapshot.edges:
        connected_targets = node_to_targets.get(
            edge.source_id, set()
        ) | node_to_targets.get(edge.target_id, set())
        if connected_targets:
            anchor = min(connected_targets)
            for index in connected_targets:
                union(anchor, index)

    components: dict[int, list[int]] = {}
    for index in range(len(eligible)):
        components.setdefault(find(index), []).append(index)

    groups: list[GraphSurfaceGroup] = []
    for indices in components.values():
        surface_keys = tuple(sorted(eligible[index].surface_key for index in indices))
        node_ids = tuple(
            sorted(
                {node_id for index in indices for node_id in eligible[index].node_ids}
            )
        )
        digest = hashlib.sha256("\0".join(surface_keys).encode("utf-8")).hexdigest()[
            :32
        ]
        groups.append(
            GraphSurfaceGroup(f"graph-group-{digest}", surface_keys, node_ids)
        )
    groups.sort(key=lambda item: (item.node_ids, item.surface_keys))
    return GraphTargetGrouping(tuple(groups), unmapped)


def _target(
    surface_key: str,
    collection: str,
    label: str,
    record: Mapping[str, Any],
    locations: tuple[dict[str, Any], ...],
    node_ids: tuple[str, ...],
    status: GraphTargetMappingStatus,
    reason: str,
) -> GraphSurfaceTarget:
    return GraphSurfaceTarget(
        surface_key, collection, label, record, locations, node_ids, status, reason
    )
