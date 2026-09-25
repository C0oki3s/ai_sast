"""Graph-grounded, model-authored investigation planning boundary."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator

from .assets import load_json
from .graph_context import GraphContextBroker
from .graphify_adapter import (
    CodeEdge,
    CodeGraphSnapshot,
    CodeNode,
    GraphifyAdapterError,
    graph_edge_identity,
)
from .investigations import Investigation, build_investigation
from .redaction import redact_payload


class GraphPlanningError(RuntimeError):
    """Raised when a planning response is malformed or cites unobserved graph facts."""


@dataclass(frozen=True, slots=True)
class GraphPlanningLimits:
    lines_before: int
    lines_after: int
    maximum_neighbor_nodes: int
    maximum_neighbor_edges: int
    maximum_input_characters: int
    maximum_target_nodes: int = 12

    @classmethod
    def configured(cls) -> GraphPlanningLimits:
        runtime = load_json("runtime/code_intelligence.json")
        return cls(
            lines_before=int(runtime["planner_context_lines_before"]),
            lines_after=int(runtime["planner_context_lines_after"]),
            maximum_neighbor_nodes=int(runtime["maximum_planner_neighbor_nodes"]),
            maximum_neighbor_edges=int(runtime["maximum_planner_neighbor_edges"]),
            maximum_input_characters=int(runtime["maximum_planner_input_characters"]),
            maximum_target_nodes=int(runtime["maximum_planner_target_nodes"]),
        )


class GraphInvestigationPlanner:
    """Ask the configured model to frame an investigation over a bounded graph slice."""

    def __init__(
        self,
        complete: Callable[[dict[str, Any]], Mapping[str, Any]],
        *,
        limits: GraphPlanningLimits | None = None,
    ) -> None:
        self.complete = complete
        self.limits = limits or GraphPlanningLimits.configured()
        if (
            min(
                self.limits.maximum_neighbor_nodes,
                self.limits.maximum_neighbor_edges,
                self.limits.maximum_input_characters,
                self.limits.maximum_target_nodes,
            )
            < 1
        ):
            raise ValueError("graph planner bounds must be positive")
        if self.limits.lines_before < 0 or self.limits.lines_after < 0:
            raise ValueError(
                "graph planner source-window context lines must be nonnegative"
            )

    def plan_target(
        self,
        *,
        codebase_id: str,
        snapshot: CodeGraphSnapshot,
        broker: GraphContextBroker,
        target_node_id: str,
        repository_context: Mapping[str, Any],
    ) -> Investigation:
        return self.plan_targets(
            codebase_id=codebase_id,
            snapshot=snapshot,
            broker=broker,
            target_node_ids=(target_node_id,),
            repository_context=repository_context,
            stable_key=f"graph-node:{target_node_id}",
        )

    def plan_targets(
        self,
        *,
        codebase_id: str,
        snapshot: CodeGraphSnapshot,
        broker: GraphContextBroker,
        target_node_ids: Sequence[str],
        repository_context: Mapping[str, Any],
        surface_context: Sequence[Mapping[str, Any]] = (),
        stable_key: str | None = None,
    ) -> Investigation:
        """Plan one bounded investigation for one or more connected graph targets."""
        target_ids = tuple(
            dict.fromkeys(str(item) for item in target_node_ids if str(item))
        )
        if not target_ids:
            raise GraphifyAdapterError("at least one graph target is required")
        if len(target_ids) > min(
            self.limits.maximum_target_nodes, self.limits.maximum_neighbor_nodes
        ):
            raise GraphPlanningError(
                "connected graph target group exceeds its configured bound"
            )
        if broker.snapshot.snapshot_id != snapshot.snapshot_id:
            raise GraphifyAdapterError(
                "Graphify context broker belongs to another snapshot"
            )

        nodes_by_id = {node.id: node for node in snapshot.nodes}
        if set(target_ids) - nodes_by_id.keys():
            raise GraphifyAdapterError("unknown graph node")
        if len(target_ids) > 1:
            adjacency = {node_id: set() for node_id in target_ids}
            for edge in snapshot.edges:
                if edge.source_id in adjacency and edge.target_id in adjacency:
                    adjacency[edge.source_id].add(edge.target_id)
                    adjacency[edge.target_id].add(edge.source_id)
            reached = {target_ids[0]}
            pending = [target_ids[0]]
            while pending:
                current = pending.pop()
                for neighbor in adjacency[current] - reached:
                    reached.add(neighbor)
                    pending.append(neighbor)
            if reached != set(target_ids):
                raise GraphPlanningError(
                    "target nodes do not form a connected Graphify group"
                )
        targets = sorted(
            (nodes_by_id[node_id] for node_id in target_ids), key=_node_sort_key
        )
        grounded_surfaces = _ground_surface_context(
            surface_context, set(target_ids), nodes_by_id, snapshot
        )
        neighborhood_nodes: dict[str, CodeNode] = {node.id: node for node in targets}
        candidate_edges: dict[str, CodeEdge] = {}
        truncated = False
        unresolved_edges = 0
        for target in targets:
            lookup = broker.neighborhood(target.id)
            truncated = truncated or lookup.truncated
            unresolved_edges = max(unresolved_edges, lookup.unresolved_edges)
            for node in lookup.nodes:
                neighborhood_nodes.setdefault(node.id, node)
            for edge in lookup.edges:
                candidate_edges[_edge_key(edge)] = edge

        target_set = set(target_ids)
        neighbors = sorted(
            (node for node in neighborhood_nodes.values() if node.id not in target_set),
            key=_node_sort_key,
        )
        neighbor_capacity = max(0, self.limits.maximum_neighbor_nodes - len(targets))
        if len(neighbors) > neighbor_capacity:
            truncated = True
        included_ids = target_set | {node.id for node in neighbors[:neighbor_capacity]}
        selected_edges = tuple(
            edge
            for _, edge in sorted(candidate_edges.items())
            if edge.source_id in included_ids and edge.target_id in included_ids
        )[: self.limits.maximum_neighbor_edges]
        if len(candidate_edges) > len(selected_edges):
            truncated = True
        included_ids.update(
            node_id
            for edge in selected_edges
            for node_id in (edge.source_id, edge.target_id)
        )
        evidence_nodes = sorted(
            (nodes_by_id[node_id] for node_id in included_ids), key=_node_sort_key
        )

        windows_by_node: dict[str, dict[str, Any]] = {}
        for node in evidence_nodes:
            window = broker.source_window_around_node(
                node.id,
                lines_before=self.limits.lines_before,
                lines_after=self.limits.lines_after,
            )
            windows_by_node[node.id] = {
                "path": window.path,
                "start_line": window.start_line,
                "end_line": window.end_line,
                "content_hash": window.source_hash,
                "excerpt": window.excerpt,
                "redaction_state": "redacted",
            }

        edge_keys = {_edge_key(edge): edge for edge in selected_edges}
        payload = {
            "repository_context": redact_payload(dict(repository_context)),
            "graph_snapshot_id": snapshot.snapshot_id,
            "targets": [
                _node_payload(target, windows_by_node[target.id]) for target in targets
            ],
            "surface_context": redact_payload(grounded_surfaces),
            "graph_nodes": [
                _node_payload(node, windows_by_node[node.id]) for node in evidence_nodes
            ],
            "graph_edges": [
                {
                    "edge_key": key,
                    "source_id": edge.source_id,
                    "target_id": edge.target_id,
                    "relation": edge.relation,
                    "provenance": edge.provenance,
                    "path": edge.path,
                    "line": edge.line,
                }
                for key, edge in sorted(edge_keys.items())
            ],
            "graph_context_truncated": truncated,
            "unresolved_graph_edges": unresolved_edges,
        }
        payload_characters = len(
            json.dumps(payload, sort_keys=True, ensure_ascii=False)
        )
        if payload_characters > self.limits.maximum_input_characters:
            raise GraphPlanningError(
                "bounded graph investigation packet exceeded its configured size"
            )
        plan = dict(self.complete(payload))
        schema = load_json("schemas/graph_investigation_plan.json")
        errors = sorted(
            Draft202012Validator(schema).iter_errors(plan),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            raise GraphPlanningError(
                f"investigation plan schema validation failed: {errors[0].message}"
            )

        allowed_ids = {node.id for node in evidence_nodes}
        supporting_ids = set(plan["supporting_node_ids"])
        if not supporting_ids <= allowed_ids:
            raise GraphPlanningError(
                "investigation plan referenced nodes outside the supplied graph slice"
            )
        supporting_edge_keys = set(plan["supporting_edge_keys"])
        if not supporting_edge_keys <= edge_keys.keys():
            raise GraphPlanningError(
                "investigation plan referenced edges outside the supplied graph slice"
            )

        referenced_ids = target_set | supporting_ids
        for key in supporting_edge_keys:
            edge = edge_keys[key]
            referenced_ids.update((edge.source_id, edge.target_id))
        source_windows = tuple(
            windows_by_node[node_id] for node_id in sorted(referenced_ids)
        )
        graph_refs: list[dict[str, Any]] = [
            {
                "node_id": node_id,
                "provenance": "EXTRACTED",
                "snapshot_id": snapshot.snapshot_id,
            }
            for node_id in sorted(referenced_ids)
        ]
        for key in sorted(supporting_edge_keys):
            edge = edge_keys[key]
            graph_refs.append(
                {
                    "edge_id": key,
                    "relation": edge.relation,
                    "provenance": edge.provenance,
                    "snapshot_id": snapshot.snapshot_id,
                }
            )
        dependencies = [
            {"kind": "graph_node", "key": node.id, "hash": node.source_hash}
            for node in (nodes_by_id[node_id] for node_id in sorted(referenced_ids))
        ]
        dependencies.extend(
            {"kind": "graph_edge", "key": key, "hash": edge_keys[key].source_hash}
            for key in sorted(supporting_edge_keys)
        )
        dependencies.append(
            {
                "kind": "graph_snapshot",
                "key": snapshot.snapshot_id,
                "hash": snapshot.snapshot_id,
            }
        )
        coverage_notes = [str(note) for note in plan["coverage_notes"]]
        if truncated:
            coverage_notes.append(
                "Graph neighborhood was bounded; additional relationships may exist outside this context packet."
            )
        if unresolved_edges:
            coverage_notes.append(
                f"Graph extraction reported {unresolved_edges} unresolved edge(s)."
            )

        target_digest = hashlib.sha256(
            "\0".join(sorted(target_ids)).encode("utf-8")
        ).hexdigest()[:32]
        target_ref = {
            "node_ids": sorted(target_ids),
            "targets": [
                {
                    "node_id": target.id,
                    "label": target.label,
                    "path": target.path,
                    "line": target.line,
                }
                for target in targets
            ],
            "surface_context": redact_payload(grounded_surfaces),
        }
        if len(targets) == 1:
            target_ref.update(target_ref["targets"][0])
        return build_investigation(
            stable_key=stable_key or f"graph-target-group:{target_digest}",
            codebase_id=codebase_id,
            snapshot_id=snapshot.snapshot_id,
            target_ref=target_ref,
            reason=str(plan["reason"]),
            security_questions=tuple(str(item) for item in plan["security_questions"]),
            graph_refs=tuple(graph_refs),
            source_windows=source_windows,
            context_dependencies=tuple(dependencies),
            coverage_notes=tuple(dict.fromkeys(coverage_notes)),
            graph_snapshot_id=snapshot.snapshot_id,
        )


def _node_sort_key(node: CodeNode) -> tuple[str, int, str]:
    return node.path, node.line, node.id


def _edge_key(edge: CodeEdge) -> str:
    return graph_edge_identity(edge)


def _node_payload(node: CodeNode, window: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "node_id": node.id,
        "label": node.label,
        "path": node.path,
        "line": node.line,
        "source_hash": node.source_hash,
        "source_window": dict(window),
    }


def _ground_surface_context(
    surfaces: Sequence[Mapping[str, Any]],
    target_ids: set[str],
    nodes_by_id: Mapping[str, CodeNode],
    snapshot: CodeGraphSnapshot,
) -> list[dict[str, Any]]:
    """Keep only surface metadata whose source/version/target links are verified."""
    grounded: list[dict[str, Any]] = []
    for surface in surfaces:
        if surface.get("mapping_status") not in {"mapped", "ambiguous"}:
            raise GraphPlanningError(
                "planner surface context must be mapped to graph nodes"
            )
        raw_node_ids = surface.get("node_ids")
        if not isinstance(raw_node_ids, list) or not raw_node_ids:
            raise GraphPlanningError(
                "planner surface context has no mapped graph nodes"
            )
        surface_node_ids = set(str(item) for item in raw_node_ids)
        if not surface_node_ids <= target_ids:
            raise GraphPlanningError(
                "planner surface references nodes outside its target group"
            )
        locations = surface.get("source_locations")
        if not isinstance(locations, list) or not locations:
            raise GraphPlanningError(
                "planner surface context has no grounded source locations"
            )
        normalized_locations: list[dict[str, Any]] = []
        for location in locations:
            if not isinstance(location, Mapping):
                raise GraphPlanningError("planner surface source location is malformed")
            path = location.get("path")
            start = location.get("start_line")
            end = location.get("end_line")
            source_hash = location.get("source_hash")
            if (
                not isinstance(path, str)
                or not isinstance(start, int)
                or isinstance(start, bool)
                or not isinstance(end, int)
                or isinstance(end, bool)
                or start < 1
                or end < start
                or not isinstance(source_hash, str)
                or snapshot.source_hashes.get(path) != source_hash
            ):
                raise GraphPlanningError(
                    "planner surface source location is not snapshot-grounded"
                )
            if not any(
                nodes_by_id[node_id].path == path
                and start <= nodes_by_id[node_id].line <= end
                and nodes_by_id[node_id].source_hash == source_hash
                for node_id in surface_node_ids
            ):
                raise GraphPlanningError(
                    "planner surface location does not match its graph nodes"
                )
            normalized_locations.append(
                {
                    "path": path,
                    "start_line": start,
                    "end_line": end,
                    "source_hash": source_hash,
                }
            )
        identity = (
            surface.get("surface_key"),
            surface.get("collection"),
            surface.get("label"),
        )
        if not all(isinstance(value, str) and value for value in identity):
            raise GraphPlanningError("planner surface context identity is incomplete")
        grounded.append(
            {
                "surface_key": identity[0],
                "collection": identity[1],
                "label": identity[2],
                "source_locations": normalized_locations,
                "node_ids": sorted(surface_node_ids),
                "mapping_status": surface["mapping_status"],
            }
        )
    return grounded
