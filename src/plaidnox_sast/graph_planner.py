"""Graph-grounded, model-authored investigation planning boundary."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator

from .assets import load_json
from .graph_context import GraphContextBroker
from .graphify_adapter import CodeEdge, CodeGraphSnapshot, CodeNode, GraphifyAdapterError
from .investigations import Investigation, build_investigation


class GraphPlanningError(RuntimeError):
    """Raised when a planning response is malformed or cites unobserved graph facts."""


@dataclass(frozen=True, slots=True)
class GraphPlanningLimits:
    lines_before: int
    lines_after: int
    maximum_neighbor_nodes: int
    maximum_neighbor_edges: int
    maximum_input_characters: int

    @classmethod
    def configured(cls) -> GraphPlanningLimits:
        runtime = load_json("runtime/code_intelligence.json")
        return cls(
            lines_before=int(runtime["planner_context_lines_before"]),
            lines_after=int(runtime["planner_context_lines_after"]),
            maximum_neighbor_nodes=int(runtime["maximum_planner_neighbor_nodes"]),
            maximum_neighbor_edges=int(runtime["maximum_planner_neighbor_edges"]),
            maximum_input_characters=int(runtime["maximum_planner_input_characters"]),
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
        if min(
            self.limits.maximum_neighbor_nodes,
            self.limits.maximum_neighbor_edges,
            self.limits.maximum_input_characters,
        ) < 1:
            raise ValueError("graph planner bounds must be positive")
        if self.limits.lines_before < 0 or self.limits.lines_after < 0:
            raise ValueError("graph planner source-window context lines must be nonnegative")

    def plan_target(
        self,
        *,
        codebase_id: str,
        snapshot: CodeGraphSnapshot,
        broker: GraphContextBroker,
        target_node_id: str,
        repository_context: Mapping[str, Any],
    ) -> Investigation:
        target = next((node for node in snapshot.nodes if node.id == target_node_id), None)
        if target is None:
            raise GraphifyAdapterError("unknown graph node")

        lookup = broker.neighborhood(target_node_id)
        neighbors = sorted(lookup.nodes, key=_node_sort_key)[: self.limits.maximum_neighbor_nodes]
        allowed_nodes = {target.id, *(node.id for node in neighbors)}
        selected_edges = tuple(
            edge
            for edge in lookup.edges
            if edge.source_id in allowed_nodes and edge.target_id in allowed_nodes
        )[: self.limits.maximum_neighbor_edges]
        included_node_ids = {target.id}
        included_node_ids.update(node_id for edge in selected_edges for node_id in (edge.source_id, edge.target_id))
        included_node_ids.update(
            node.id for node in neighbors if node.id in included_node_ids or node.id == target.id
        )
        nodes_by_id = {node.id: node for node in snapshot.nodes}
        evidence_nodes = sorted((nodes_by_id[node_id] for node_id in included_node_ids), key=_node_sort_key)
        evidence_nodes = [target, *(node for node in evidence_nodes if node.id != target.id)]

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
            "repository_context": dict(repository_context),
            "graph_snapshot_id": snapshot.snapshot_id,
            "target": _node_payload(target, windows_by_node[target.id]),
            "graph_nodes": [_node_payload(node, windows_by_node[node.id]) for node in evidence_nodes],
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
            "graph_context_truncated": lookup.truncated
            or len(lookup.nodes) > self.limits.maximum_neighbor_nodes
            or len(lookup.edges) > self.limits.maximum_neighbor_edges,
            "unresolved_graph_edges": lookup.unresolved_edges,
        }
        payload_characters = len(json.dumps(payload, sort_keys=True, ensure_ascii=False))
        if payload_characters > self.limits.maximum_input_characters:
            raise GraphPlanningError("bounded graph investigation packet exceeded its configured size")
        plan = dict(self.complete(payload))
        schema = load_json("schemas/graph_investigation_plan.json")
        errors = sorted(Draft202012Validator(schema).iter_errors(plan), key=lambda error: list(error.absolute_path))
        if errors:
            raise GraphPlanningError(f"investigation plan schema validation failed: {errors[0].message}")

        allowed_ids = {node.id for node in evidence_nodes}
        supporting_ids = set(plan["supporting_node_ids"])
        if not supporting_ids <= allowed_ids:
            raise GraphPlanningError("investigation plan referenced nodes outside the supplied graph slice")
        supporting_edge_keys = set(plan["supporting_edge_keys"])
        if not supporting_edge_keys <= edge_keys.keys():
            raise GraphPlanningError("investigation plan referenced edges outside the supplied graph slice")

        referenced_ids = {target.id} | supporting_ids
        for key in supporting_edge_keys:
            edge = edge_keys[key]
            referenced_ids.update((edge.source_id, edge.target_id))
        source_windows = tuple(windows_by_node[node_id] for node_id in sorted(referenced_ids))
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
        dependencies.append({"kind": "graph_snapshot", "key": snapshot.snapshot_id, "hash": snapshot.snapshot_id})
        coverage_notes = [str(note) for note in plan["coverage_notes"]]
        if payload["graph_context_truncated"]:
            coverage_notes.append("Graph neighborhood was bounded; additional relationships may exist outside this context packet.")
        if lookup.unresolved_edges:
            coverage_notes.append(f"Graph extraction reported {lookup.unresolved_edges} unresolved edge(s).")

        return build_investigation(
            stable_key=f"graph-node:{target.id}",
            codebase_id=codebase_id,
            snapshot_id=snapshot.snapshot_id,
            target_ref={"node_id": target.id, "label": target.label, "path": target.path, "line": target.line},
            reason=str(plan["reason"]),
            security_questions=tuple(str(item) for item in plan["security_questions"]),
            graph_refs=tuple(graph_refs),
            source_windows=source_windows,
            context_dependencies=tuple(dependencies),
            coverage_notes=tuple(dict.fromkeys(coverage_notes)),
        )


def _node_sort_key(node: CodeNode) -> tuple[str, int, str]:
    return node.path, node.line, node.id


def _edge_key(edge: CodeEdge) -> str:
    identity = json.dumps(
        [edge.source_id, edge.target_id, edge.relation, edge.provenance, edge.path, edge.line, edge.source_hash],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _node_payload(node: CodeNode, window: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "node_id": node.id,
        "label": node.label,
        "path": node.path,
        "line": node.line,
        "source_hash": node.source_hash,
        "source_window": dict(window),
    }
