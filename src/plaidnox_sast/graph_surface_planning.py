"""Coordinate source-grounded security-surface groups into investigations."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .assets import load_json
from .graph_targets import (
    GraphTargetInventory,
    GraphTargetMappingStatus,
    GraphTargetGrouping,
    group_connected_graph_targets,
    map_repository_surfaces_to_graph,
)
from .graphify_adapter import CodeGraphSnapshot
from .investigations import Investigation


@dataclass(frozen=True, slots=True)
class GraphSurfacePlanningGap:
    group_id: str
    surface_keys: tuple[str, ...]
    node_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class GraphSurfacePlanningResult:
    snapshot_id: str
    inventory: GraphTargetInventory
    grouping: GraphTargetGrouping
    investigations: tuple[Investigation, ...]
    planning_gaps: tuple[GraphSurfacePlanningGap, ...]

    @property
    def mapping_gap_count(self) -> int:
        return sum(
            target.mapping_status is not GraphTargetMappingStatus.MAPPED
            and target.mapping_status is not GraphTargetMappingStatus.AMBIGUOUS
            for target in self.inventory.targets
        )


class GraphSurfacePlanningCoordinator:
    """Map and batch eligible surfaces before making bounded AI planner calls.

    The callback should be `PlaidNoxDeepHuntAgent.plan_graph_investigation` with
    its repository context, snapshot, and Context Broker bound. Provider errors
    intentionally propagate; this coordinator only reports deterministic
    mapping and configured-size gaps.
    """

    def __init__(
        self,
        plan_group: Callable[..., Investigation],
        *,
        maximum_target_nodes: int | None = None,
    ) -> None:
        self.plan_group = plan_group
        runtime = load_json("runtime/code_intelligence.json")
        self.maximum_target_nodes = int(
            maximum_target_nodes
            if maximum_target_nodes is not None
            else runtime["maximum_planner_target_nodes"]
        )
        if self.maximum_target_nodes < 1:
            raise ValueError("maximum planner target node count must be positive")

    def plan(
        self,
        *,
        codebase_id: str,
        repository_context: Mapping[str, Any],
        graph_snapshot: CodeGraphSnapshot,
    ) -> GraphSurfacePlanningResult:
        inventory = map_repository_surfaces_to_graph(repository_context, graph_snapshot)
        grouping = group_connected_graph_targets(inventory, graph_snapshot)
        investigations: list[Investigation] = []
        gaps: list[GraphSurfacePlanningGap] = []
        for group in grouping.groups:
            if len(group.node_ids) > self.maximum_target_nodes:
                gaps.append(
                    GraphSurfacePlanningGap(
                        group_id=group.group_id,
                        surface_keys=group.surface_keys,
                        node_ids=group.node_ids,
                        reason="connected_surface_group_exceeds_planner_target_bound",
                    )
                )
                continue
            investigations.append(
                self.plan_group(
                    codebase_id=codebase_id,
                    target_node_ids=group.node_ids,
                    surface_context=group.surface_context,
                    stable_key=group.group_id,
                )
            )
        return GraphSurfacePlanningResult(
            snapshot_id=graph_snapshot.snapshot_id,
            inventory=inventory,
            grouping=grouping,
            investigations=tuple(investigations),
            planning_gaps=tuple(gaps),
        )
