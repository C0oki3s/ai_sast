"""Coordinate source-grounded security-surface groups into investigations."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from .assets import load_json
from .graph_targets import (
    GraphTargetInventory,
    GraphTargetMappingStatus,
    GraphTargetGrouping,
    group_connected_graph_targets,
    map_repository_surfaces_to_graph,
)
from .graphify_adapter import CodeGraphSnapshot
from .investigations import Investigation, bind_storage_snapshot, validate_investigation
from .persistence.repositories import (
    InvestigationValue,
    PersistenceConflictError,
    SurfacePlanningValue,
    unit_of_work,
)


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
    reused_groups: int = 0
    persisted_groups: int = 0

    @property
    def mapping_gap_count(self) -> int:
        return sum(
            target.mapping_status is not GraphTargetMappingStatus.MAPPED
            and target.mapping_status is not GraphTargetMappingStatus.AMBIGUOUS
            for target in self.inventory.targets
        )


class InvestigationOrmStore:
    """Commit each completed planning unit through its own tenant ORM transaction."""

    def __init__(self, factory: sessionmaker[Session], tenant_id: str) -> None:
        self.factory = factory
        self.tenant_id = tenant_id

    def list_for_scan(self, scan_id: str) -> list[InvestigationValue]:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            return repository.list_investigations(scan_id)

    def save(self, scan_id: str, investigation: Investigation) -> InvestigationValue:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            return repository.save_investigation(scan_id, investigation)

    def save_surface_plan(
        self, scan_id: str, snapshot_id: str, planning_data: dict[str, Any]
    ) -> SurfacePlanningValue:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            return repository.save_surface_planning(scan_id, snapshot_id, planning_data)

    def complete_surface_plan(
        self, scan_id: str, snapshot_id: str
    ) -> SurfacePlanningValue:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            return repository.complete_surface_planning(scan_id, snapshot_id)


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
        persistence: InvestigationOrmStore | None = None,
    ) -> None:
        self.plan_group = plan_group
        self.persistence = persistence
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
        scan_id: str | None = None,
        repository_context: Mapping[str, Any],
        graph_snapshot: CodeGraphSnapshot,
        storage_snapshot_id: str | None = None,
    ) -> GraphSurfacePlanningResult:
        inventory = map_repository_surfaces_to_graph(repository_context, graph_snapshot)
        grouping = group_connected_graph_targets(inventory, graph_snapshot)
        investigations: list[Investigation] = []
        gaps: list[GraphSurfacePlanningGap] = []
        reused_groups = 0
        persisted_groups = 0
        durable_snapshot_id = storage_snapshot_id or graph_snapshot.snapshot_id
        existing_by_stable_key: dict[str, InvestigationValue] = {}
        if self.persistence is not None:
            if not scan_id:
                raise ValueError(
                    "scan_id is required when investigation persistence is configured"
                )
            for existing in self.persistence.list_for_scan(scan_id):
                if existing.snapshot_id != durable_snapshot_id:
                    continue
                if existing.stable_key in existing_by_stable_key:
                    raise PersistenceConflictError(
                        "multiple stored investigation versions share one surface group and snapshot"
                    )
                existing_by_stable_key[existing.stable_key] = existing
            self.persistence.save_surface_plan(
                scan_id,
                durable_snapshot_id,
                _surface_plan_data(inventory, grouping, self.maximum_target_nodes),
            )
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
            existing = existing_by_stable_key.get(group.group_id)
            if existing is not None:
                investigation = _restore_investigation(existing)
                if investigation.codebase_id != codebase_id:
                    raise PersistenceConflictError(
                        "stored investigation belongs to another codebase"
                    )
                investigations.append(investigation)
                reused_groups += 1
                continue
            investigation = self.plan_group(
                codebase_id=codebase_id,
                target_node_ids=group.node_ids,
                surface_context=group.surface_context,
                stable_key=group.group_id,
            )
            if investigation.stable_key != group.group_id:
                raise PersistenceConflictError(
                    "planner returned an investigation for a different graph surface group"
                )
            investigation = bind_storage_snapshot(investigation, durable_snapshot_id)
            if self.persistence is not None:
                assert scan_id is not None
                self.persistence.save(scan_id, investigation)
                persisted_groups += 1
            investigations.append(investigation)
        if self.persistence is not None:
            assert scan_id is not None
            self.persistence.complete_surface_plan(scan_id, durable_snapshot_id)
        return GraphSurfacePlanningResult(
            snapshot_id=graph_snapshot.snapshot_id,
            inventory=inventory,
            grouping=grouping,
            investigations=tuple(investigations),
            planning_gaps=tuple(gaps),
            reused_groups=reused_groups,
            persisted_groups=persisted_groups,
        )


def _restore_investigation(value: InvestigationValue) -> Investigation:
    data = dict(value.investigation_data)
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
    if (
        investigation.investigation_id != value.investigation_id
        or investigation.snapshot_id != value.snapshot_id
        or investigation.stable_key != value.stable_key
        or investigation.evidence_hash != value.evidence_hash
        or investigation.state != value.state
    ):
        raise PersistenceConflictError(
            "stored investigation row conflicts with its payload"
        )
    return investigation


def _surface_plan_data(
    inventory: GraphTargetInventory,
    grouping: GraphTargetGrouping,
    maximum_target_nodes: int,
) -> dict[str, Any]:
    oversized_group_ids = {
        group.group_id
        for group in grouping.groups
        if len(group.node_ids) > maximum_target_nodes
    }
    return {
        "schema_version": 1,
        # Preserve the original ledger field for records created before the
        # pipeline distinguished Graphify and ORM snapshot identities.
        "snapshot_id": inventory.snapshot_id,
        "maximum_target_nodes": maximum_target_nodes,
        "mapping_counts": inventory.mapping_counts,
        "surface_targets": [
            {
                "surface_key": target.surface_key,
                "collection": target.collection,
                "label": target.label,
                "mapping_status": target.mapping_status.value,
                "node_ids": list(target.node_ids),
                "source_locations": list(target.source_locations),
                "gap_reason": target.gap_reason,
            }
            for target in inventory.targets
        ],
        "groups": [
            {
                "group_id": group.group_id,
                "surface_keys": list(group.surface_keys),
                "node_ids": list(group.node_ids),
                "planning_status": (
                    "gap"
                    if group.group_id in oversized_group_ids
                    else "eligible_for_planning"
                ),
            }
            for group in grouping.groups
        ],
        "unmapped_surface_keys": list(grouping.unmapped_surface_keys),
        "planning_gaps": [
            {
                "group_id": group.group_id,
                "surface_keys": list(group.surface_keys),
                "node_ids": list(group.node_ids),
                "reason": "connected_surface_group_exceeds_planner_target_bound",
            }
            for group in grouping.groups
            if group.group_id in oversized_group_ids
        ],
    }
