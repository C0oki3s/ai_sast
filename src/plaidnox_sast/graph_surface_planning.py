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
from .graphify_adapter import (
    CodeGraphSnapshot,
    investigation_graph_mismatches,
)
from .investigations import (
    Investigation,
    bind_storage_snapshot,
    investigation_from_payload,
    planning_context_hash,
    rebase_investigation,
)
from .persistence.repositories import (
    GraphifySnapshotValue,
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
    reused_group_ids: tuple[str, ...] = ()
    reusable_no_candidate_group_ids: tuple[str, ...] = ()

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

    def list_for_codebase(self, codebase_id: str) -> list[InvestigationValue]:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            return repository.list_investigations_for_codebase(codebase_id)

    def list_reusable_no_candidates(
        self, codebase_id: str, workflow_version: str
    ) -> list[InvestigationValue]:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            return repository.list_reusable_no_candidate_investigations(
                codebase_id, workflow_version
            )

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

    def record_group_status(
        self,
        scan_id: str,
        snapshot_id: str,
        group_id: str,
        status: str,
        investigation_id: str | None = None,
    ) -> SurfacePlanningValue:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            return repository.record_surface_planning_group(
                scan_id, snapshot_id, group_id, status, investigation_id
            )

    def transition_investigation(
        self, scan_id: str, investigation_id: str, state: str, checkpoint_ref: str | None = None
    ) -> InvestigationValue:
        """Persist an investigation lifecycle transition with revision checking."""
        with unit_of_work(self.factory, self.tenant_id) as repository:
            values = repository.list_investigations(scan_id)
            current = next((item for item in values if item.investigation_id == investigation_id), None)
            if current is None:
                raise PersistenceConflictError("investigation is absent from the active scan")
            return repository.transition_investigation(
                investigation_id,
                state,
                expected_revision=current.revision,
                checkpoint_ref=checkpoint_ref,
            )


class GraphifySnapshotOrmStore:
    """Persist Graphify's structural snapshot through Code Scanning's ORM."""

    def __init__(self, factory: sessionmaker[Session], tenant_id: str) -> None:
        self.factory = factory
        self.tenant_id = tenant_id

    def save(self, scan_id: str, snapshot_id: str, graph_snapshot: CodeGraphSnapshot) -> GraphifySnapshotValue:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            return repository.save_graphify_snapshot(scan_id, snapshot_id, graph_snapshot)

    def latest(
        self, codebase_id: str, *, excluding_scan_id: str | None = None
    ) -> GraphifySnapshotValue | None:
        with unit_of_work(self.factory, self.tenant_id) as repository:
            return repository.latest_graphify_snapshot(
                codebase_id, excluding_scan_id=excluding_scan_id
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
        invalidated_prior_investigation_ids: frozenset[str] = frozenset(),
        reusable_no_candidate_ids: frozenset[str] = frozenset(),
    ) -> GraphSurfacePlanningResult:
        inventory = map_repository_surfaces_to_graph(repository_context, graph_snapshot)
        grouping = group_connected_graph_targets(inventory, graph_snapshot)
        investigations: list[Investigation] = []
        gaps: list[GraphSurfacePlanningGap] = []
        reused_groups = 0
        reused_group_ids: list[str] = []
        reusable_no_candidate_group_ids: list[str] = []
        persisted_groups = 0
        durable_snapshot_id = storage_snapshot_id or graph_snapshot.snapshot_id
        existing_by_stable_key: dict[str, InvestigationValue] = {}
        prior_by_stable_key: dict[str, InvestigationValue] = {}
        reusable_no_candidate_by_stable_key: dict[str, InvestigationValue] = {}
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
            prior_values = self.persistence.list_for_codebase(codebase_id)
            for prior in prior_values:
                if prior.investigation_id in reusable_no_candidate_ids:
                    reusable_no_candidate_by_stable_key.setdefault(
                        prior.stable_key, prior
                    )
            for prior in prior_values:
                if prior.scan_id == scan_id or prior.stable_key in prior_by_stable_key:
                    continue
                prior_by_stable_key[prior.stable_key] = prior
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
                mismatches = investigation_graph_mismatches(
                    investigation,
                    graph_snapshot,
                    expected_planning_context_hash=planning_context_hash(
                        dict(repository_context),
                        tuple(dict(item) for item in group.surface_context),
                    ),
                )
                if mismatches or not _targets_match(investigation, group.node_ids):
                    raise PersistenceConflictError(
                        "stored same-scan investigation no longer matches its immutable graph evidence"
                    )
                investigations.append(investigation)
                reused_groups += 1
                reused_group_ids.append(group.group_id)
                if self.persistence is not None:
                    assert scan_id is not None
                    self.persistence.record_group_status(
                        scan_id,
                        durable_snapshot_id,
                        group.group_id,
                        "reused",
                        investigation.investigation_id,
                    )
                continue
            prior = reusable_no_candidate_by_stable_key.get(
                group.group_id
            ) or prior_by_stable_key.get(group.group_id)
            if prior is not None:
                prior_investigation = _restore_investigation(prior)
                expected_context_hash = planning_context_hash(
                    dict(repository_context), tuple(dict(item) for item in group.surface_context)
                )
                mismatches = investigation_graph_mismatches(
                    prior_investigation,
                    graph_snapshot,
                    expected_planning_context_hash=expected_context_hash,
                )
                if (
                    prior_investigation.codebase_id == codebase_id
                    and prior_investigation.investigation_id
                    not in invalidated_prior_investigation_ids
                    and not mismatches
                    and _targets_match(prior_investigation, group.node_ids)
                ):
                    investigation = rebase_investigation(
                        prior_investigation,
                        storage_snapshot_id=durable_snapshot_id,
                        graph_snapshot_id=graph_snapshot.snapshot_id,
                    )
                    if self.persistence is not None:
                        assert scan_id is not None
                        self.persistence.save(scan_id, investigation)
                        self.persistence.record_group_status(
                            scan_id,
                            durable_snapshot_id,
                            group.group_id,
                            "reused",
                            investigation.investigation_id,
                        )
                        persisted_groups += 1
                    investigations.append(investigation)
                    reused_groups += 1
                    reused_group_ids.append(group.group_id)
                    if prior_investigation.investigation_id in reusable_no_candidate_ids:
                        reusable_no_candidate_group_ids.append(group.group_id)
                    continue
            if self.persistence is not None:
                assert scan_id is not None
                self.persistence.record_group_status(
                    scan_id, durable_snapshot_id, group.group_id, "planning"
                )
            try:
                investigation = self.plan_group(
                    codebase_id=codebase_id,
                    target_node_ids=group.node_ids,
                    surface_context=group.surface_context,
                    stable_key=group.group_id,
                )
            except Exception:
                if self.persistence is not None:
                    assert scan_id is not None
                    self.persistence.record_group_status(
                        scan_id, durable_snapshot_id, group.group_id, "failed"
                    )
                raise
            if investigation.stable_key != group.group_id:
                raise PersistenceConflictError(
                    "planner returned an investigation for a different graph surface group"
                )
            investigation = bind_storage_snapshot(investigation, durable_snapshot_id)
            if investigation.investigation_id in reusable_no_candidate_ids:
                reusable_no_candidate_group_ids.append(group.group_id)
            if self.persistence is not None:
                assert scan_id is not None
                self.persistence.save(scan_id, investigation)
                persisted_groups += 1
            investigations.append(investigation)
            if self.persistence is not None:
                assert scan_id is not None
                self.persistence.record_group_status(
                    scan_id,
                    durable_snapshot_id,
                    group.group_id,
                    "planned",
                    investigation.investigation_id,
                )
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
            reused_group_ids=tuple(reused_group_ids),
            reusable_no_candidate_group_ids=tuple(reusable_no_candidate_group_ids),
        )


def _restore_investigation(value: InvestigationValue) -> Investigation:
    investigation = investigation_from_payload(dict(value.investigation_data))
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


def _targets_match(investigation: Investigation, expected_node_ids: tuple[str, ...]) -> bool:
    target_ref = investigation.target_ref
    current = target_ref.get("node_ids")
    if not isinstance(current, (list, tuple)):
        single = target_ref.get("node_id")
        current = [single] if isinstance(single, str) else []
    return set(current) == set(expected_node_ids)


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
                "planning_status": "gap" if group.group_id in oversized_group_ids else "pending",
                "investigation_id": None,
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
