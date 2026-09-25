from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.graph_context import GraphContextBroker
from plaidnox_sast.graph_planner import GraphInvestigationPlanner
from plaidnox_sast.graph_surface_planning import (
    GraphSurfacePlanningCoordinator,
    InvestigationOrmStore,
)
from plaidnox_sast.graphify_adapter import CodeEdge, CodeGraphSnapshot, CodeNode
from plaidnox_sast.persistence.models import Base
from plaidnox_sast.persistence.repositories import PersistenceConflictError, unit_of_work


def _snapshot(root: Path, *, connected: bool) -> CodeGraphSnapshot:
    source = root / "app.py"
    source.write_text(
        "def handle_request():\n    return load_account()\n", encoding="utf-8"
    )
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    nodes = (
        CodeNode("route", "app.py", 1, "handle_request", source_hash),
        CodeNode("service", "app.py", 2, "load_account", source_hash),
    )
    edges = (
        (CodeEdge("route", "service", "CALLS", "EXTRACTED", "app.py", 2, source_hash),)
        if connected
        else ()
    )
    return CodeGraphSnapshot(
        source_hashes={"app.py": source_hash},
        nodes=nodes,
        edges=edges,
        unresolved_edges=0,
        extractor_version="test",
    )


def _context(snapshot: CodeGraphSnapshot, *, include_unmapped: bool = False):
    location = {
        "path": "app.py",
        "start_line": 1,
        "end_line": 2,
        "grounding_status": "verified_source_location",
        "source_content_hash": snapshot.source_hashes["app.py"],
    }
    entries = [
        {
            "entry_id": "entry-account",
            "name": "Account request",
            "evidence_locations": [location],
        }
    ]
    if include_unmapped:
        entries.append({"entry_id": "unmapped", "name": "Missing source evidence"})
    return {"entry_points": entries}


def test_coordinator_maps_groups_and_plans_each_group_once(tmp_path: Path):
    snapshot = _snapshot(tmp_path, connected=True)
    broker = GraphContextBroker(tmp_path, snapshot)
    model_payloads = []
    planner = GraphInvestigationPlanner(
        lambda payload: (
            model_payloads.append(payload)
            or {
                "reason": "Review the account request and its downstream operation.",
                "security_questions": [
                    "Is the resource selected for this request owner-bound?"
                ],
                "supporting_node_ids": [],
                "supporting_edge_keys": [],
                "coverage_notes": [],
            }
        )
    )
    coordinator = GraphSurfacePlanningCoordinator(
        lambda **arguments: planner.plan_targets(
            snapshot=snapshot,
            broker=broker,
            repository_context={"business_context": "Accounts belong to customers."},
            **arguments,
        )
    )

    result = coordinator.plan(
        codebase_id="codebase-a",
        repository_context=_context(snapshot, include_unmapped=True),
        graph_snapshot=snapshot,
    )

    assert len(model_payloads) == 1
    assert len(result.investigations) == 1
    assert result.mapping_gap_count == 1
    assert result.planning_gaps == ()
    assert result.investigations[0].stable_key == result.grouping.groups[0].group_id
    assert model_payloads[0]["surface_context"][0]["mapping_status"] == "ambiguous"


def test_coordinator_reports_oversized_connected_groups_without_ai_call(tmp_path: Path):
    snapshot = _snapshot(tmp_path, connected=True)
    coordinator = GraphSurfacePlanningCoordinator(
        lambda **_arguments: pytest.fail("oversized graph group reached the model"),
        maximum_target_nodes=1,
    )

    result = coordinator.plan(
        codebase_id="codebase-a",
        repository_context=_context(snapshot),
        graph_snapshot=snapshot,
    )

    assert not result.investigations
    assert len(result.planning_gaps) == 1
    assert (
        result.planning_gaps[0].reason
        == "connected_surface_group_exceeds_planner_target_bound"
    )
    assert len(result.planning_gaps[0].surface_keys) == 1


def test_coordinator_persists_each_plan_and_reuses_it_after_restart(tmp_path: Path):
    snapshot = _snapshot(tmp_path, connected=True)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-a", "example/account", "Account")
        repository.add_snapshot(
            snapshot.snapshot_id,
            "codebase-a",
            "revision-a",
            "tree-hash-a",
            "context-v1",
        )
        repository.start_scan(
            "scan-a", "codebase-a", snapshot.snapshot_id, "deep", "workflow-v1"
        )

    persistence = InvestigationOrmStore(factory, "tenant-a")
    broker = GraphContextBroker(tmp_path, snapshot)
    model_calls = []
    planner = GraphInvestigationPlanner(
        lambda payload: (
            model_calls.append(payload)
            or {
                "reason": "Review account identity selection.",
                "security_questions": ["Can another principal select this account?"],
                "supporting_node_ids": [],
                "supporting_edge_keys": [],
                "coverage_notes": [],
            }
        )
    )
    repository_context = _context(snapshot, include_unmapped=True)
    fail_before_first_plan = True

    def plan_group(**arguments):
        nonlocal fail_before_first_plan
        if fail_before_first_plan:
            fail_before_first_plan = False
            raise RuntimeError("synthetic planner interruption")
        return planner.plan_targets(
            snapshot=snapshot,
            broker=broker,
            repository_context=repository_context,
            **arguments,
        )

    coordinator = GraphSurfacePlanningCoordinator(
        plan_group,
        persistence=persistence,
    )
    arguments = {
        "codebase_id": "codebase-a",
        "scan_id": "scan-a",
        "repository_context": repository_context,
        "graph_snapshot": snapshot,
    }

    with pytest.raises(RuntimeError, match="synthetic planner interruption"):
        coordinator.plan(**arguments)
    with unit_of_work(factory, "tenant-a") as repository:
        interrupted = repository.get_surface_planning("scan-a")
    assert interrupted is not None
    assert interrupted.state == "planning"
    assert interrupted.planning_data["mapping_counts"]["no_location"] == 1
    assert len(interrupted.planning_data["unmapped_surface_keys"]) == 1
    assert interrupted.planning_data["groups"][0]["planning_status"] == "failed"
    with pytest.raises(PersistenceConflictError, match="groups remain unresolved"):
        persistence.complete_surface_plan("scan-a", snapshot.snapshot_id)

    first = coordinator.plan(**arguments)
    assert len(model_calls) == 1
    assert first.persisted_groups == 1
    assert first.reused_groups == 0
    with unit_of_work(factory, "tenant-a") as repository:
        completed = repository.get_surface_planning("scan-a")
    assert completed is not None
    assert completed.state == "complete"
    assert completed.revision == 6
    assert completed.planning_data["groups"][0]["planning_status"] == "planned"
    assert completed.planning_data["groups"][0]["investigation_id"] == first.investigations[0].investigation_id
    resumed = GraphSurfacePlanningCoordinator(
        lambda **_arguments: pytest.fail("persisted investigation should be reused"),
        persistence=persistence,
    ).plan(**arguments)
    assert resumed.persisted_groups == 0
    assert resumed.reused_groups == 1
    assert (
        resumed.investigations[0].investigation_id
        == first.investigations[0].investigation_id
    )
    assert (
        resumed.investigations[0].evidence_hash == first.investigations[0].evidence_hash
    )


def test_coordinator_reuses_compatible_plan_across_codebase_snapshots(tmp_path: Path):
    first_snapshot = _snapshot(tmp_path, connected=True)
    unrelated = tmp_path / "unrelated.py"
    unrelated.write_text("def unrelated():\n    return 0\n", encoding="utf-8")
    second_snapshot = CodeGraphSnapshot(
        source_hashes={
            **first_snapshot.source_hashes,
            "unrelated.py": hashlib.sha256(unrelated.read_bytes()).hexdigest(),
        },
        nodes=first_snapshot.nodes,
        edges=first_snapshot.edges,
        unresolved_edges=first_snapshot.unresolved_edges,
        extractor_version=first_snapshot.extractor_version,
    )
    assert first_snapshot.snapshot_id != second_snapshot.snapshot_id

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-a", "example/account", "Account")
        for scan_id, snapshot, revision in (
            ("scan-a", first_snapshot, "revision-a"),
            ("scan-b", second_snapshot, "revision-b"),
        ):
            repository.add_snapshot(
                snapshot.snapshot_id,
                "codebase-a",
                revision,
                f"tree-{revision}",
                "context-v1",
            )
            repository.start_scan(
                scan_id, "codebase-a", snapshot.snapshot_id, "deep", "workflow-v1"
            )

    persistence = InvestigationOrmStore(factory, "tenant-a")
    repository_context = _context(first_snapshot)
    model_calls = []
    planner = GraphInvestigationPlanner(
        lambda payload: (
            model_calls.append(payload)
            or {
                "reason": "Review the account identity boundary.",
                "security_questions": ["Can the caller select another account?"],
                "supporting_node_ids": [],
                "supporting_edge_keys": [],
                "coverage_notes": [],
            }
        )
    )
    first = GraphSurfacePlanningCoordinator(
        lambda **arguments: planner.plan_targets(
            snapshot=first_snapshot,
            broker=GraphContextBroker(tmp_path, first_snapshot),
            repository_context=repository_context,
            **arguments,
        ),
        persistence=persistence,
    ).plan(
        codebase_id="codebase-a",
        scan_id="scan-a",
        repository_context=repository_context,
        graph_snapshot=first_snapshot,
    )
    assert first.persisted_groups == 1
    original_id = first.investigations[0].investigation_id

    second = GraphSurfacePlanningCoordinator(
        lambda **_arguments: pytest.fail("compatible prior plan should be reused"),
        persistence=persistence,
    ).plan(
        codebase_id="codebase-a",
        scan_id="scan-b",
        repository_context=_context(second_snapshot),
        graph_snapshot=second_snapshot,
    )

    reused = second.investigations[0]
    assert second.reused_groups == 1
    assert second.persisted_groups == 1
    assert len(model_calls) == 1
    assert reused.investigation_id != original_id
    assert reused.graph_snapshot_id == second_snapshot.snapshot_id
    assert reused.state == "planned"
    assert reused.checkpoint_ref is None
    assert all(
        reference.get("snapshot_id") == second_snapshot.snapshot_id
        for reference in reused.graph_refs
    )
    assert all(
        dependency["key"] == second_snapshot.snapshot_id
        and dependency["hash"] == second_snapshot.snapshot_id
        for dependency in reused.context_dependencies
        if dependency["kind"] == "graph_snapshot"
    )


def test_coordinator_does_not_reuse_plan_when_business_context_changes(tmp_path: Path):
    snapshot = _snapshot(tmp_path, connected=True)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-a", "example/account", "Account")
        for scan_id in ("scan-a", "scan-b"):
            snapshot_id = f"{scan_id}-snapshot"
            repository.add_snapshot(
                snapshot_id,
                "codebase-a",
                scan_id,
                f"tree-{scan_id}",
                "context-v1",
            )
            repository.start_scan(
                scan_id, "codebase-a", snapshot_id, "deep", "workflow-v1"
            )

    persistence = InvestigationOrmStore(factory, "tenant-a")
    model_calls = []
    planner = GraphInvestigationPlanner(
        lambda payload: (
            model_calls.append(payload)
            or {
                "reason": "Review the account identity boundary.",
                "security_questions": ["Can the caller select another account?"],
                "supporting_node_ids": [],
                "supporting_edge_keys": [],
                "coverage_notes": [],
            }
        )
    )
    context = {**_context(snapshot), "business_context": "Accounts are customer-owned."}
    GraphSurfacePlanningCoordinator(
        lambda **arguments: planner.plan_targets(
            snapshot=snapshot,
            broker=GraphContextBroker(tmp_path, snapshot),
            repository_context=context,
            **arguments,
        ),
        persistence=persistence,
    ).plan(
        codebase_id="codebase-a",
        scan_id="scan-a",
        repository_context=context,
        graph_snapshot=snapshot,
        storage_snapshot_id="scan-a-snapshot",
    )
    changed_context = {**context, "business_context": "Accounts belong to organizations."}
    rerun = GraphSurfacePlanningCoordinator(
        lambda **arguments: planner.plan_targets(
            snapshot=snapshot,
            broker=GraphContextBroker(tmp_path, snapshot),
            repository_context=changed_context,
            **arguments,
        ),
        persistence=persistence,
    ).plan(
        codebase_id="codebase-a",
        scan_id="scan-b",
        repository_context=changed_context,
        graph_snapshot=snapshot,
        storage_snapshot_id="scan-b-snapshot",
    )

    assert rerun.reused_groups == 0
    assert rerun.persisted_groups == 1
    assert len(model_calls) == 2


def test_coordinator_binds_graph_evidence_to_durable_scan_snapshot(tmp_path: Path):
    snapshot = _snapshot(tmp_path, connected=True)
    durable_snapshot_id = "snapshot-db-identity"
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-a", "example/account", "Account")
        repository.add_snapshot(
            durable_snapshot_id,
            "codebase-a",
            "revision-a",
            "tree-hash-a",
            "context-v1",
        )
        repository.start_scan(
            "scan-a", "codebase-a", durable_snapshot_id, "deep", "workflow-v1"
        )

    broker = GraphContextBroker(tmp_path, snapshot)
    planner = GraphInvestigationPlanner(
        lambda _payload: {
            "reason": "Review the account identity selection.",
            "security_questions": ["Can a caller select another principal's account?"],
            "supporting_node_ids": [],
            "supporting_edge_keys": [],
            "coverage_notes": [],
        }
    )
    result = GraphSurfacePlanningCoordinator(
        lambda **arguments: planner.plan_targets(
            snapshot=snapshot,
            broker=broker,
            repository_context={},
            **arguments,
        ),
        persistence=InvestigationOrmStore(factory, "tenant-a"),
    ).plan(
        codebase_id="codebase-a",
        scan_id="scan-a",
        repository_context=_context(snapshot),
        graph_snapshot=snapshot,
        storage_snapshot_id=durable_snapshot_id,
    )

    assert len(result.investigations) == 1
    investigation = result.investigations[0]
    assert investigation.snapshot_id == durable_snapshot_id
    assert investigation.graph_snapshot_id == snapshot.snapshot_id
    assert investigation.graph_snapshot_id != investigation.snapshot_id
    with unit_of_work(factory, "tenant-a") as repository:
        saved = repository.list_investigations("scan-a")
        surface_plan = repository.get_surface_planning("scan-a")
    assert saved[0].snapshot_id == durable_snapshot_id
    assert saved[0].investigation_data["graph_snapshot_id"] == snapshot.snapshot_id
    assert surface_plan is not None
    assert surface_plan.snapshot_id == durable_snapshot_id
    assert surface_plan.planning_data["snapshot_id"] == snapshot.snapshot_id


def test_coordinator_plans_100k_loc_repository_in_bounded_graph_groups(
    tmp_path: Path,
):
    """Exercise large surface planning without a live Graphify/model provider."""
    nodes = []
    edges = []
    source_hashes = {}
    source_characters = 0
    repository_context = {"entry_points": []}

    for file_index in range(100):
        path = f"services/service_{file_index:03d}.py"
        source = tmp_path / path
        source.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# indexed source line\n"] * 1000
        file_symbols = []
        for symbol_index in range(8):
            line = symbol_index * 100 + 1
            node_id = f"service-{file_index:03d}-handler-{symbol_index}"
            label = f"handle_{file_index}_{symbol_index}"
            lines[line - 1] = f"def {label}():\n"
            file_symbols.append((node_id, label, line))
        source.write_text("".join(lines), encoding="utf-8")
        source_content = source.read_bytes()
        source_characters += len(source_content)
        source_hash = hashlib.sha256(source_content).hexdigest()
        source_hashes[path] = source_hash
        file_nodes = []
        for node_id, label, line in file_symbols:
            node = CodeNode(node_id, path, line, label, source_hash)
            nodes.append(node)
            file_nodes.append(node)
            repository_context["entry_points"].append(
                {
                    "entry_id": node_id,
                    "name": label,
                    "evidence_locations": [
                        {
                            "path": path,
                            "start_line": line,
                            "end_line": line,
                            "grounding_status": "verified_source_location",
                            "source_content_hash": source_hash,
                        }
                    ],
                }
            )
        edges.extend(
            CodeEdge(
                left.id,
                right.id,
                "CALLS",
                "EXTRACTED",
                path,
                right.line,
                source_hash,
            )
            for left, right in zip(file_nodes, file_nodes[1:])
        )

    snapshot = CodeGraphSnapshot(
        source_hashes=source_hashes,
        nodes=tuple(nodes),
        edges=tuple(edges),
        unresolved_edges=0,
        extractor_version="synthetic-large-fixture",
    )
    broker = GraphContextBroker(tmp_path, snapshot)
    model_payload_sizes = []
    planner = GraphInvestigationPlanner(
        lambda payload: (
            model_payload_sizes.append(
                len(json.dumps(payload, sort_keys=True, ensure_ascii=False))
            )
            or {
                "reason": "Review this source-grounded service flow.",
                "security_questions": [
                    "Can untrusted request data reach a sensitive effect without authorization?"
                ],
                "supporting_node_ids": [],
                "supporting_edge_keys": [],
                "coverage_notes": [],
            }
        )
    )
    coordinator = GraphSurfacePlanningCoordinator(
        lambda **arguments: planner.plan_targets(
            snapshot=snapshot,
            broker=broker,
            repository_context={},
            **arguments,
        )
    )

    result = coordinator.plan(
        codebase_id="large-codebase",
        repository_context=repository_context,
        graph_snapshot=snapshot,
    )

    limits = planner.limits
    assert len(repository_context["entry_points"]) == 800
    assert len(snapshot.nodes) == 800
    assert len(snapshot.edges) == 700
    assert len(result.inventory.targets) == 800
    assert result.inventory.mapping_counts["mapped"] == 800
    assert len(result.grouping.groups) == 100
    assert len(result.investigations) == 100
    assert all(len(group.node_ids) == 8 for group in result.grouping.groups)
    assert not result.mapping_gap_count
    assert not result.grouping.unmapped_surface_keys
    assert not result.planning_gaps
    assert len(model_payload_sizes) == len(result.investigations)
    assert max(model_payload_sizes) <= limits.maximum_input_characters
    assert all(size < 20_000 for size in model_payload_sizes)
    assert sum(model_payload_sizes) < source_characters


def test_coordinator_reuses_terminal_no_candidate_for_identical_snapshot(tmp_path: Path):
    from plaidnox_sast.assets import load_json

    snapshot = _snapshot(tmp_path, connected=True)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    workflow_version = str(load_json("prompts/manifest.json")["version"])
    with unit_of_work(factory, "tenant-a") as repository:
        repository.add_codebase("codebase-a", "example/account", "Account")
        repository.add_snapshot("snapshot-a", "codebase-a", "revision-a", "tree-a", "context-v1")
        repository.start_scan("scan-a", "codebase-a", "snapshot-a", "deep", workflow_version)

    broker = GraphContextBroker(tmp_path, snapshot)
    repository_context = _context(snapshot)
    planner = GraphInvestigationPlanner(
        lambda _payload: {
            "reason": "Review account identity selection.",
            "security_questions": ["Can another principal select this account?"],
            "supporting_node_ids": [],
            "supporting_edge_keys": [],
            "coverage_notes": [],
        }
    )
    store = InvestigationOrmStore(factory, "tenant-a")
    first = GraphSurfacePlanningCoordinator(
        lambda **arguments: planner.plan_targets(
            snapshot=snapshot, broker=broker, repository_context=repository_context, **arguments
        ),
        persistence=store,
    ).plan(
        codebase_id="codebase-a", scan_id="scan-a", repository_context=repository_context,
        graph_snapshot=snapshot, storage_snapshot_id="snapshot-a",
    )
    prior = first.investigations[0]
    with unit_of_work(factory, "tenant-a") as repository:
        repository.transition_investigation(prior.investigation_id, "running", expected_revision=1)
        repository.transition_investigation(prior.investigation_id, "no_candidate", expected_revision=2)
        repository.finish_scan("scan-a", coverage_complete=True, scan_status="SUCCESSFUL")
        repository.start_scan("scan-b", "codebase-a", "snapshot-a", "deep", workflow_version)

    reusable_ids = frozenset(
        item.investigation_id
        for item in store.list_reusable_no_candidates("codebase-a", workflow_version)
    )
    assert prior.investigation_id in reusable_ids
    second = GraphSurfacePlanningCoordinator(
        lambda **_arguments: pytest.fail("compatible investigation should not be replanned"),
        persistence=store,
    ).plan(
        codebase_id="codebase-a", scan_id="scan-b", repository_context=repository_context,
        graph_snapshot=snapshot, storage_snapshot_id="snapshot-a",
        reusable_no_candidate_ids=reusable_ids,
    )
    assert second.reusable_no_candidate_group_ids == (prior.stable_key,)
    assert second.investigations[0].investigation_id == prior.investigation_id
    assert store.list_for_scan("scan-b") == []
