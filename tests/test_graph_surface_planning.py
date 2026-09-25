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
from plaidnox_sast.persistence.repositories import unit_of_work


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
    coordinator = GraphSurfacePlanningCoordinator(
        lambda **arguments: planner.plan_targets(
            snapshot=snapshot,
            broker=broker,
            repository_context={},
            **arguments,
        ),
        persistence=persistence,
    )
    arguments = {
        "codebase_id": "codebase-a",
        "scan_id": "scan-a",
        "repository_context": _context(snapshot),
        "graph_snapshot": snapshot,
    }

    first = coordinator.plan(**arguments)
    resumed = GraphSurfacePlanningCoordinator(
        lambda **_arguments: pytest.fail("persisted investigation should be reused"),
        persistence=persistence,
    ).plan(**arguments)

    assert len(model_calls) == 1
    assert first.persisted_groups == 1
    assert first.reused_groups == 0
    assert resumed.persisted_groups == 0
    assert resumed.reused_groups == 1
    assert (
        resumed.investigations[0].investigation_id
        == first.investigations[0].investigation_id
    )
    assert (
        resumed.investigations[0].evidence_hash == first.investigations[0].evidence_hash
    )


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
