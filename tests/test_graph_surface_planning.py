from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from plaidnox_sast.graph_context import GraphContextBroker
from plaidnox_sast.graph_planner import GraphInvestigationPlanner
from plaidnox_sast.graph_surface_planning import GraphSurfacePlanningCoordinator
from plaidnox_sast.graphify_adapter import CodeEdge, CodeGraphSnapshot, CodeNode


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
