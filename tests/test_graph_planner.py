from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from plaidnox_sast.graph_context import GraphContextBroker
from plaidnox_sast.ai import AIRepositoryContext, PlaidNoxDeepHuntAgent
from plaidnox_sast.graph_planner import (
    GraphInvestigationPlanner,
    GraphPlanningError,
    GraphPlanningLimits,
    _select_security_summaries,
)
from plaidnox_sast.graphify_adapter import (
    CodeGraphSnapshot,
    CodeNode,
    graph_node_neighborhood_hash,
    normalize_extraction,
)
from plaidnox_sast.models import ModelTier


def test_graph_planner_target_batch_limit_is_loaded_from_runtime_asset():
    assert GraphPlanningLimits.configured().maximum_target_nodes == 12


def test_persisted_security_summaries_are_scoped_to_graph_source_paths():
    selected = _select_security_summaries(
        [
            {
                "symbol_id": "symbol-a",
                "content_hash": "hash-a",
                "facts": [
                    {"kind": "indexed_symbol", "path": "account.py"},
                    {"kind": "indexed_symbol", "path": "unrelated.py"},
                ],
            }
        ],
        source_paths={"account.py"},
        maximum=4,
        maximum_facts=3,
    )

    assert selected[0]["symbol_id"] == "symbol-a"
    assert [item["path"] for item in selected[0]["facts"]] == ["account.py"]
    assert selected[0]["provenance"] == "persisted_tree_sitter_syntax_summary"


def test_agent_loads_persisted_summaries_for_graph_targets(tmp_path: Path):
    snapshot = _graph(tmp_path)
    target = next(node for node in snapshot.nodes if node.label == "update_account()")

    class Store:
        def list_security_summaries(self, context_id):
            assert context_id == "ctx-current"
            return [
                {
                    "symbol_id": "summary-account",
                    "content_hash": "summary-hash",
                    "facts": [{"kind": "indexed_symbol", "path": "account.py"}],
                },
                {
                    "symbol_id": "summary-other",
                    "content_hash": "other-hash",
                    "facts": [{"kind": "indexed_symbol", "path": "other.py"}],
                },
            ]

    agent = object.__new__(PlaidNoxDeepHuntAgent)
    agent.context_store = Store()
    agent.event_sink = None
    context = AIRepositoryContext(
        codebase="codebase",
        revision="revision",
        architecture="",
        applications=[],
        source_inventory=[],
        source_tree=[],
        graph_symbols=0,
        graph_routes=0,
        context_fabric={"context_id": "ctx-current"},
    )

    summaries = agent._load_graph_planner_security_summaries(
        context, snapshot, (target.id,)
    )

    assert [item["symbol_id"] for item in summaries] == ["summary-account"]


def _graph(root: Path):
    source = root / "account.py"
    source.write_text(
        "def update_account(principal, account_id):\n"
        "    account = load_account(account_id)\n"
        "    return account.save()\n\n"
        "def load_account(account_id):\n"
        "    return database.get(account_id)\n",
        encoding="utf-8",
    )
    extracted = {
        "nodes": [
            {
                "id": "raw-update",
                "label": "update_account()",
                "source_file": "account.py",
                "source_location": "L1",
            },
            {
                "id": "raw-load",
                "label": "load_account()",
                "source_file": "account.py",
                "source_location": "L5",
            },
        ],
        "edges": [
            {
                "source": "raw-update",
                "target": "raw-load",
                "relation": "calls",
                "confidence": "INFERRED",
                "source_file": "account.py",
                "source_location": "L2",
            }
        ],
    }
    return normalize_extraction(root, [source], extracted)


def test_graph_planner_builds_source_grounded_open_ended_investigation(tmp_path: Path):
    snapshot = _graph(tmp_path)
    broker = GraphContextBroker(tmp_path, snapshot)
    target = next(node for node in snapshot.nodes if node.label == "update_account()")
    observed = []

    def complete(payload):
        observed.append(payload)
        edge = payload["graph_edges"][0]
        node_id = next(
            node["node_id"]
            for node in payload["graph_nodes"]
            if node["label"] == "load_account()"
        )
        return {
            "reason": "This function loads and saves a caller-selected account.",
            "security_questions": [
                "Is the selected account bound to the authenticated principal?"
            ],
            "supporting_node_ids": [node_id],
            "supporting_edge_keys": [edge["edge_key"]],
            "coverage_notes": [],
        }

    planner = GraphInvestigationPlanner(complete)
    result = planner.plan_target(
        codebase_id="codebase-a",
        snapshot=snapshot,
        broker=broker,
        target_node_id=target.id,
        repository_context={"business_context": "Accounts are customer-owned."},
        security_summaries=[
            {
                "symbol_id": "summary-account",
                "content_hash": "summary-hash",
                "facts": [
                    {"kind": "indexed_symbol", "path": "account.py", "name": "update_account"}
                ],
                "dependency_symbol_ids": [],
                "unresolved_relationship_ids": [],
            }
        ],
    )

    assert len(observed) == 1
    assert observed[0]["cached_security_summaries"][0]["symbol_id"] == "summary-account"
    assert observed[0]["cached_security_summaries"][0]["provenance"] == "persisted_tree_sitter_syntax_summary"
    assert result.target_ref["node_id"] == target.id
    assert result.security_questions == (
        "Is the selected account bound to the authenticated principal?",
    )
    assert len(result.source_windows) == 2
    assert {item["provenance"] for item in result.graph_refs if "edge_id" in item} == {
        "INFERRED"
    }
    neighborhood_dependencies = {
        item["key"]: item["hash"]
        for item in result.context_dependencies
        if item["kind"] == "graph_node_neighborhood"
    }
    assert set(neighborhood_dependencies) == {
        item["node_id"] for item in result.graph_refs if "node_id" in item
    }
    assert all(
        neighborhood_dependencies[node_id]
        == graph_node_neighborhood_hash(snapshot, node_id)
        for node_id in neighborhood_dependencies
    )
    assert result.evidence_hash
    assert result.state == "planned"


def test_graph_planner_plans_connected_targets_in_one_bounded_call(tmp_path: Path):
    snapshot = _graph(tmp_path)
    broker = GraphContextBroker(tmp_path, snapshot)
    targets = tuple(node.id for node in snapshot.nodes)
    observed = []

    def complete(payload):
        observed.append(payload)
        return {
            "reason": "Review the account selection and persistence path.",
            "security_questions": [
                "Can the selected account differ from the authenticated owner?"
            ],
            "supporting_node_ids": [],
            "supporting_edge_keys": [],
            "coverage_notes": [],
        }

    result = GraphInvestigationPlanner(complete).plan_targets(
        codebase_id="codebase-a",
        snapshot=snapshot,
        broker=broker,
        target_node_ids=targets,
        repository_context={"business_context": "Accounts are customer-owned."},
        surface_context=[
            {
                "surface_key": "surface-a",
                "collection": "entry_points",
                "label": "Account update endpoint",
                "node_ids": list(targets),
                "mapping_status": "mapped",
                "source_locations": [
                    {
                        "path": "account.py",
                        "start_line": 1,
                        "end_line": 5,
                        "source_hash": snapshot.source_hashes["account.py"],
                    }
                ],
            }
        ],
        stable_key="surface-group:account-update",
    )

    assert len(observed) == 1
    assert len(observed[0]["targets"]) == 2
    assert observed[0]["surface_context"][0]["surface_key"] == "surface-a"
    assert result.stable_key == "surface-group:account-update"
    assert result.target_ref["node_ids"] == sorted(targets)
    assert len(result.source_windows) == 2


def test_graph_planner_rejects_target_group_above_configured_bound(tmp_path: Path):
    snapshot = _graph(tmp_path)
    limits = GraphPlanningLimits(1, 1, 5, 5, 80000, maximum_target_nodes=1)
    planner = GraphInvestigationPlanner(
        lambda _payload: pytest.fail("oversized target group reached the model"),
        limits=limits,
    )

    with pytest.raises(
        GraphPlanningError, match="target group exceeds its configured bound"
    ):
        planner.plan_targets(
            codebase_id="codebase-a",
            snapshot=snapshot,
            broker=GraphContextBroker(tmp_path, snapshot),
            target_node_ids=tuple(node.id for node in snapshot.nodes),
            repository_context={},
        )


def test_graph_planner_rejects_unconnected_target_nodes(tmp_path: Path):
    snapshot = _graph(tmp_path)
    unrelated = CodeNode(
        "health", "account.py", 1, "health_check", snapshot.source_hashes["account.py"]
    )
    snapshot = CodeGraphSnapshot(
        source_hashes=snapshot.source_hashes,
        nodes=(*snapshot.nodes, unrelated),
        edges=snapshot.edges,
        unresolved_edges=snapshot.unresolved_edges,
        extractor_version=snapshot.extractor_version,
    )
    planner = GraphInvestigationPlanner(
        lambda _payload: pytest.fail("disconnected targets reached the model")
    )

    with pytest.raises(
        GraphPlanningError, match="do not form a connected Graphify group"
    ):
        planner.plan_targets(
            codebase_id="codebase-a",
            snapshot=snapshot,
            broker=GraphContextBroker(tmp_path, snapshot),
            target_node_ids=(snapshot.nodes[0].id, unrelated.id),
            repository_context={},
        )


def test_graph_planner_rejects_surface_context_with_stale_source_hash(tmp_path: Path):
    snapshot = _graph(tmp_path)
    targets = tuple(node.id for node in snapshot.nodes)
    planner = GraphInvestigationPlanner(
        lambda _payload: pytest.fail("stale surface context reached the model")
    )

    with pytest.raises(GraphPlanningError, match="not snapshot-grounded"):
        planner.plan_targets(
            codebase_id="codebase-a",
            snapshot=snapshot,
            broker=GraphContextBroker(tmp_path, snapshot),
            target_node_ids=targets,
            repository_context={},
            surface_context=[
                {
                    "surface_key": "surface-a",
                    "collection": "entry_points",
                    "label": "Account update endpoint",
                    "node_ids": list(targets),
                    "mapping_status": "mapped",
                    "source_locations": [
                        {
                            "path": "account.py",
                            "start_line": 1,
                            "end_line": 5,
                            "source_hash": "0" * 64,
                        }
                    ],
                }
            ],
        )


@pytest.mark.parametrize(
    "invented_field", ["supporting_node_ids", "supporting_edge_keys"]
)
def test_graph_planner_rejects_unobserved_relationships(
    tmp_path: Path, invented_field: str
):
    snapshot = _graph(tmp_path)
    target = next(node for node in snapshot.nodes if node.label == "update_account()")
    result = {
        "reason": "Investigate the target.",
        "security_questions": ["Is authorization enforced?"],
        "supporting_node_ids": [],
        "supporting_edge_keys": [],
        "coverage_notes": [],
    }
    result[invented_field] = [
        "f" * 64 if invented_field == "supporting_edge_keys" else "invented-reference"
    ]
    planner = GraphInvestigationPlanner(lambda _payload: result)

    with pytest.raises(GraphPlanningError, match="outside the supplied graph slice"):
        planner.plan_target(
            codebase_id="codebase-a",
            snapshot=snapshot,
            broker=GraphContextBroker(tmp_path, snapshot),
            target_node_id=target.id,
            repository_context={},
        )


def test_graph_planner_rejects_oversized_context_instead_of_sending_it(tmp_path: Path):
    snapshot = _graph(tmp_path)
    target = next(node for node in snapshot.nodes if node.label == "update_account()")
    planner = GraphInvestigationPlanner(
        lambda _payload: pytest.fail("oversized packet reached the model"),
        limits=GraphPlanningLimits(1, 1, 5, 5, 32),
    )

    with pytest.raises(GraphPlanningError, match="exceeded its configured size"):
        planner.plan_target(
            codebase_id="codebase-a",
            snapshot=snapshot,
            broker=GraphContextBroker(tmp_path, snapshot),
            target_node_id=target.id,
            repository_context={"business_context": "x" * 256},
        )


def test_agent_routes_graph_planning_through_configured_structured_model_call(
    tmp_path: Path,
):
    snapshot = _graph(tmp_path)
    target = next(node for node in snapshot.nodes if node.label == "update_account()")

    class FakeResponses:
        kwargs = None

        def create(self, **kwargs):
            self.kwargs = kwargs
            return SimpleNamespace(
                status="completed",
                output_text=json.dumps(
                    {
                        "reason": "Review the account identity and mutation path.",
                        "security_questions": [
                            "Does the identity used for the write match the authenticated principal?"
                        ],
                        "supporting_node_ids": [],
                        "supporting_edge_keys": [],
                        "coverage_notes": [],
                    }
                ),
            )

    class FakeClient:
        responses = FakeResponses()

    client = FakeClient()
    context = AIRepositoryContext(
        codebase="example",
        revision="rev-1",
        architecture="Python service",
        applications=[],
        source_inventory=[],
        source_tree=["account.py"],
        graph_symbols=2,
        graph_routes=0,
        business_context="Accounts belong to individual customers.",
    )

    agent = PlaidNoxDeepHuntAgent(client, model="test-model")
    investigation = agent.plan_graph_investigation(
        context,
        codebase_id="codebase-a",
        graph_snapshot=snapshot,
        context_broker=GraphContextBroker(tmp_path, snapshot),
        target_node_id=target.id,
    )

    assert investigation.state == "planned"
    assert (
        client.responses.kwargs["text"]["format"]["name"]
        == "plaidnox_graph_investigation_plan"
    )
    assert client.responses.kwargs["model"] == agent._model_for_tier(ModelTier.FAST)
    assert client.responses.kwargs["max_output_tokens"] == 2500


def test_agent_routes_connected_surface_group_through_litellm_planner(tmp_path: Path):
    snapshot = _graph(tmp_path)

    class FakeResponses:
        kwargs = None

        def create(self, **kwargs):
            self.kwargs = kwargs
            return SimpleNamespace(
                status="completed",
                output_text=json.dumps(
                    {
                        "reason": "Review the account update path.",
                        "security_questions": [
                            "Is ownership enforced before the update?"
                        ],
                        "supporting_node_ids": [],
                        "supporting_edge_keys": [],
                        "coverage_notes": [],
                    }
                ),
            )

    class FakeClient:
        responses = FakeResponses()

    client = FakeClient()
    context = AIRepositoryContext(
        codebase="example",
        revision="rev-1",
        architecture="Python service",
        applications=[],
        source_inventory=[],
        source_tree=["account.py"],
        graph_symbols=2,
        graph_routes=0,
        business_context="Accounts belong to individual customers.",
    )
    targets = tuple(node.id for node in snapshot.nodes)
    agent = PlaidNoxDeepHuntAgent(client, model="test-model")

    investigation = agent.plan_graph_investigation(
        context,
        codebase_id="codebase-a",
        graph_snapshot=snapshot,
        context_broker=GraphContextBroker(tmp_path, snapshot),
        target_node_ids=targets,
        surface_context=[
            {
                "surface_key": "surface-a",
                "collection": "entry_points",
                "label": "Account update endpoint",
                "node_ids": list(targets),
                "mapping_status": "mapped",
                "source_locations": [
                    {
                        "path": "account.py",
                        "start_line": 1,
                        "end_line": 5,
                        "source_hash": snapshot.source_hashes["account.py"],
                    }
                ],
            }
        ],
        stable_key="surface-group:account-update",
    )

    assert investigation.stable_key == "surface-group:account-update"
    assert investigation.target_ref["node_ids"] == sorted(targets)
    assert client.responses.kwargs["model"] == agent._model_for_tier(ModelTier.FAST)
    assert client.responses.kwargs["max_output_tokens"] == 2500
