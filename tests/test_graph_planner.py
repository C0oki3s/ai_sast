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
)
from plaidnox_sast.graphify_adapter import normalize_extraction
from plaidnox_sast.models import ModelTier


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
            {"id": "raw-update", "label": "update_account()", "source_file": "account.py", "source_location": "L1"},
            {"id": "raw-load", "label": "load_account()", "source_file": "account.py", "source_location": "L5"},
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
        node_id = next(node["node_id"] for node in payload["graph_nodes"] if node["label"] == "load_account()")
        return {
            "reason": "This function loads and saves a caller-selected account.",
            "security_questions": ["Is the selected account bound to the authenticated principal?"],
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
    )

    assert len(observed) == 1
    assert result.target_ref["node_id"] == target.id
    assert result.security_questions == ("Is the selected account bound to the authenticated principal?",)
    assert len(result.source_windows) == 2
    assert {item["provenance"] for item in result.graph_refs if "edge_id" in item} == {"INFERRED"}
    assert result.evidence_hash
    assert result.state == "planned"


@pytest.mark.parametrize("invented_field", ["supporting_node_ids", "supporting_edge_keys"])
def test_graph_planner_rejects_unobserved_relationships(tmp_path: Path, invented_field: str):
    snapshot = _graph(tmp_path)
    target = next(node for node in snapshot.nodes if node.label == "update_account()")
    result = {
        "reason": "Investigate the target.",
        "security_questions": ["Is authorization enforced?"],
        "supporting_node_ids": [],
        "supporting_edge_keys": [],
        "coverage_notes": [],
    }
    result[invented_field] = ["f" * 64 if invented_field == "supporting_edge_keys" else "invented-reference"]
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


def test_agent_routes_graph_planning_through_configured_structured_model_call(tmp_path: Path):
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
    assert client.responses.kwargs["text"]["format"]["name"] == "plaidnox_graph_investigation_plan"
    assert client.responses.kwargs["model"] == agent._model_for_tier(ModelTier.FAST)
    assert client.responses.kwargs["max_output_tokens"] == 2500
