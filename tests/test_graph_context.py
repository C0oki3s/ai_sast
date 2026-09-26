from __future__ import annotations

from pathlib import Path

import pytest

from plaidnox_sast.graph_context import GraphContextBroker
from plaidnox_sast.graph import RipgrepDiscovery
from plaidnox_sast.graphify_adapter import GraphifyAdapterError, normalize_extraction


def _snapshot(root: Path):
    source = root / "service.py"
    source.write_text("def entry():\n    return effect()\n\ndef effect():\n    return 1\n")
    extracted = {
        "nodes": [
            {"id": "raw-entry", "label": "entry()", "source_file": "service.py", "source_location": "L1"},
            {"id": "raw-effect", "label": "effect()", "source_file": "service.py", "source_location": "L4"},
        ],
        "edges": [
            {
                "source": "raw-entry",
                "target": "raw-effect",
                "relation": "calls",
                "confidence": "AMBIGUOUS",
                "source_file": "service.py",
                "source_location": "L2",
            }
        ],
    }
    return normalize_extraction(root, [source], extracted)


def test_graph_broker_returns_directional_edges_with_provenance(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    broker = GraphContextBroker(tmp_path, snapshot, maximum_edges=1)
    entry = broker.definitions("entry()")[0]
    effect = broker.definitions("effect()")[0]

    callees = broker.callees(entry.id)
    callers = broker.callers(effect.id)

    assert callees.nodes == (effect,)
    assert callers.nodes == (entry,)
    assert callers.edges[0].provenance == "AMBIGUOUS"
    assert not callers.truncated
    assert broker.references(effect.id).nodes == ()


def test_graph_broker_source_window_is_exact_and_rejects_staleness(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    broker = GraphContextBroker(tmp_path, snapshot)

    window = broker.source_window("service.py", 1, 2)

    assert window.excerpt == "def entry():\n    return effect()\n"
    assert window.source_hash == snapshot.source_hashes["service.py"]
    with pytest.raises(GraphifyAdapterError, match="not in"):
        broker.source_window(".env", 1, 1)

    (tmp_path / "service.py").write_text("def entry():\n    return changed()\n")
    with pytest.raises(GraphifyAdapterError, match="changed after"):
        broker.source_window("service.py", 1, 2)


def test_graph_broker_reports_truncation_without_claiming_completeness(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    extra_edge = snapshot.edges[0]
    from dataclasses import replace

    duplicated = replace(snapshot, edges=(extra_edge, extra_edge))
    entry = next(node for node in snapshot.nodes if node.label == "entry()")

    result = GraphContextBroker(tmp_path, duplicated, maximum_edges=1).callees(entry.id)

    assert result.truncated
    assert len(result.edges) == 1


def test_graph_broker_resolves_typed_call_context_with_provenance_and_source(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    broker = GraphContextBroker(tmp_path, snapshot)

    result = broker.resolve_request(
        {"kind": "callees", "symbol": "entry()", "path": "service.py"}
    )

    assert [node["label"] for node in result["nodes"]] == ["effect()"]
    assert result["edges"][0]["relation"] == "calls"
    assert result["edges"][0]["provenance"] == "AMBIGUOUS"
    assert result["edges"][0]["edge_id"]
    assert result["source_windows"][0]["path"] == "service.py"
    assert result["source_windows"][0]["content_hash"] == snapshot.source_hashes["service.py"]


def test_graph_broker_does_not_claim_evidence_for_unmatched_typed_request(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    broker = GraphContextBroker(tmp_path, snapshot)

    result = broker.resolve_request(
        {"kind": "callers", "symbol": "missing()", "path": "service.py"}
    )

    assert result["nodes"] == []
    assert result["edges"] == []
    assert result["source_windows"] == []


def test_graph_broker_uses_literal_rg_fallback_without_fabricating_edges(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    broker = GraphContextBroker(
        tmp_path,
        snapshot,
        fallback_discovery=RipgrepDiscovery(tmp_path),
    )

    result = broker.resolve_request(
        {
            "kind": "callers",
            "symbol": "missing_symbol",
            "query": "return effect()",
        }
    )

    assert result["nodes"] == []
    assert result["edges"] == []
    assert result["fallback"]["provider"] == "ripgrep"
    assert result["fallback"]["relationship_status"] == "unresolved"
    assert result["fallback"]["hit_count"] == 1
    assert result["source_windows"][0]["content_hash"] == snapshot.source_hashes["service.py"]


def test_graph_relationship_resolvers_use_configured_edges_not_generic_adjacency(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    broker = GraphContextBroker(tmp_path, snapshot)

    route_context = broker.resolve_request(
        {"kind": "middleware", "symbol": "entry()", "path": "service.py"}
    )
    reader_context = broker.resolve_request(
        {"kind": "readers", "symbol": "entry()", "path": "service.py"}
    )

    assert [item["relation"] for item in route_context["edges"]] == ["calls"]
    assert reader_context["edges"] == []
