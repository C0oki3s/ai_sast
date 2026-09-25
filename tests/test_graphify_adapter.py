from __future__ import annotations

from pathlib import Path

import pytest

from plaidnox_sast.graphify_adapter import (
    CodeEdge,
    GraphDelta,
    GraphifyAdapterError,
    affected_investigation_ids,
    extract_structural_graph,
    graph_edge_identity,
    normalize_extraction,
)


def _graph(raw_prefix: str) -> dict:
    return {
        "nodes": [
            {
                "id": f"{raw_prefix}-file",
                "label": "app.py",
                "source_file": "app.py",
                "source_location": "L1",
            },
            {
                "id": f"{raw_prefix}-foo",
                "label": "foo()",
                "source_file": "app.py",
                "source_location": "L1",
            },
            {
                "id": f"{raw_prefix}-bar",
                "label": "bar()",
                "source_file": "app.py",
                "source_location": "L4",
            },
        ],
        "edges": [
            {
                "source": f"{raw_prefix}-foo",
                "target": f"{raw_prefix}-bar",
                "relation": "calls",
                "confidence": "EXTRACTED",
                "source_file": "app.py",
                "source_location": "L2",
            }
        ],
    }


def test_graphify_raw_ids_are_normalized_to_stable_source_ids(tmp_path: Path) -> None:
    file = tmp_path / "app.py"
    file.write_text("def foo():\n    return bar()\n\ndef bar():\n    return 1\n")

    first = normalize_extraction(tmp_path, [file], _graph("machine-a"))
    second = normalize_extraction(tmp_path, [file], _graph("machine-b"))

    assert first.nodes == second.nodes
    assert first.edges == second.edges
    assert first.edges[0].provenance == "EXTRACTED"
    assert first.neighborhood(first.nodes[1].id, maximum_edges=1) == first.edges


def test_graphify_symbol_identity_survives_a_line_shift(tmp_path: Path) -> None:
    file = tmp_path / "app.py"
    file.write_text("def foo():\n    return 1\n")
    original = _graph("first")
    original["nodes"] = original["nodes"][:2]
    original["edges"] = []
    before = normalize_extraction(tmp_path, [file], original)

    file.write_text("# added comment\ndef foo():\n    return 1\n")
    shifted = _graph("second")
    shifted["nodes"] = shifted["nodes"][:2]
    shifted["nodes"][1]["source_location"] = "L2"
    shifted["edges"] = []
    after = normalize_extraction(tmp_path, [file], shifted)

    assert before.nodes[1].id == after.nodes[1].id
    assert before.nodes[1].source_hash != after.nodes[1].source_hash


def test_graphify_source_provenance_rejects_excluded_and_out_of_bounds_evidence(tmp_path: Path) -> None:
    file = tmp_path / "app.py"
    file.write_text("def foo():\n    pass\n")
    extracted = _graph("raw")
    extracted["nodes"][0]["source_file"] = "../secret.py"
    with pytest.raises(GraphifyAdapterError, match="escaped"):
        normalize_extraction(tmp_path, [file], extracted)

    extracted = _graph("raw")
    extracted["nodes"][2]["source_location"] = "L999"
    with pytest.raises(GraphifyAdapterError, match="outside"):
        normalize_extraction(tmp_path, [file], extracted)


def test_graphify_extraction_receives_only_admitted_source(tmp_path: Path) -> None:
    allowed = tmp_path / "app.py"
    allowed.write_text("def foo():\n    return bar()\n\ndef bar():\n    return 1\n")
    (tmp_path / "secret.env").write_text("SHOULD_NOT_BE_READ=1\n")
    observed: list[Path] = []

    def fake_extractor(paths: list[Path], **_kwargs: object) -> dict:
        observed.extend(paths)
        return _graph("extractor")

    snapshot = extract_structural_graph(tmp_path, extractor=fake_extractor)

    assert observed == [allowed]
    assert snapshot.unresolved_edges == 0
    assert len(snapshot.edges) == 1


def test_graphify_cache_stays_outside_the_source_snapshot(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def foo():\n    pass\n")
    seen_cache: list[Path] = []

    def fake_extractor(_paths: list[Path], *, cache_root: Path, **_kwargs: object) -> dict:
        seen_cache.append(cache_root)
        return {"nodes": [], "edges": []}

    extract_structural_graph(tmp_path, extractor=fake_extractor)

    assert seen_cache
    assert tmp_path not in seen_cache[0].parents
    assert not seen_cache[0].exists()
    with pytest.raises(GraphifyAdapterError, match="outside"):
        extract_structural_graph(tmp_path, cache_root=tmp_path / "cache", extractor=fake_extractor)


def test_graphify_rejects_source_mutation_during_extraction(tmp_path: Path) -> None:
    file = tmp_path / "app.py"
    file.write_text("def foo():\n    return 1\n")

    def changing_extractor(_paths: list[Path], **_kwargs: object) -> dict:
        file.write_text("def foo():\n    return 2\n")
        return {"nodes": [], "edges": []}

    with pytest.raises(GraphifyAdapterError, match="changed during"):
        extract_structural_graph(tmp_path, extractor=changing_extractor)


def test_graphify_missing_endpoint_is_an_explicit_gap(tmp_path: Path) -> None:
    file = tmp_path / "app.py"
    file.write_text("def foo():\n    return bar()\n\ndef bar():\n    return 1\n")
    extracted = _graph("raw")
    extracted["edges"][0]["target"] = "external-target"

    snapshot = normalize_extraction(tmp_path, [file], extracted)

    assert snapshot.unresolved_edges == 1
    assert snapshot.edges == ()


def test_graphify_delta_marks_removed_source_and_edges(tmp_path: Path) -> None:
    old_file = tmp_path / "app.py"
    old_file.write_text("def foo():\n    return bar()\n\ndef bar():\n    return 1\n")
    previous = normalize_extraction(tmp_path, [old_file], _graph("old"))
    old_file.unlink()
    new_file = tmp_path / "new.py"
    new_file.write_text("def baz():\n    return 2\n")
    current_raw = {
        "nodes": [
            {"id": "new-baz", "label": "baz()", "source_file": "new.py", "source_location": "L1"}
        ],
        "edges": [],
    }
    current = normalize_extraction(tmp_path, [new_file], current_raw)

    delta = current.difference(previous)

    assert delta.added_files == ("new.py",)
    assert delta.removed_files == ("app.py",)
    assert len(delta.removed_node_ids) == 3
    assert len(delta.removed_edges) == 1
    assert current.snapshot_id != previous.snapshot_id


def test_graphify_unsupported_admitted_file_is_visible_as_unindexed(tmp_path: Path) -> None:
    file = tmp_path / "app.py"
    file.write_text("def foo():\n    pass\n")

    snapshot = normalize_extraction(tmp_path, [file], {"nodes": [], "edges": []})

    assert snapshot.unindexed_files == ("app.py",)


def test_graph_delta_invalidates_only_investigations_using_changed_evidence() -> None:
    investigations = [
        {
            "investigation_id": "auth",
            "target_ref": {"node_id": "auth-node"},
            "graph_refs": [{"node_id": "auth-node"}],
            "source_windows": [{"path": "auth.py"}],
            "context_dependencies": [
                {"kind": "graph_node", "key": "auth-node", "hash": "old"},
                {"kind": "graph_snapshot", "key": "old-snapshot", "hash": "old-snapshot"},
            ],
        },
        {
            "investigation_id": "orders",
            "target_ref": {"node_id": "orders-node"},
            "graph_refs": [{"node_id": "orders-node"}],
            "source_windows": [{"path": "orders.py"}],
            "context_dependencies": [
                {"kind": "graph_snapshot", "key": "old-snapshot", "hash": "old-snapshot"}
            ],
        },
        {
            "investigation_id": "auth-callee",
            "target_ref": {"node_id": "session-node"},
            "graph_refs": [{"node_id": "session-node"}],
            "source_windows": [{"path": "session.py"}],
            "context_dependencies": [],
        },
    ]
    delta = GraphDelta(
        added_files=(),
        changed_files=("auth.py",),
        removed_files=(),
        added_node_ids=(),
        changed_node_ids=("auth-node",),
        removed_node_ids=(),
        added_edges=(
            CodeEdge(
                "auth-node",
                "session-node",
                "calls",
                "EXTRACTED",
                "auth.py",
                24,
                "new-source-hash",
            ),
        ),
        removed_edges=(),
    )

    assert affected_investigation_ids(investigations, delta) == ("auth", "auth-callee")


def test_graph_delta_matches_removed_edge_dependencies() -> None:
    edge = CodeEdge("route", "handler", "calls", "EXTRACTED", "routes.py", 7, "old-hash")
    investigations = [
        {
            "investigation_id": "route-handler",
            "target_ref": {},
            "graph_refs": [],
            "source_windows": [],
            "context_dependencies": [{"kind": "graph_edge", "key": graph_edge_identity(edge)}],
        }
    ]
    delta = GraphDelta((), (), (), (), (), (), (), (edge,))

    assert affected_investigation_ids(investigations, delta) == ("route-handler",)
