from pathlib import Path

from plaidnox_sast.ai import _is_generated_path, _merge_regions, _source_segments
from plaidnox_sast.assets import load_json
from plaidnox_sast.graph import build_structural_graph


def _window(path, start, end, task, query="q"):
    return {
        "path": path,
        "start_line": start,
        "end_line": end,
        "content": "x" * (end - start + 1),
        "query_ids": [query],
        "task_ids": [task],
        "security_ir_slice": {},
    }


def test_overlapping_and_adjacent_windows_merge_into_one_region_with_all_tasks(tmp_path):
    (tmp_path / "app.js").write_text("\n".join(f"line {n}" for n in range(1, 400)))
    windows = [
        _window("app.js", 100, 180, "auth", "q1"),
        _window("app.js", 110, 190, "ssrf", "q2"),
        _window("app.js", 200, 220, "xss", "q3"),
        _window("app.js", 350, 380, "rate", "q4"),
    ]
    regions = _merge_regions(tmp_path, windows, None, load_json("runtime/agent.json"))
    regions.sort(key=lambda item: item["start_line"])

    assert [(r["start_line"], r["end_line"]) for r in regions] == [(100, 220), (350, 380)]
    assert regions[0]["task_ids"] == ["auth", "ssrf", "xss"]
    assert regions[0]["query_ids"] == ["q1", "q2", "q3"]
    assert regions[0]["content"].splitlines()[0] == "line 100"


def test_lockfiles_and_minified_bundles_are_not_discovery_targets(tmp_path):
    for name in ("package-lock.json", "yarn.lock", "bundle.min.js"):
        assert _is_generated_path(Path(name))
    assert not _is_generated_path(Path("app.js"))
    (tmp_path / "package-lock.json").write_text("{}\n" * 5000)
    (tmp_path / "app.js").write_text("const a = 1;\n")
    assert {s["path"] for s in _source_segments(tmp_path)} == {"app.js"}


def test_express_routes_become_first_class_symbols(tmp_path):
    (tmp_path / "app.js").write_text(
        "app.get('/a', (req, res) => {\n  res.send('a');\n});\n"
        "router.post('/b', auth, async (req, res) => {\n  res.send('b');\n});\n"
        "other.get('/c', () => {});\n"
    )
    graph = build_structural_graph(tmp_path)
    assert [(r.name, r.line, r.end_line) for r in graph.routes] == [("GET /a", 1, 3), ("POST /b", 4, 6)]


def test_context_built_before_route_extraction_is_rebuilt(tmp_path):
    from plaidnox_sast.context_fabric import ContextFabricStore

    (tmp_path / "app.js").write_text("app.get('/a', () => {});\n")
    graph = build_structural_graph(tmp_path)
    store = ContextFabricStore(tmp_path / "fabric.sqlite")
    first = store.prepare_snapshot("o/r", "rev", tmp_path, graph)
    store.save_repository_context(first.current.context_id, "o/r", {"graph_routes": 0})

    assert store.prepare_snapshot("o/r", "rev", tmp_path, graph).reused is False

    store.save_repository_context(first.current.context_id, "o/r", {"graph_routes": 1})
    assert store.prepare_snapshot("o/r", "rev", tmp_path, graph).reused is True


def test_query_budget_is_tight_for_small_repositories_and_per_task_for_large_ones():
    from plaidnox_sast.ai import _query_budget

    runtime = load_json("runtime/code_intelligence.json")
    assert _query_budget(runtime, 14, 6) == 48
    assert _query_budget(runtime, 14, 12) == 60
    assert _query_budget(runtime, 400, 6) == 180
