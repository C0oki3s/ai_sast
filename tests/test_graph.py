import pytest

from plaidnox_sast.graph import (
    RipgrepDiscovery,
    RipgrepQueryError,
    build_structural_graph,
    readable_source_tree,
    source_files,
)


def test_structural_graph_uses_tree_sitter_without_baked_in_searches(sample_repo):
    graph = build_structural_graph(sample_repo)
    assert graph.tree_sitter_files >= 1
    assert graph.rg_queries == 0
    assert graph.routes == []


def test_structural_graph_returns_changed_attack_surface(sample_repo):
    surface = build_structural_graph(sample_repo).affected_surface(["app.js"])
    assert surface["changed_paths"] == ["app.js"]
    assert surface["routes"] == []


def test_structural_graph_keeps_symbol_references_for_incremental_navigation(tmp_path):
    (tmp_path / "service.py").write_text(
        "def load_record(identifier):\n    return identifier\n\n"
        "def handle_request(value):\n    return load_record(value)\n",
        encoding="utf-8",
    )

    graph = build_structural_graph(tmp_path)

    assert any(
        item.source == "handle_request" and item.target == "load_record"
        for item in graph.references
    )


def test_readable_source_tree_is_stable_and_excludes_secret_containers(sample_repo):
    assert readable_source_tree(sample_repo) == [".plaidnox/config.yaml", "app.js"]


def test_ripgrep_discovery_returns_bounded_structured_hits(sample_repo):
    hits = RipgrepDiscovery(sample_repo).search("signin", "req\\.body", ["*.js"])

    assert hits
    assert hits[0].query_id == "signin"
    assert hits[0].path == "app.js"
    assert hits[0].line > 0


def test_ripgrep_discovery_preserves_a_redacted_diagnostic_for_invalid_model_pattern(sample_repo):
    with pytest.raises(RipgrepQueryError) as raised:
        RipgrepDiscovery(sample_repo).search("model-query-1", r"(?<!\.)eval\(")

    error = raised.value
    assert error.query_id == "model-query-1"
    assert error.exit_code == 2
    assert len(error.pattern_hash) == 64
    assert error.diagnostic
    assert "exit code 2" in str(error)


def test_ripgrep_literal_search_never_interprets_model_text_as_regex(sample_repo):
    hits = RipgrepDiscovery(sample_repo).search_literals(
        "model-literal-query",
        [r"(?<!\.)eval\(", "req.body"],
        ["*.js"],
    )

    assert any(hit.query_id == "model-literal-query" for hit in hits)


def test_ripgrep_discovery_never_searches_unlisted_file_types(tmp_path):
    (tmp_path / "app.py").write_text("dangerous_call(user_input)\n", encoding="utf-8")
    (tmp_path / ".env").write_text("dangerous_call(secret_value)\n", encoding="utf-8")

    hits = RipgrepDiscovery(tmp_path).search("security-signal", "dangerous_call")

    assert [hit.path for hit in hits] == ["app.py"]


def test_source_inventory_enforces_excludes_and_maximum_size(tmp_path):
    (tmp_path / "keep.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / "excluded.py").write_text("print('excluded')", encoding="utf-8")
    (tmp_path / "large.py").write_text("x" * 100, encoding="utf-8")

    files = source_files(tmp_path, exclude=["excluded.py"], max_file_bytes=20)

    assert [path.name for path in files] == ["keep.py"]


def test_source_inventory_recognizes_common_extensionless_manifests(tmp_path):
    for filename in ("go.mod", "requirements.txt", "build.gradle", "Cargo.lock"):
        (tmp_path / filename).write_text("module metadata\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not source inventory\n", encoding="utf-8")

    files = source_files(tmp_path)

    assert [path.name for path in files] == [
        "Cargo.lock",
        "build.gradle",
        "go.mod",
        "requirements.txt",
    ]


def test_ripgrep_enforces_project_excludes_and_exact_maximum_size(tmp_path):
    (tmp_path / "keep.py").write_text("signal()\n", encoding="utf-8")
    (tmp_path / "excluded.py").write_text("signal()\n", encoding="utf-8")
    (tmp_path / "large.py").write_text("signal()\n" + "x" * 100, encoding="utf-8")

    hits = RipgrepDiscovery(
        tmp_path,
        exclude=["excluded.py"],
        max_file_bytes=20,
    ).search("bounded", "signal")

    assert [hit.path for hit in hits] == ["keep.py"]
