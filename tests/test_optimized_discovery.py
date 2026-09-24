from pathlib import Path

from plaidnox_sast.optimized_ai import (
    DiscoveryRegion,
    _canonical_queries,
    _discovery_progress,
    _merge_discovery_regions,
    _region_from_range,
    _subtract_covered_ranges,
)


def test_checkpoint_identity_uses_semantic_obligations_not_planner_ids():
    region = DiscoveryRegion(
        path="app.js",
        start_line=10,
        end_line=20,
        content="const x = input;",
        anchor_type="symbol",
        anchor_id="authCheck",
        content_hash="content",
        security_ir_hash="ir",
        task_ids={"task-a"},
        query_ids={"query-a"},
        coverage_refs={"task-a::obligation::0"},
        obligations={"verify identity before protected routes"},
        vulnerability_themes={"authentication"},
    )
    first = region.checkpoint_key("v1")

    region.task_ids = {"renumbered-task"}
    region.query_ids = {"renumbered-query"}
    region.coverage_refs = {"renumbered-task::obligation::9"}
    assert region.checkpoint_key("v1") == first

    region.obligations.add("prevent unsigned token acceptance")
    assert region.checkpoint_key("v1") != first


def test_overlapping_regions_use_actual_merged_span_size(tmp_path: Path):
    # Each input window is ~10k chars, so summing both would incorrectly exceed
    # the 16k cap. Their actual union is ~15k and should merge.
    lines = ["x" * 99 for _ in range(150)]
    (tmp_path / "app.js").write_text("\n".join(lines), encoding="utf-8")
    first = _region_from_range(tmp_path, None, "app.js", 1, 100)
    second = _region_from_range(tmp_path, None, "app.js", 51, 150)
    assert first is not None and second is not None

    merged, merged_windows = _merge_discovery_regions(
        tmp_path,
        [first, second],
        None,
        {
            "region_overlap_ratio": 0.5,
            "region_max_gap_lines": 20,
            "region_max_characters": 16000,
        },
    )

    assert merged_windows == 1
    assert [(item.start_line, item.end_line) for item in merged] == [(1, 150)]


def test_distinct_structural_route_anchors_do_not_merge(tmp_path: Path):
    (tmp_path / "app.js").write_text("\n".join("x" for _ in range(100)), encoding="utf-8")
    first = DiscoveryRegion(
        "app.js", 1, 60, "x", "route", "GET /a", "a", "ir-a"
    )
    second = DiscoveryRegion(
        "app.js", 30, 90, "x", "route", "POST /b", "b", "ir-b"
    )

    merged, merged_windows = _merge_discovery_regions(
        tmp_path,
        [first, second],
        None,
        {
            "region_overlap_ratio": 0.5,
            "region_max_gap_lines": 20,
            "region_max_characters": 16000,
        },
    )

    assert merged_windows == 0
    assert [item.anchor_id for item in merged] == ["GET /a", "POST /b"]


def test_fallback_subtracts_already_covered_ranges():
    assert _subtract_covered_ranges(1, 120, [(70, 120)]) == [(1, 69)]
    assert _subtract_covered_ranges(1, 120, [(1, 20), (40, 60), (90, 120)]) == [
        (21, 39),
        (61, 89),
    ]


def test_canonical_query_dedupe_preserves_all_provenance():
    queries = [
        {
            "query_id": "q-auth",
            "search_terms": ["req.user", "authCheck"],
            "include_globs": ["*.js"],
            "task_ids": ["auth"],
            "coverage_refs": ["auth::obligation::0"],
        },
        {
            "query_id": "q-authz",
            "search_terms": ["authCheck", "req.user"],
            "include_globs": ["*.js"],
            "task_ids": ["authz"],
            "coverage_refs": ["authz::obligation::0"],
        },
    ]

    [merged] = _canonical_queries(queries)
    assert merged["query_ids"] == {"q-auth", "q-authz"}
    assert merged["task_ids"] == {"auth", "authz"}
    assert merged["coverage_refs"] == {"auth::obligation::0", "authz::obligation::0"}


def test_zero_candidate_round_continues_when_next_focus_is_novel():
    progressed, obligations, branches, focus = _discovery_progress(
        {
            "next_focus": "trace req.user into protected routes",
            "coverage": {
                "obligations_reviewed": [],
                "branches_reviewed": [],
                "unresolved_areas": ["protected routes"],
            },
        },
        new_candidates=0,
        previous_obligations=set(),
        previous_branches=set(),
        seen_focuses=set(),
    )
    assert progressed is True
    assert obligations == set()
    assert branches == set()
    assert focus == "trace req.user into protected routes"


def test_repeated_focus_without_new_evidence_is_no_progress():
    progressed, *_ = _discovery_progress(
        {
            "next_focus": "trace req.user into protected routes",
            "coverage": {
                "obligations_reviewed": ["auth checked"],
                "branches_reviewed": ["/reports"],
                "unresolved_areas": ["/dashboard"],
            },
        },
        new_candidates=0,
        previous_obligations={"auth checked"},
        previous_branches={"/reports"},
        seen_focuses={"trace req.user into protected routes"},
    )
    assert progressed is False
