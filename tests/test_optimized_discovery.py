from pathlib import Path
from types import SimpleNamespace
import json

from plaidnox_sast.ai import AIRepositoryContext, HuntPlan, HuntTask
from plaidnox_sast.coverage import reconcile_obligations, reconcile_workset_batches
from plaidnox_sast.graph import Reference, StructuralGraph, Symbol, build_structural_graph
from plaidnox_sast.optimized_ai import (
    DiscoveryCoverageState,
    DiscoveryObligation,
    DiscoveryRegion,
    _canonical_queries,
    _discovery_workset_units,
    _has_context_evidence,
    _enrich_region_requirements,
    _merge_discovery_regions,
    _region_from_range,
    _resolve_discovery_context_request,
    _subtract_covered_ranges,
    _tasks_relevant_to_region,
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
        obligation_specs={
            "obl-identity": DiscoveryObligation(
                "obl-identity",
                "security_invariant",
                "verify identity before protected routes",
            )
        },
        vulnerability_themes={"authentication"},
    )
    first = region.checkpoint_key("v1")

    region.task_ids = {"renumbered-task"}
    region.query_ids = {"renumbered-query"}
    region.coverage_refs = {"renumbered-task::obligation::9"}
    assert region.checkpoint_key("v1") == first

    region.obligation_specs["obl-signature"] = DiscoveryObligation(
        "obl-signature",
        "security_invariant",
        "prevent unsigned token acceptance",
    )
    assert region.checkpoint_key("v1") != first


def test_optimized_workset_units_keep_exact_multi_slice_source_windows():
    first = DiscoveryRegion(
        path="routes/account.js",
        start_line=10,
        end_line=14,
        content="app.get('/account', authCheck, handler);",
        anchor_type="route",
        anchor_id="GET /account",
        content_hash="a" * 64,
        security_ir_hash="route-ir",
        obligations={"review route control"},
        obligation_specs={
            "route-control": DiscoveryObligation(
                "route-control", "security_invariant", "Review route control"
            )
        },
    )
    second = DiscoveryRegion(
        path="routes/account.js",
        start_line=18,
        end_line=24,
        content="function authCheck(req) { return verify(req); }",
        anchor_type="route",
        anchor_id="GET /account",
        content_hash="b" * 64,
        security_ir_hash="middleware-ir",
        obligations={"review identity gate"},
        obligation_specs={
            "identity-gate": DiscoveryObligation(
                "identity-gate", "security_invariant", "Review identity gate"
            )
        },
    )

    units, metrics = _discovery_workset_units([first, second])

    assert len(units) == 1
    unit = units[0]
    assert {"route-control", "identity-gate"} <= set(unit.obligation_specs)
    surface_reviews = [
        item for item in unit.obligation_specs.values() if item.obligation_type == "surface_review"
    ]
    assert len(surface_reviews) == 1
    assert surface_reviews[0].importance == "REQUIRED"
    assert surface_reviews[0].obligation_id in unit.security_workset["obligation_ids"]
    assert {(item["path"], item["start_line"], item["end_line"]) for item in unit.source_windows()} == {
        ("routes/account.js", 10, 14),
        ("routes/account.js", 18, 24),
    }
    assert {location["path"] for item in unit.security_workset["slices"] for location in item["locations"]} == {"routes/account.js"}
    assert metrics["unique_worksets"] == 1
    assert metrics["review_batches"] == 1


def test_workset_mapping_keeps_overlapping_structural_anchors_separate():
    route = DiscoveryRegion(
        path="app.js",
        start_line=10,
        end_line=20,
        content="route content",
        anchor_type="route",
        anchor_id="GET /account",
        content_hash="a" * 64,
        security_ir_hash="route-ir",
        obligation_specs={
            "route-obligation": DiscoveryObligation(
                "route-obligation", "security_invariant", "Review route"
            )
        },
    )
    function = DiscoveryRegion(
        path="app.js",
        start_line=10,
        end_line=20,
        content="function content",
        anchor_type="symbol",
        anchor_id="loadAccount",
        content_hash="b" * 64,
        security_ir_hash="function-ir",
        obligation_specs={
            "function-obligation": DiscoveryObligation(
                "function-obligation", "security_invariant", "Review function"
            )
        },
    )

    units, _metrics = _discovery_workset_units([route, function])

    assert len(units) == 2
    assert {
        frozenset(key for key, item in unit.obligation_specs.items() if item.obligation_type != "surface_review")
        for unit in units
    } == {
        frozenset({"route-obligation"}),
        frozenset({"function-obligation"}),
    }
    assert len({
        item.canonical_id
        for unit in units
        for item in unit.obligation_specs.values()
        if item.obligation_type == "surface_review"
    }) == 2


def test_required_surface_review_spans_every_lossless_workset_batch():
    regions = [
        DiscoveryRegion(
            path="routes/batch.js",
            start_line=index + 1,
            end_line=index + 1,
            content=f"evidence_{index}()",
            anchor_type="route",
            anchor_id="GET /batch",
            content_hash=f"{index + 1:064x}",
            security_ir_hash=f"ir-{index}",
        )
        for index in range(9)
    ]
    units, metrics = _discovery_workset_units(regions)

    assert metrics["review_batches"] == 2
    reviews = [
        next(item for item in unit.obligation_specs.values() if item.obligation_type == "surface_review")
        for unit in units
    ]
    assert reviews[0].canonical_id == reviews[1].canonical_id
    assert all(item.importance == "REQUIRED" for item in reviews)
    planned = [
        {
            "region_id": unit.region_id,
            "security_workset": unit.security_workset,
            "obligations": [item.to_dict() for item in unit.obligation_specs.values()],
        }
        for unit in units
    ]
    observations = [
        {"region_id": unit.region_id, "obligation": review.to_dict(), "status": status}
        for unit, review, status in zip(units, reviews, ("NO_ISSUE", "UNRESOLVED"), strict=True)
    ]
    reduced, batch_metrics = reconcile_workset_batches(observations, planned)

    assert batch_metrics["workset_batch_obligations_unresolved"] == 1
    assert reconcile_obligations(reduced)["canonical_required_unresolved"] == 1


def test_graph_workset_supplies_cross_file_route_evidence(tmp_path: Path):
    from plaidnox_sast.ai import _candidate_from_ai_item

    (tmp_path / "app.js").write_text(
        "const app = express();\napp.get('/account', check_auth);\nconst adjacent = true;\n",
        encoding="utf-8",
    )
    (tmp_path / "middleware.py").write_text(
        "def check_auth(request):\n    return request.user\n",
        encoding="utf-8",
    )
    graph = build_structural_graph(tmp_path)
    route = next(item for item in graph.routes if "GET /account" in item.name)
    region = _region_from_range(
        tmp_path, graph, route.path, 1, 3, anchor=route
    )
    assert region is not None
    region.obligation_specs["identity"] = DiscoveryObligation(
        "identity", "security_invariant", "Review the authenticated identity"
    )

    units, metrics = _discovery_workset_units(
        [region], root=tmp_path, graph=graph
    )

    assert len(units) == 1
    assert metrics["graph_worksets_selected"] == 1
    assert units[0].security_workset["evidence_source"] == "tree_sitter_graph"
    assert units[0].security_workset["workset_complete"] is False
    assert region.obligation_specs.items() <= units[0].obligation_specs.items()
    assert sum(item.obligation_type == "surface_review" for item in units[0].obligation_specs.values()) == 1
    assert {window["path"] for window in units[0].source_windows()} == {
        "app.js", "middleware.py"
    }
    excerpts = [
        location["excerpt"]
        for evidence in units[0].security_workset["slices"]
        for location in evidence["locations"]
    ]
    assert sum("app.get('/account'" in excerpt for excerpt in excerpts) == 1
    assert any("const adjacent = true" in excerpt for excerpt in excerpts)
    hypothesis = {
        "candidate_id": "identity-hypothesis",
        "title": "Identity boundary may be crossed",
        "vulnerability_class": "CWE-287",
        "classification_references": [],
        "business_impact": "An identity-bound operation may be affected.",
        "severity": "high",
        "confidence": 0.7,
        "category": "authentication",
        "path": "middleware.py",
        "start_line": 1,
        "end_line": 2,
        "message": "The identity boundary needs independent verification.",
        "attack_path": "input -> identity selection",
        "evidence_basis": {
            "origin": [], "propagation": [], "expected_boundary": [],
            "sensitive_effect": [], "controls_checked": [], "missing_evidence": [],
        },
        "root_cause": {},
        "root_equivalence": {},
        "attacker_influence": "request input",
        "security_control": "identity check",
        "broken_invariant": "Identity must be verified before use.",
        "sensitive_effect": "identity-bound operation",
        "gained_capability": "select another identity",
        "required_context": [],
    }
    assert _candidate_from_ai_item(
        tmp_path,
        hypothesis,
        units[0].to_segment(),
        allowed_source_windows=units[0].source_windows(),
    ) is not None
    (tmp_path / "unrelated.py").write_text("unsafe_call()\n", encoding="utf-8")
    assert _candidate_from_ai_item(
        tmp_path,
        {**hypothesis, "path": "unrelated.py", "start_line": 1, "end_line": 1},
        units[0].to_segment(),
        allowed_source_windows=units[0].source_windows(),
    ) is None


def test_graph_workset_with_sensitive_related_source_uses_region_evidence(tmp_path: Path):
    (tmp_path / "app.js").write_text(
        "const app = express();\napp.get('/account', check_auth);\n",
        encoding="utf-8",
    )
    (tmp_path / "credential_handler.py").write_text(
        "def check_auth(request):\n    return request.user\n",
        encoding="utf-8",
    )
    graph = build_structural_graph(tmp_path)
    route = next(item for item in graph.routes if "GET /account" in item.name)
    region = _region_from_range(
        tmp_path, graph, route.path, route.line, route.end_line, anchor=route
    )
    assert region is not None

    units, metrics = _discovery_workset_units(
        [region], root=tmp_path, graph=graph
    )

    assert len(units) == 1
    assert metrics["graph_worksets_selected"] == 0
    assert metrics["graph_worksets_deferred_sources"] == 1
    assert {window["path"] for window in units[0].source_windows()} == {"app.js"}


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


def _context_request():
    return {
        "kind": "readers",
        "path": "",
        "symbol": "req.user.email",
        "start_line": 1,
        "end_line": 1,
        "offset": 0,
        "pattern": "",
        "query": "",
    }


def test_coverage_state_requires_a_typed_context_request_for_continuation():
    obligation = DiscoveryObligation("obl-auth", "security_invariant", "Trace identity consumers")
    state = DiscoveryCoverageState("region-auth", {obligation.obligation_id: obligation})
    state.apply(
        [
            {
                "obligation_id": "obl-auth",
                "status": "NEEDS_CONTEXT",
                "candidate_ids": [],
                "evidence": [],
                "reason": "Consumers are outside this region.",
                "context_requests": [_context_request()],
            }
        ],
        set(),
    )

    assert state.unresolved_ids() == ["obl-auth"]
    assert state.complete is False


def test_coverage_state_records_missing_dispositions_as_unresolved():
    obligation = DiscoveryObligation("obl-auth", "security_invariant", "Trace identity consumers")
    state = DiscoveryCoverageState("region-auth", {obligation.obligation_id: obligation})

    state.apply([], set())

    assert state.complete is True
    assert state.processing_complete is True
    assert state.coverage_complete is False
    assert state.dispositions["obl-auth"]["status"] == "UNRESOLVED"
    assert state.contract_issues == ["response omitted an obligation disposition"]


def test_coverage_state_keeps_ungrounded_candidate_as_unresolved():
    obligation = DiscoveryObligation("obl-auth", "security_invariant", "Trace identity consumers")
    state = DiscoveryCoverageState("region-auth", {obligation.obligation_id: obligation})
    state.apply(
        [
            {
                "obligation_id": "obl-auth",
                "status": "CANDIDATE_FOUND",
                "candidate_ids": ["candidate-outside-region"],
                "context_requests": [],
            }
        ],
        set(),
    )

    assert state.dispositions["obl-auth"]["status"] == "UNRESOLVED"
    assert state.dispositions["obl-auth"]["candidate_ids"] == []
    assert state.contract_issues == ["candidate disposition did not link to a grounded candidate"]


def test_related_tasks_are_aggregated_into_region_scoped_obligations():
    region = DiscoveryRegion("app.js", 1, 20, "source", "route", "GET /", "content", "ir")
    plan = HuntPlan(
        "plan",
        "Review security boundaries.",
        [
            HuntTask(
                "task-a", "Authentication", "Review authentication.", ["app.js"], ["GET /"],
                ["token integrity"], [], [], [],
                business_invariants=["Verified identity is immutable."],
                coverage_obligations=["Trace identity consumers."],
            ),
            HuntTask(
                "task-b", "Authorization", "Review authorization.", ["app.js"], ["GET /"],
                ["object authorization"], [], [], [],
                business_invariants=["Resources stay tenant scoped."],
                coverage_obligations=["Trace object access."],
            ),
        ],
    )
    region.task_ids = {"task-a", "task-b"}

    _enrich_region_requirements(region, plan)

    assert len(region.obligation_specs) == 5
    combined = " ".join(item.question for item in region.obligation_specs.values())
    assert "Verified identity is immutable." in combined
    assert "Resources stay tenant scoped." in combined
    assert "Trace identity consumers." in combined
    assert "Trace object access." in combined


def test_global_coverage_reconciliation_ids_match_one_invariant_in_a_larger_local_set():
    first_task = HuntTask(
        "auth-all", "Authentication", "Review authentication.", [], [], [], [], [], [],
        business_invariants=["Verified identity is immutable.", "Refresh state is principal-bound."],
    )
    second_task = HuntTask(
        "auth-single", "Authentication", "Review authentication.", [], [], [], [], [], [],
        business_invariants=["Verified identity is immutable."],
    )
    first_region = DiscoveryRegion("auth.js", 1, 20, "x", "symbol", "auth", "a", "a", task_ids={"auth-all"})
    second_region = DiscoveryRegion("auth.js", 21, 40, "y", "symbol", "auth2", "b", "b", task_ids={"auth-single"})

    _enrich_region_requirements(first_region, HuntPlan("p1", "Review", [first_task]))
    _enrich_region_requirements(second_region, HuntPlan("p2", "Review", [second_task]))

    first_ids = {item.canonical_id for item in first_region.obligation_specs.values()}
    second_ids = {item.canonical_id for item in second_region.obligation_specs.values()}
    assert first_ids & second_ids
    assert len(first_ids) == 2
    assert len(second_ids) == 1


def test_obligations_are_scoped_by_focus_path_and_exact_route():
    tasks = [
        HuntTask(
            "auth", "Auth", "Review authentication.", ["middleware/ValidateToken.js"],
            ["GET /dashboard"], ["identity integrity"], [], [], [],
            business_invariants=["Verified identity stays immutable."],
        ),
        HuntTask(
            "reports", "Reports", "Review report authorization.", ["app.js"],
            ["POST /reports"], ["report authorization"], [], [], [],
            business_invariants=["Only managers can create reports."],
        ),
        HuntTask(
            "flag", "Flag", "Review flag workflow.", ["app.js"],
            ["POST /flag"], ["flag workflow"], [], [], [],
            business_invariants=["Only the intended flag updates state."],
        ),
    ]
    plan = HuntPlan("plan", "Review boundaries.", tasks)
    middleware_region = DiscoveryRegion(
        "middleware/ValidateToken.js", 1, 73, "source", "symbol", "authCheck", "content", "ir",
        task_ids={"auth", "reports", "flag"},
    )
    report_region = DiscoveryRegion(
        "app.js", 100, 140, "source", "route", "route:POST /reports", "content", "ir",
        task_ids={"auth", "reports", "flag"},
    )
    route_range_region = DiscoveryRegion(
        "app.js", 1, 80, "source", "line_range", "app.js:1-80", "content", "ir",
        task_ids={"auth", "reports", "flag"},
        security_ir_slice={
            "symbols": [
                {
                    "kind": "route",
                    "name": "GET /dashboard",
                    "qualified_name": "route:GET /dashboard",
                    "line": 40,
                    "end_line": 70,
                }
            ]
        },
    )

    _enrich_region_requirements(middleware_region, plan)
    _enrich_region_requirements(report_region, plan)
    _enrich_region_requirements(route_range_region, plan)
    assert {task.task_id for task in _tasks_relevant_to_region(middleware_region, plan)} == {"auth"}
    assert {task.task_id for task in _tasks_relevant_to_region(report_region, plan)} == {"reports"}
    assert {task.task_id for task in _tasks_relevant_to_region(route_range_region, plan)} == {"auth"}
    middleware_questions = " ".join(item.question for item in middleware_region.obligation_specs.values())
    report_questions = " ".join(item.question for item in report_region.obligation_specs.values())
    route_range_questions = " ".join(item.question for item in route_range_region.obligation_specs.values())

    assert "Verified identity stays immutable." in middleware_questions
    assert "Only managers can create reports." not in middleware_questions
    assert "Only managers can create reports." in report_questions
    assert "Only the intended flag updates state." not in report_questions
    assert "Verified identity stays immutable." in route_range_questions
    assert "Only managers can create reports." not in route_range_questions
    assert "Only the intended flag updates state." not in route_range_questions


def test_route_task_payload_drops_unrelated_entry_points_and_global_obligations():
    from plaidnox_sast.optimized_ai import _region_task_payload

    task = HuntTask(
        "routes", "Route security", "Review routes.", ["app.js"],
        ["POST /reports", "GET /flag"], ["authorization"],
        ["Check POST /reports object authorization", "Audit every production route"],
        [], [], coverage_obligations=["POST /reports must enforce tenant scope", "Review all routes"],
    )
    region = DiscoveryRegion(
        "app.js", 100, 140, "source", "route", "route:POST /reports", "content", "ir"
    )

    payload = _region_task_payload(task, region)

    assert payload["scope"] == "LOCAL"
    assert payload["entry_points"] == ["POST /reports"]
    assert payload["focus_paths"] == ["app.js"]
    assert payload["evidence_requirements"] == ["Check POST /reports object authorization"]
    assert payload["coverage_obligations"] == ["POST /reports must enforce tenant scope"]


def test_focus_path_with_line_range_matches_only_overlapping_structural_region():
    task = HuntTask(
        "auth", "Authentication", "Review auth.", ["middleware/ValidateToken.js:35-72"],
        [], ["authentication"], [], [], [],
    )
    plan = HuntPlan("plan", "Review focused code.", [task])
    overlapping = DiscoveryRegion(
        "middleware/ValidateToken.js", 60, 80, "source", "symbol", "authCheck", "hash", "ir",
    )
    disjoint = DiscoveryRegion(
        "middleware/ValidateToken.js", 100, 120, "source", "symbol", "other", "hash2", "ir2",
    )

    assert _tasks_relevant_to_region(overlapping, plan) == [task]
    assert _tasks_relevant_to_region(disjoint, plan) == []


def test_only_resolved_context_with_material_evidence_can_trigger_continuation():
    assert _has_context_evidence({"resolved": True, "matches": []}) is False
    assert _has_context_evidence(
        {"resolved": True, "matches": [{"path": "app.js", "line": 10, "content": "req.user.email"}]}
    ) is True


def test_lockfile_hits_never_become_discovery_regions(tmp_path: Path):
    from plaidnox_sast.ai import HuntPlan, HuntTask
    from plaidnox_sast.optimized_ai import _search_discovery_regions

    (tmp_path / "app.js").write_text("const express = require('express');\n" * 3)
    (tmp_path / "package-lock.json").write_text('{"express": "4.0.0"}\n' * 500)
    plan = HuntPlan("p", "s", [HuntTask("t", "T", "o", ["."], [], ["auth"], ["e"], [], [])])
    queries = [{"query_id": "q", "search_terms": ["express"], "include_globs": ["*"], "task_ids": ["t"]}]

    regions = _search_discovery_regions(tmp_path, queries, plan, None, None, None)

    assert {region.path for region in regions} == {"app.js"}


def test_indexed_route_without_search_hit_still_gets_required_workset_review(tmp_path: Path):
    from plaidnox_sast.optimized_ai import _search_discovery_regions

    (tmp_path / "app.js").write_text(
        "app.get('/first', first_handler); // first_marker\n"
        "app.get('/second', second_handler);\n",
        encoding="utf-8",
    )
    graph = build_structural_graph(tmp_path)
    assert len(graph.routes) == 2
    plan = HuntPlan("plan", "Review entry points", [])
    stats: dict[str, int] = {}
    queries = [{
        "query_id": "first-only",
        "search_terms": ["first_marker"],
        "include_globs": ["*.js"],
        "task_ids": [],
    }]

    regions = _search_discovery_regions(
        tmp_path, queries, plan, graph, None, None, stats=stats
    )
    units, _ = _discovery_workset_units(regions, root=tmp_path, graph=graph)

    assert stats["indexed_routes_in_scope"] == 2
    assert stats["indexed_route_regions_added"] >= 1
    assert {route.name for route in graph.routes} <= {
        region.anchor_id.removeprefix("route:") for region in regions
    }
    assert any(
        "GET /second" in unit.security_workset["surface_id"]
        and any(item.obligation_type == "surface_review" and item.importance == "REQUIRED"
                for item in unit.obligation_specs.values())
        for unit in units
    )


def test_indexed_route_can_seed_discovery_when_search_returns_no_hits(tmp_path: Path):
    from plaidnox_sast.optimized_ai import _search_discovery_regions

    (tmp_path / "app.js").write_text("app.get('/health', handler);\n", encoding="utf-8")
    graph = build_structural_graph(tmp_path)
    stats: dict[str, int] = {}

    regions = _search_discovery_regions(
        tmp_path, [], HuntPlan("plan", "Review entry points", []), graph, None, None,
        stats=stats,
    )

    assert len(regions) == 1
    assert regions[0].anchor_type == "route"
    assert stats["rg_hits_unique"] == 0
    assert stats["indexed_route_regions_added"] == 1


def test_indexed_route_seeding_respects_analysis_scope(tmp_path: Path):
    from plaidnox_sast.optimized_ai import _search_discovery_regions

    (tmp_path / "public.js").write_text("app.get('/public', handler);\n", encoding="utf-8")
    (tmp_path / "private.js").write_text("app.get('/private', handler);\n", encoding="utf-8")
    graph = build_structural_graph(tmp_path)
    stats: dict[str, int] = {}

    regions = _search_discovery_regions(
        tmp_path, [], HuntPlan("plan", "Review entry points", []), graph, None, None,
        include_paths={"public.js"}, stats=stats,
    )

    assert [region.path for region in regions] == ["public.js"]
    assert stats["indexed_routes_in_scope"] == 1


def test_indexed_registration_without_search_hit_gets_required_review(tmp_path: Path):
    from plaidnox_sast.optimized_ai import _search_discovery_regions

    (tmp_path / "worker.py").write_text(
        "def process_message(payload):\n    return payload\n\n"
        "queue.register('daily', process_message)\n",
        encoding="utf-8",
    )
    graph = build_structural_graph(tmp_path)
    worksets = []
    stats: dict[str, int] = {}

    regions = _search_discovery_regions(
        tmp_path, [], HuntPlan("plan", "Review registered work", []), graph, None, None,
        stats=stats, indexed_worksets=worksets,
    )
    units, metrics = _discovery_workset_units(
        regions, root=tmp_path, graph=graph, indexed_worksets=worksets,
    )

    assert stats["rg_hits_unique"] == 0
    assert stats["indexed_registration_regions_added"] == 1
    assert metrics["graph_worksets_selected"] == 1
    assert len(units) == 1
    assert units[0].security_workset["surface_type"] == "symbol_registration"
    assert units[0].security_workset["workset_complete"] is False
    assert any(
        item.obligation_type == "surface_review" and item.importance == "REQUIRED"
        for item in units[0].obligation_specs.values()
    )


def test_indexed_registration_already_covered_by_search_is_not_added_twice(tmp_path: Path):
    from plaidnox_sast.optimized_ai import _search_discovery_regions

    (tmp_path / "worker.py").write_text(
        "def process_message(payload):\n    return payload\n\n"
        "queue.register('daily', process_message)\n",
        encoding="utf-8",
    )
    graph = build_structural_graph(tmp_path)
    stats: dict[str, int] = {}
    queries = [{
        "query_id": "registration",
        "search_terms": ["queue.register"],
        "include_globs": ["*.py"],
        "task_ids": [],
    }]

    regions = _search_discovery_regions(
        tmp_path, queries, HuntPlan("plan", "Review registered work", []),
        graph, None, None, stats=stats,
    )

    assert stats["rg_hits_unique"] == 1
    assert stats["indexed_registration_regions_added"] == 0
    assert len(regions) == 1


class _ObligationAgent:
    """Minimal mixin used with the production optimized agent below."""

    def _create_search_plan(self, _context, plan):
        return [
            {
                "query_id": "q-entry",
                "search_terms": ["authCheck"],
                "include_globs": ["*.js"],
                "task_ids": [plan.tasks[0].task_id],
                "coverage_refs": ["auth-invariant"],
            }
        ]


def _discovery_context(tmp_path: Path):
    return AIRepositoryContext(
        "org/repo",
        "revision",
        "Express fixture",
        [],
        [],
        ["app.js"],
        0,
        0,
        analysis_scope_paths=["app.js"],
    )


def _discovery_plan():
    return HuntPlan(
        "plan",
        "Review the authentication boundary.",
        [
            HuntTask(
                "task-auth",
                "Authentication identity integrity",
                "Trace authenticated identity into consumers.",
                ["app.js"],
                ["GET /account"],
                ["authentication"],
                ["Trace the identity value into protected effects."],
                [],
                [],
                business_invariants=["Verified identity cannot be overwritten."],
                coverage_obligations=["Account for all identity consumers."],
            )
        ],
    )


def _terminal_results(request):
    return [
        {
            "obligation_id": item["obligation_id"],
            "status": "NO_ISSUE",
            "candidate_ids": [],
            "evidence": [],
            "reason": "The supplied evidence does not support a boundary failure.",
            "context_requests": [],
        }
        for item in request["security_obligations"]
    ]


def test_optimized_discovery_calls_each_terminal_region_once(tmp_path: Path):
    from plaidnox_sast.optimized_ai import OptimizedPlaidNoxDeepHuntAgent

    class Agent(_ObligationAgent, OptimizedPlaidNoxDeepHuntAgent):
        def __init__(self):
            super().__init__(SimpleNamespace())
            self.requests = []

        def _structured_response(self, _name, _schema, _operation, payload, **_kwargs):
            self.requests.append(payload)
            return SimpleNamespace(
                output_text=json.dumps(
                    {"candidates": [], "obligation_results": _terminal_results(payload)}
                )
            )

    (tmp_path / "app.js").write_text(
        "function authCheck(req) { return req.user; }\nauthCheck(request);\n",
        encoding="utf-8",
    )
    agent = Agent()
    agent.configure_security_graph(build_structural_graph(tmp_path))
    candidates, failures = agent.discover_candidates(
        tmp_path,
        _discovery_context(tmp_path),
        _discovery_plan(),
    )

    assert candidates == []
    assert failures == 0
    assert len(agent.requests) == agent.discovery_metrics["regions_planned"]
    assert agent.requests[0]["security_workset"]["slices"]
    assert "content" not in agent.requests[0]["source_segment"]
    assert agent.requests[0]["security_workset"]["evidence_source"] == "tree_sitter_graph"
    assert {window["start_line"] for window in agent.requests[0]["source_windows"]} == {1, 2}
    assert agent.discovery_metrics["continuations_executed"] == 0
    assert agent.discovery_metrics["discovery_model_calls_per_unique_region"] == 1.0


def test_context_broker_blocks_continuation_when_request_adds_no_evidence(tmp_path: Path):
    from plaidnox_sast.optimized_ai import OptimizedPlaidNoxDeepHuntAgent

    class Agent(_ObligationAgent, OptimizedPlaidNoxDeepHuntAgent):
        def __init__(self):
            super().__init__(SimpleNamespace())
            self.requests = []

        def _structured_response(self, _name, _schema, _operation, payload, **_kwargs):
            self.requests.append(payload)
            results = []
            for obligation in payload["security_obligations"]:
                results.append(
                    {
                        "obligation_id": obligation["obligation_id"],
                        "status": "NEEDS_CONTEXT",
                        "candidate_ids": [],
                        "evidence": [],
                        "reason": "A consumer is required.",
                        "context_requests": [
                            {
                                **_context_request(),
                                "symbol": "symbol_that_does_not_exist",
                            }
                        ],
                    }
                )
            return SimpleNamespace(output_text=json.dumps({"candidates": [], "obligation_results": results}))

    (tmp_path / "app.js").write_text("function authCheck(req) { return req.user; }\n", encoding="utf-8")
    agent = Agent()
    agent.configure_security_graph(build_structural_graph(tmp_path))
    _candidates, failures = agent.discover_candidates(
        tmp_path,
        _discovery_context(tmp_path),
        _discovery_plan(),
    )

    assert failures == 0
    assert len(agent.requests) == 1
    assert agent.discovery_metrics["continuations_blocked_no_new_context"] >= 1
    assert agent.discovery_unresolved_obligations >= 1


def test_context_broker_continuation_contains_only_new_delta(tmp_path: Path):
    from plaidnox_sast.optimized_ai import OptimizedPlaidNoxDeepHuntAgent

    class Agent(_ObligationAgent, OptimizedPlaidNoxDeepHuntAgent):
        def __init__(self):
            super().__init__(SimpleNamespace())
            self.requests = []

        def _structured_response(self, _name, _schema, _operation, payload, **_kwargs):
            self.requests.append(payload)
            if len(self.requests) == 1:
                results = [
                    {
                        "obligation_id": item["obligation_id"],
                        "status": "NEEDS_CONTEXT",
                        "candidate_ids": [],
                        "evidence": [],
                        "reason": "Resolve the downstream consumer.",
                        "context_requests": [{**_context_request(), "symbol": "consumeIdentity"}],
                    }
                    for item in payload["security_obligations"]
                ]
            else:
                results = _terminal_results(payload)
            return SimpleNamespace(output_text=json.dumps({"candidates": [], "obligation_results": results}))

    (tmp_path / "app.js").write_text(
        "function authCheck(req) { return req.user; }\n"
        "function consumeIdentity(user) { return user.email; }\n",
        encoding="utf-8",
    )
    agent = Agent()
    agent.configure_security_graph(build_structural_graph(tmp_path))
    _candidates, failures = agent.discover_candidates(
        tmp_path,
        _discovery_context(tmp_path),
        _discovery_plan(),
    )

    assert failures == 0
    assert len(agent.requests) == 2
    continuation = agent.requests[1]
    assert "source_segment" not in continuation
    assert "repository_context" not in continuation
    assert continuation["new_context"]
    assert agent.discovery_metrics["continuations_executed"] == 1


def test_candidate_grounding_windows_require_source_content_in_broker_packet():
    from plaidnox_sast.optimized_ai import _source_windows_from_context

    windows = _source_windows_from_context(
        [
            {
                "path": "middleware.js",
                "start_line": 9,
                "end_line": 10,
                "content": "9: function authCheck() {\n10: return false;",
            },
            {
                "matches": [
                    {
                        "path": "app.js",
                        "line": 20,
                        "content": "18: app.get(\n19: '/account',\n20: authCheck,\n21: handler);",
                    },
                    {"path": "ignored.js", "line": 1},
                ]
            },
        ]
    )

    assert windows == [
        {"path": "middleware.js", "start_line": 9, "end_line": 10},
        {"path": "app.js", "start_line": 18, "end_line": 21},
    ]


def test_continuation_candidate_from_broker_source_reaches_candidate_queue(tmp_path: Path, monkeypatch):
    from plaidnox_sast.optimized_ai import OptimizedPlaidNoxDeepHuntAgent

    class Agent(_ObligationAgent, OptimizedPlaidNoxDeepHuntAgent):
        def __init__(self):
            super().__init__(SimpleNamespace())
            self.requests = []

        def _structured_response(self, _name, _schema, _operation, payload, **_kwargs):
            self.requests.append(payload)
            if len(self.requests) == 1:
                results = [
                    {
                        "obligation_id": item["obligation_id"],
                        "status": "NEEDS_CONTEXT",
                        "candidate_ids": [],
                        "evidence": [],
                        "reason": "The auth middleware source is needed.",
                        "context_requests": [_context_request()],
                    }
                    for item in payload["security_obligations"]
                ]
                candidates = []
            else:
                candidates = [
                    {
                        "candidate_id": "cross-file-auth",
                        "title": "Unverified identity controls token revocation",
                        "vulnerability_class": "CWE-287",
                        "classification_references": [],
                        "business_impact": "Another user's session can be revoked.",
                        "severity": "high",
                        "confidence": 0.91,
                        "category": "authentication",
                        "path": "middleware.js",
                        "start_line": 2,
                        "end_line": 3,
                        "message": "Decoded cookie claims select the account to mutate.",
                        "attack_path": "cookie -> jwt.decode -> account update",
                        "evidence_basis": {
                            "origin": [], "propagation": [], "expected_boundary": [],
                            "sensitive_effect": [], "controls_checked": [], "missing_evidence": [],
                        },
                        "root_cause": {
                            "symbol": "authCheck", "security_control": "token verification",
                            "broken_invariant": "Unverified identity cannot select a record.",
                            "capability": "revoke another user's token",
                        },
                        "root_equivalence": {
                            "control_family_id": "TOKEN_VERIFICATION",
                            "invariant_family_id": "VERIFIED_IDENTITY_ONLY",
                            "effect_family_id": "AUTH_STATE_WRITE",
                            "capability_family_id": "CROSS_USER_TOKEN_REVOCATION",
                        },
                        "attacker_influence": "Cookie token",
                        "security_control": "Cognito verification",
                        "broken_invariant": "Unverified identity cannot select a record.",
                        "sensitive_effect": "Token revocation",
                        "gained_capability": "Revoke another user's token",
                        "required_context": [],
                    }
                ]
                results = [
                    {
                        "obligation_id": item["obligation_id"],
                        "status": "CANDIDATE_FOUND",
                        "candidate_ids": ["cross-file-auth"],
                        "evidence": [],
                        "reason": "The cross-file root cause is evidenced.",
                        "context_requests": [],
                    }
                    for item in payload["security_obligations"]
                ]
            return SimpleNamespace(
                output_text=json.dumps({"candidates": candidates, "obligation_results": results})
            )

    (tmp_path / "app.js").write_text(
        "app.get('/account', authCheck, handler);\n",
        encoding="utf-8",
    )
    (tmp_path / "middleware.js").write_text(
        "function authCheck(req) {\n"
        "  const claims = jwt.decode(req.cookies.idToken);\n"
        "  return removeAccessTokenFromDB(claims.email);\n"
        "}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "plaidnox_sast.optimized_ai._resolve_discovery_context_request",
        lambda *_args, **_kwargs: {
            "kind": "readers",
            "resolved": True,
            "matches": [
                {
                    "path": "middleware.js",
                    "line": 2,
                    "end_line": 3,
                    "content": "1: function authCheck(req) {\n2: const claims = jwt.decode(req.cookies.idToken);\n3: return removeAccessTokenFromDB(claims.email);",
                }
            ],
            "context_characters": 128,
        },
    )
    agent = Agent()
    agent.configure_security_graph(build_structural_graph(tmp_path))

    candidates, failures = agent.discover_candidates(
        tmp_path,
        _discovery_context(tmp_path),
        _discovery_plan(),
    )

    assert failures == 0
    assert len(agent.requests) == 2
    assert len(candidates) == 1
    assert candidates[0].evidence.path == "middleware.js"
    assert candidates[0].metadata["candidate_id"] == "cross-file-auth"


def test_typed_context_uses_security_ir_before_ripgrep_for_references(tmp_path):
    (tmp_path / "routes.js").write_text(
        "app.get('/reports', authCheck, reportHandler);\n",
        encoding="utf-8",
    )
    graph = StructuralGraph(
        references=[Reference("routes.js", "authCheck", "routes.js", 1, "identifier")]
    )
    agent = SimpleNamespace(
        security_graph=graph,
        source_excludes=[],
        max_file_bytes=None,
        knowledge_coordinator=None,
    )

    result = _resolve_discovery_context_request(
        agent,
        tmp_path,
        {"kind": "readers", "symbol": "authCheck"},
    )

    assert result["resolved"] is True
    assert result["resolution_source"] == "security_ir"
    assert result["matches"][0]["relationship"] == "reference"
    assert result["matches"][0]["direction_proven"] is False
    assert "authCheck" in result["matches"][0]["content"]


def test_typed_middleware_context_resolves_route_attachment_from_security_ir(tmp_path):
    (tmp_path / "routes.js").write_text(
        "app.get('/reports', authCheck, reportHandler);\n",
        encoding="utf-8",
    )
    graph = StructuralGraph(
        references=[Reference("routes.js", "authCheck", "routes.js", 1, "identifier")],
        routes=[Symbol("GET /reports", "routes.js", 1, 1, "route")],
    )
    agent = SimpleNamespace(
        security_graph=graph,
        source_excludes=[],
        max_file_bytes=None,
        knowledge_coordinator=None,
    )

    result = _resolve_discovery_context_request(
        agent,
        tmp_path,
        {"kind": "middleware", "symbol": "authCheck"},
    )

    assert result["resolved"] is True
    assert result["resolution_source"] == "security_ir"
    assert result["routes"][0]["name"] == "GET /reports"
    assert "authCheck" in result["routes"][0]["content"]


def test_typed_context_falls_back_to_ripgrep_when_security_ir_has_no_relationship(tmp_path):
    (tmp_path / "routes.js").write_text(
        "app.get('/reports', authCheck, reportHandler);\n",
        encoding="utf-8",
    )
    agent = SimpleNamespace(
        security_graph=StructuralGraph(),
        source_excludes=[],
        max_file_bytes=None,
        knowledge_coordinator=None,
    )

    result = _resolve_discovery_context_request(
        agent,
        tmp_path,
        {"kind": "middleware", "symbol": "authCheck"},
    )

    assert result["resolved"] is True
    assert result["resolution_source"] == "ripgrep_fallback"
    assert result["matches"][0]["content"]
