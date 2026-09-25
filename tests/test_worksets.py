from __future__ import annotations

import hashlib
import json

import pytest

from plaidnox_sast.graph import build_structural_graph
from plaidnox_sast.worksets import (
    SecuritySlice,
    SecuritySliceTooLarge,
    SecuritySummary,
    SecurityWorkset,
    SecurityWorksetContractError,
    SourceLocation,
    security_worksets_from_regions,
    security_worksets_from_graph,
    security_summaries_from_graph,
    validate_security_contract,
)


def _location(path: str, excerpt: str, *, start: int = 1) -> SourceLocation:
    return SourceLocation(
        path=path,
        start_line=start,
        end_line=start + excerpt.count("\n"),
        content_hash=hashlib.sha256(excerpt.encode()).hexdigest(),
        excerpt=excerpt,
        symbol_id=f"{path}::handler",
    )


def _slice(
    path: str, excerpt: str, *, start: int = 1, unresolved: tuple[str, ...] = ()
) -> SecuritySlice:
    return SecuritySlice(
        locations=(_location(path, excerpt, start=start),),
        facts=({"kind": "observed_call", "target": "save"},),
        unresolved_edge_ids=unresolved,
    )


def test_workset_identity_is_stable_when_evidence_changes_but_evidence_hash_is_not():
    original = SecurityWorkset(
        "http_route", "POST /accounts/{id}", (_slice("routes/account.py", "save()"),)
    )
    updated = SecurityWorkset(
        "http_route",
        "POST /accounts/{id}",
        (_slice("routes/account.py", "save(new_value)"),),
    )

    assert original.workset_id == updated.workset_id
    assert original.evidence_hash != updated.evidence_hash


def test_workset_can_carry_cross_file_slices_with_exact_source_provenance():
    workset = SecurityWorkset(
        "http_route",
        "POST /accounts/{id}",
        (
            _slice("routes/account.py", "update(request)"),
            _slice("models/account.py", "record.save()", start=30),
        ),
        obligation_ids=("authz:account-owner",),
    )
    payload = workset.to_dict()
    validate_security_contract("security_workset", payload)

    assert [item["locations"][0]["path"] for item in payload["slices"]] == [
        "routes/account.py",
        "models/account.py",
    ]
    assert payload["obligation_ids"] == ["authz:account-owner"]
    assert payload["complete"] is True


def test_unresolved_graph_edges_are_preserved_and_mark_slice_incomplete():
    workset = SecurityWorkset(
        "symbol",
        "services.account.update",
        (_slice("services/account.py", "persist()", unresolved=("edge:call:save",)),),
    )

    assert workset.complete is False
    assert workset.to_dict()["slices"][0]["unresolved_edge_ids"] == ["edge:call:save"]


def test_batches_preserve_every_slice_and_signal_remaining_evidence():
    workset = SecurityWorkset(
        "http_route",
        "POST /accounts/{id}",
        tuple(_slice(f"services/{index}.py", "x" * 30) for index in range(5)),
    )
    policy = {"maximum_slices_per_batch": 2, "maximum_batch_characters": 2400}
    batches = workset.batches(policy)
    returned = [item["slice_id"] for batch in batches for item in batch["slices"]]

    assert returned == [item.slice_id for item in workset.slices]
    assert [len(item["slices"]) for item in batches] == [2, 2, 1]
    assert batches[0]["remaining_slice_count"] == 3
    assert batches[-1]["remaining_slice_count"] == 0
    assert all(item["batch_count"] == 3 for item in batches)
    assert all(
        len(json.dumps(item, ensure_ascii=False, sort_keys=True)) <= 2400
        for item in batches
    )


def test_slice_larger_than_budget_fails_instead_of_silent_truncation():
    workset = SecurityWorkset(
        "symbol", "service.run", (_slice("service.py", "x" * 1000),)
    )

    with pytest.raises(
        SecuritySliceTooLarge, match="split the evidence slice explicitly"
    ):
        workset.batches(
            {"maximum_slices_per_batch": 2, "maximum_batch_characters": 100}
        )


def test_source_location_rejects_absolute_and_traversal_paths():
    digest = "a" * 64
    with pytest.raises(SecurityWorksetContractError, match="repository-relative"):
        SourceLocation("../secret.py", 1, 1, digest)
    with pytest.raises(SecurityWorksetContractError, match="repository-relative"):
        SourceLocation("/etc/passwd", 1, 1, digest)
    with pytest.raises(SecurityWorksetContractError, match="repository-relative"):
        SourceLocation("C:\\Windows\\system.ini", 1, 1, digest)


def test_security_summary_keeps_stable_identity_separate_from_content_version():
    summary = SecuritySummary(
        "py:services.account.update",
        "b" * 64,
        facts=({"kind": "writes", "target": "Account"},),
        dependency_symbol_ids=("py:models.account.save",),
        unresolved_relationship_ids=("relation:dynamic_dispatch",),
    )
    payload = summary.to_dict()
    validate_security_contract("security_summary", payload)

    assert payload["symbol_id"] == "py:services.account.update"
    assert payload["content_hash"] == "b" * 64
    assert payload["complete"] is False
    assert "verdict" not in payload


def test_workset_schema_rejects_embedded_vulnerability_verdict():
    workset = SecurityWorkset(
        "symbol", "service.run", (_slice("service.py", "run()"),)
    ).to_dict()
    workset["verdict"] = "safe"

    with pytest.raises(SecurityWorksetContractError, match="schema validation"):
        validate_security_contract("security_workset", workset)


def test_region_adapter_groups_same_structural_surface_as_multiple_evidence_slices():
    regions = [
        {
            "path": "routes/account.py",
            "start_line": 10,
            "end_line": 15,
            "anchor_type": "route",
            "anchor_id": "POST /accounts/{id}",
            "content": "lookup_account(id)",
            "content_hash": "a" * 64,
            "security_ir_slice": {"calls": ["lookup_account"]},
            "obligation_ids": ["authz:account-owner"],
        },
        {
            "path": "routes/account.py",
            "start_line": 16,
            "end_line": 20,
            "anchor_type": "route",
            "anchor_id": "POST /accounts/{id}",
            "content": "save_account(value)",
            "content_hash": "b" * 64,
            "security_ir_slice": {"calls": ["save_account"]},
            "obligation_ids": ["authz:account-owner"],
        },
        {
            "path": "routes/account.py",
            "start_line": 30,
            "end_line": 35,
            "anchor_type": "route",
            "anchor_id": "DELETE /accounts/{id}",
            "content": "delete_account(id)",
            "content_hash": "c" * 64,
        },
    ]

    worksets = security_worksets_from_regions(regions)

    assert len(worksets) == 2
    post = next(item for item in worksets if "POST" in item.surface_id)
    assert len(post.slices) == 2
    assert post.obligation_ids == ("authz:account-owner",)
    assert {span.path for item in post.slices for span in item.locations} == {
        "routes/account.py"
    }


def test_workset_redacts_source_and_fact_strings_before_serialization():
    secret_uri = "mongodb+srv://operator:long-secret@db.example/app"
    source = SourceLocation(
        "src/app.py",
        1,
        1,
        hashlib.sha256(secret_uri.encode()).hexdigest(),
        excerpt=secret_uri,
    )
    evidence = SecuritySlice((source,), facts=({"observed": secret_uri},))
    summary = SecuritySummary("py:app.run", "d" * 64, facts=({"observed": secret_uri},))
    workset = SecurityWorkset(
        "symbol", "src/app.py::run", (evidence,), metadata={"note": secret_uri}
    )

    assert "operator:long-secret" not in source.excerpt
    assert "operator:long-secret" not in str(evidence.to_dict())
    assert "operator:long-secret" not in str(summary.to_dict())
    assert "operator:long-secret" not in str(workset.to_dict())


def test_region_adapter_merges_duplicate_evidence_slices_and_keeps_all_obligations():
    region = {
        "path": "routes/account.py",
        "start_line": 10,
        "end_line": 15,
        "anchor_type": "route",
        "anchor_id": "POST /accounts/{id}",
        "content": "save_account(value)",
        "content_hash": "a" * 64,
    }

    workset = security_worksets_from_regions(
        [
            {**region, "obligation_ids": ["authz:owner"]},
            {**region, "obligation_ids": ["input:validation"]},
        ]
    )[0]

    assert len(workset.slices) == 1
    assert workset.obligation_ids == ("authz:owner", "input:validation")


def test_graph_planner_builds_route_worksets_with_cross_file_evidence(sample_repo):
    with (sample_repo / "app.js").open("a", encoding="utf-8") as source:
        source.write("\napp.get('/extra', check_auth);\n")
    (sample_repo / "middleware.py").write_text(
        "def check_auth(request):\n    return request.user\n", encoding="utf-8"
    )
    graph = build_structural_graph(sample_repo)
    worksets = security_worksets_from_graph(sample_repo, graph, maximum_source_lines=2)

    route_sets = [item for item in worksets if item.surface_type == "http_route"]
    assert len(route_sets) == len(graph.routes) == 2
    route = next(item for item in route_sets if "POST /signin" in item.surface_id)
    assert route.surface_id.startswith("app.js::route:POST /signin")
    assert route.metadata["source"] == "tree_sitter_route_registration"
    assert route.complete is False
    assert {"route-callback-roles:app.js:4", "route-middleware-attachment:app.js:4"}.issubset(
        route.unresolved_edge_ids
    )
    assert "middleware attachment is not verified" in route.metadata[
        "relationship_limitations"
    ]
    assert all(
        location.end_line - location.start_line < 2
        for evidence in route.slices
        for location in evidence.locations
    )
    validate_security_contract("security_workset", route.to_dict())
    extra_route = next(item for item in route_sets if "GET /extra" in item.surface_id)
    related = [
        fact
        for evidence in extra_route.slices
        for fact in evidence.facts
        if fact.get("kind") == "route_registration_symbol_reference"
    ]
    assert related
    assert related[0]["symbol_id"] == "middleware.py::check_auth"
    assert "does not establish callback role" in related[0]["relationship_limit"]
    boundaries = [
        fact
        for evidence in extra_route.slices
        for fact in evidence.facts
        if fact.get("kind") == "callable_boundary_observation"
    ]
    assert boundaries
    assert boundaries[0]["trust_of_inputs"] == "unresolved"
    assert all(item.surface_type == "http_route" for item in route_sets)


def test_graph_planner_exposes_generic_top_level_symbol_registrations(tmp_path):
    (tmp_path / "worker.py").write_text(
        "def process_message(payload):\n    return payload\n\n"
        "queue.register('daily', process_message)\n",
        encoding="utf-8",
    )
    graph = build_structural_graph(tmp_path)

    worksets = security_worksets_from_graph(tmp_path, graph)
    registrations = [item for item in worksets if item.surface_type == "symbol_registration"]

    assert len(registrations) == 1
    registration = registrations[0]
    assert "queue.register@4" in registration.surface_id
    assert registration.complete is False
    assert registration.unresolved_edge_ids == ("registration-role:worker.py:4",)
    assert "registration role is unresolved" in registration.metadata["relationship_limitations"]
    facts = [fact for item in registration.slices for fact in item.facts]
    references = [item for item in facts if item["kind"] == "top_level_call_symbol_reference"]
    assert references
    assert references[0]["symbol_id"] == "worker.py::process_message"
    boundaries = [item for item in facts if item["kind"] == "callable_boundary_observation"]
    assert boundaries
    assert "payload" in boundaries[0]["signature_syntax"]
    assert boundaries[0]["trust_of_inputs"] == "unresolved"
    validate_security_contract("security_workset", registration.to_dict())


def test_graph_planner_rejects_source_changed_since_indexing(tmp_path):
    source = tmp_path / "app.js"
    source.write_text(
        "const app = express();\napp.get('/x', (req, res) => res.send('ok'));\n",
        encoding="utf-8",
    )
    graph = build_structural_graph(tmp_path)
    source.write_text(
        "const app = express();\napp.get('/x', (req, res) => res.send('changed'));\n",
        encoding="utf-8",
    )

    with pytest.raises(SecurityWorksetContractError, match="changed after graph construction"):
        security_worksets_from_graph(tmp_path, graph)


def test_security_summaries_resolve_unique_calls_and_preserve_unknown_relationships(tmp_path):
    (tmp_path / "service.py").write_text(
        "def persist(value):\n    return value\n\n"
        "def handle(value):\n    return persist(value)\n\n"
        "def external(value):\n    return print(value)\n",
        encoding="utf-8",
    )
    graph = build_structural_graph(tmp_path)

    summaries = security_summaries_from_graph(graph)
    by_name = {
        item.facts[0]["name"]: item
        for item in summaries
    }
    handle = by_name["handle"]
    persist = by_name["persist"]
    external = by_name["external"]

    assert handle.dependency_symbol_ids == (persist.symbol_id,)
    assert handle.complete is True
    indexed = handle.facts[0]
    assert indexed["kind"] == "indexed_symbol"
    assert "value" in indexed["signature_syntax"]
    call_facts = [item for item in handle.facts if item["kind"] == "tree_sitter_call_observation"]
    assert call_facts[0]["target_symbol_id"] == persist.symbol_id
    assert "does not establish data flow" in call_facts[0]["relationship_limit"]
    validate_security_contract("security_summary", handle.to_dict())
    assert external.complete is False
    assert external.unresolved_relationship_ids
    assert len(handle.content_hash) == 64

    previous_hash = handle.content_hash
    (tmp_path / "service.py").write_text(
        "def persist(value):\n    return value\n\n"
        "def handle(value):\n    return persist(value + 1)\n\n"
        "def external(value):\n    return print(value)\n",
        encoding="utf-8",
    )
    revised_graph = build_structural_graph(tmp_path)
    revised_by_name = {
        item.facts[0]["name"]: item
        for item in security_summaries_from_graph(revised_graph)
    }
    revised_handle = revised_by_name["handle"]
    assert revised_handle.content_hash != previous_hash


def test_graph_planner_rejects_nonpositive_slice_line_limit(sample_repo):
    graph = build_structural_graph(sample_repo)
    with pytest.raises(SecurityWorksetContractError, match="must be positive"):
        security_worksets_from_graph(sample_repo, graph, maximum_source_lines=0)
