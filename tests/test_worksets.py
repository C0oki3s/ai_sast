from __future__ import annotations

import hashlib
import json

import pytest

from plaidnox_sast.worksets import (
    SecuritySlice,
    SecuritySliceTooLarge,
    SecuritySummary,
    SecurityWorkset,
    SecurityWorksetContractError,
    SourceLocation,
    security_worksets_from_regions,
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
