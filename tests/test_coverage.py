from plaidnox_sast.coverage import (
    obligation_identity,
    reconcile_obligations,
    reconcile_workset_batches,
)


def _record(region: str, status: str, *, type_name: str = "security_invariant"):
    question = '{"business_invariants":["verified identity is immutable"]}'
    canonical_id, importance = obligation_identity(type_name, question, region_id=region)
    return {
        "region_id": region,
        "obligation": {
            "type": type_name,
            "question": question,
            "canonical_id": canonical_id,
            "importance": importance,
        },
        "status": status,
    }


def test_reconciler_resolves_sibling_region_duplicate_without_hiding_raw_state():
    result = reconcile_obligations(
        [_record("region-a", "UNRESOLVED"), _record("region-b", "CANDIDATE_FOUND")]
    )

    assert result["canonical_required_obligations"] == 1
    assert result["canonical_required_unresolved"] == 0
    assert result["obligations_reconciled_by_sibling"] == 1


def test_reconciler_keeps_distinct_required_obligations_unresolved():
    first = _record("region-a", "UNRESOLVED")
    second = _record("region-b", "UNRESOLVED")
    second["obligation"]["question"] = '{"business_invariants":["tenant ownership is enforced"]}'
    second["obligation"]["canonical_id"], second["obligation"]["importance"] = obligation_identity(
        "security_invariant", second["obligation"]["question"], region_id="region-b"
    )

    result = reconcile_obligations([first, second])

    assert result["canonical_obligations_total"] == 2
    assert result["canonical_required_unresolved"] == 2


def test_location_only_coverage_remains_region_scoped_and_supporting():
    question_a = '{"focus_paths":["auth.js:1-20"],"inventory_refs":["auth.js"]}'
    question_b = '{"focus_paths":["auth.js:21-40"],"inventory_refs":["auth.js"]}'
    id_a, importance_a = obligation_identity("coverage", question_a, region_id="a")
    id_b, importance_b = obligation_identity("coverage", question_b, region_id="b")

    assert id_a != id_b
    assert importance_a == importance_b == "SUPPORTING"


def test_explicit_coverage_obligation_is_required():
    _, importance = obligation_identity(
        "coverage",
        '{"coverage_obligations":["Review production authentication entry point"]}',
        region_id="route-a",
    )

    assert importance == "REQUIRED"


def _batch(region_id: str, obligation: dict, *, workset_id: str = "route-a") -> dict:
    return {
        "region_id": region_id,
        "security_workset": {
            "workset_id": workset_id,
            "evidence_hash": "snapshot-a",
            "batch_index": int(region_id.rsplit("-", 1)[-1]) if region_id.startswith("batch-") else 0,
            "batch_count": 2,
        },
        "obligations": [obligation],
    }


def test_multibatch_clean_result_does_not_hide_unresolved_sibling():
    clean = _record("batch-0", "NO_ISSUE")
    unresolved = _record("batch-1", "UNRESOLVED")
    batches = [_batch(item["region_id"], item["obligation"]) for item in (clean, unresolved)]

    reduced, metrics = reconcile_workset_batches([clean, unresolved], batches)
    result = reconcile_obligations(reduced)

    assert metrics["workset_batch_obligations_unresolved"] == 1
    assert result["canonical_required_unresolved"] == 1


def test_missing_workset_batch_remains_required_even_with_sibling_clean_result():
    clean = _record("batch-0", "NO_ISSUE")
    missing = _record("batch-1", "NO_ISSUE")
    other_workset = _record("other-region", "CANDIDATE_FOUND")
    batches = [_batch(item["region_id"], item["obligation"]) for item in (clean, missing)]

    reduced, metrics = reconcile_workset_batches([clean, other_workset], batches)
    result = reconcile_obligations(reduced)

    assert metrics["workset_batch_observations_missing"] == 1
    assert result["canonical_required_unresolved"] == 1


def test_multibatch_obligation_assigned_to_one_batch_only_can_complete():
    first = _record("batch-0", "NO_ISSUE")
    second = _record("batch-1", "CANDIDATE_FOUND")
    second["obligation"]["question"] = '{"business_invariants":["tenant isolation"]}'
    second["obligation"]["canonical_id"], second["obligation"]["importance"] = obligation_identity(
        "security_invariant", second["obligation"]["question"], region_id="batch-1"
    )
    batches = [_batch(item["region_id"], item["obligation"]) for item in (first, second)]

    reduced, metrics = reconcile_workset_batches([first, second], batches)
    result = reconcile_obligations(reduced)

    assert metrics["workset_batch_obligations_reconciled"] == 2
    assert result["canonical_required_obligations"] == 2
    assert result["canonical_required_unresolved"] == 0


def test_missing_planned_batch_is_required_coverage_gap():
    clean = _record("batch-0", "NO_ISSUE")
    reduced, metrics = reconcile_workset_batches([clean], [_batch("batch-0", clean["obligation"])])

    assert metrics["workset_batches_missing"] == 1
    assert reconcile_obligations(reduced)["canonical_required_unresolved"] == 1
