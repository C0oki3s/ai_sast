from plaidnox_sast.coverage import obligation_identity, reconcile_obligations


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
