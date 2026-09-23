from __future__ import annotations

from dataclasses import replace

from plaidnox_scm.baseline import BaselineRelationship, FindingBaselineClassification
from plaidnox_scm.policy import evaluate_merge_policy


def _classification(
    *,
    relationship: BaselineRelationship = "REGRESSED",
    severity: str = "high",
    confidence: float = 0.95,
    verification_state: str = "verified",
) -> FindingBaselineClassification:
    return FindingBaselineClassification(
        relationship=relationship,
        root_cause_fingerprint="root-1",
        finding_fingerprint="finding-1",
        candidate_id="candidate-1",
        verification_state=verification_state,
        baseline_state=None,
        root_cause_path="middleware/ValidateToken.js",
        root_cause_symbol="ValidateToken",
        vulnerability_class="authentication bypass",
        title="Protected routes accept forged identity claims",
        severity=severity,
        confidence=confidence,
        root_cause_changed_in_review=True,
        reason="fixture",
    )


def test_high_regressed_finding_blocks_merge() -> None:
    result = evaluate_merge_policy((_classification(),), coverage_complete=True)

    assert result.decision == "BLOCK"
    assert result.blocking_count == 1
    assert result.warning_count == 0


def test_medium_introduced_finding_warns() -> None:
    result = evaluate_merge_policy(
        (_classification(relationship="INTRODUCED", severity="medium"),),
        coverage_complete=True,
    )

    assert result.decision == "WARN"
    assert result.warning_count == 1


def test_existing_high_finding_is_visible_but_does_not_block_default_policy() -> None:
    result = evaluate_merge_policy(
        (_classification(relationship="EXISTING"),),
        coverage_complete=True,
    )

    assert result.decision == "PASS"
    assert result.existing_count == 1
    assert result.blocking_count == 0


def test_resolved_finding_is_informational() -> None:
    result = evaluate_merge_policy(
        (_classification(relationship="RESOLVED", verification_state="rejected"),),
        coverage_complete=True,
    )

    assert result.decision == "PASS"
    assert result.resolved_count == 1


def test_incomplete_review_never_returns_success() -> None:
    result = evaluate_merge_policy((), coverage_complete=False)

    assert result.decision == "INCOMPLETE"
    assert result.incomplete is True


def test_low_confidence_verified_result_requires_security_approval() -> None:
    result = evaluate_merge_policy(
        (_classification(confidence=0.69),),
        coverage_complete=True,
    )

    assert result.decision == "REQUIRE_SECURITY_APPROVAL"
    assert result.approval_count == 1


def test_unknown_severity_requires_security_approval() -> None:
    result = evaluate_merge_policy(
        (_classification(severity="urgent"),),
        coverage_complete=True,
    )

    assert result.decision == "REQUIRE_SECURITY_APPROVAL"


def test_blocking_verified_finding_retains_block_when_other_coverage_is_incomplete() -> None:
    result = evaluate_merge_policy((_classification(),), coverage_complete=False)

    assert result.decision == "BLOCK"
    assert result.incomplete is True
    assert any("incomplete" in reason.lower() for reason in result.reasons)


def test_policy_evaluation_does_not_mutate_classification() -> None:
    finding = _classification()
    original = replace(finding)

    evaluate_merge_policy((finding,), coverage_complete=True)

    assert finding == original
