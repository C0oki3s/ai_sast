"""Wave 13: triage-aware merge policy and scanner-driven fix validation."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from plaidnox_scm import attempts, triage
from plaidnox_scm.api_models import PolicyAction
from plaidnox_scm.api_service import ReviewService
from plaidnox_scm.baseline import FindingBaselineClassification
from plaidnox_scm.models import Base
from plaidnox_scm.policy import evaluate_merge_policy
from plaidnox_scm.source_broker import RepositoryMirrorBroker

TENANT = "github:installation:12345"
REVIEW = "review_wave13"


def _factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _classification(**overrides: object) -> FindingBaselineClassification:
    value = FindingBaselineClassification(
        relationship="REGRESSED",
        root_cause_fingerprint="root-1",
        finding_fingerprint="finding-1",
        candidate_id="candidate-1",
        verification_state="verified",
        baseline_state=None,
        root_cause_path="middleware/ValidateToken.js",
        root_cause_symbol="ValidateToken",
        vulnerability_class="authentication bypass",
        title="Protected routes accept forged identity claims",
        severity="high",
        confidence=0.95,
        root_cause_changed_in_review=True,
        reason="fixture",
    )
    return replace(value, **overrides)


def _persisted_finding() -> dict[str, object]:
    return {
        "finding_id": "finding-1",
        "root_cause_fingerprint": "root-1",
        "title": "Protected routes accept forged identity claims",
        "severity": "high",
        "confidence": 0.95,
        "root_cause_path": "middleware/ValidateToken.js",
        "root_cause_symbol": "ValidateToken",
        "root_cause_changed_in_pr": True,
        "category": "authentication bypass",
        "baseline_relationship": "regressed",
    }


def _seed_completed_review(factory, *, action: str = "block") -> None:
    with attempts.unit_of_work(factory, TENANT) as repository:
        repository.claim(
            REVIEW,
            "github:repository:1",
            provider="github",
            repository_id=1,
            review_number=7,
            base_sha="a" * 40,
            head_sha="b" * 40,
            delivery_id="delivery-1",
            lease_owner="worker-1",
            lease_seconds=600,
            max_attempts=3,
        )
        assert repository.complete(
            REVIEW,
            "worker-1",
            outcome="findings_verified",
            action=action,
            summary="1 verified finding(s): 1 blocking, 1 requiring triage.",
            incomplete_reason=None,
            counters={"verified": 1, "blocking": 1, "in_triage": 1},
            findings=[_persisted_finding()],
        )


def _service(factory, tmp_path: Path) -> ReviewService:
    return ReviewService(RepositoryMirrorBroker(tmp_path), factory, lambda: None)  # type: ignore[arg-type,return-value]


@pytest.mark.parametrize("state", ["false_positive", "accepted_risk"])
def test_closed_triage_state_passes_a_blocking_finding(state: str) -> None:
    result = evaluate_merge_policy(
        (_classification(),), coverage_complete=True, triage_states={"finding-1": state}
    )

    assert result.decision == "PASS"
    assert result.blocking_count == 0
    assert result.triaged_count == 1
    assert result.in_triage_count == 0
    assert result.dispositions[0].triage_state == state


@pytest.mark.parametrize("state", ["open", "confirmed", "fix_pending"])
def test_open_triage_states_keep_blocking(state: str) -> None:
    result = evaluate_merge_policy(
        (_classification(),), coverage_complete=True, triage_states={"finding-1": state}
    )

    assert result.decision == "BLOCK"
    assert result.in_triage_count == 1
    assert result.triaged_count == 0


def test_triage_never_overrides_incomplete_coverage() -> None:
    result = evaluate_merge_policy(
        (_classification(),), coverage_complete=False, triage_states={"finding-1": "false_positive"}
    )

    assert result.decision == "INCOMPLETE"


def test_triage_does_not_count_existing_baseline_debt() -> None:
    result = evaluate_merge_policy(
        (_classification(relationship="EXISTING"),),
        coverage_complete=True,
        triage_states={"finding-1": "accepted_risk"},
    )

    assert result.triaged_count == 0
    assert result.in_triage_count == 0


def test_fp_triage_immediately_reevaluates_the_completed_review(tmp_path: Path) -> None:
    factory = _factory()
    _seed_completed_review(factory)
    service = _service(factory, tmp_path)

    response = service.apply_triage_command(
        REVIEW, "finding-1", "fp", actor="reviewer", reason="sanitized upstream"
    )

    assert response is not None
    assert response.state == "false_positive"
    assert response.review_action is PolicyAction.ALLOW
    assert response.review_summary == "1 verified finding(s) reported; none require merge action."
    status = service.get_status(REVIEW)
    assert status is not None
    assert status.action == "allow"
    assert status.counters == {"verified": 1, "blocking": 0, "in_triage": 0}


def test_valid_triage_keeps_the_review_blocked(tmp_path: Path) -> None:
    factory = _factory()
    _seed_completed_review(factory)

    response = _service(factory, tmp_path).apply_triage_command(
        REVIEW, "finding-1", "valid", actor="reviewer", reason=None
    )

    assert response is not None
    assert response.review_action is PolicyAction.BLOCK


def test_incomplete_review_is_not_reevaluated_by_triage(tmp_path: Path) -> None:
    factory = _factory()
    _seed_completed_review(factory, action="incomplete")
    service = _service(factory, tmp_path)

    response = service.apply_triage_command(
        REVIEW, "finding-1", "fp", actor="reviewer", reason="sanitized upstream"
    )

    assert response is not None
    assert response.review_action is None
    assert service.get_status(REVIEW).action == "incomplete"


def _validate(factory, tmp_path: Path, *classifications: FindingBaselineClassification) -> None:
    result = SimpleNamespace(baseline_classifications=classifications)
    _service(factory, tmp_path)._record_fix_validations(TENANT, "review_later", result)  # type: ignore[arg-type]


def _apply(factory, command: str, reason: str | None = None) -> None:
    with triage.unit_of_work(factory, TENANT) as repository:
        repository.apply_command("finding-1", REVIEW, command, actor="reviewer", reason=reason)


def test_resolved_classification_validates_a_pending_fix(tmp_path: Path) -> None:
    factory = _factory()
    _apply(factory, "valid")
    _apply(factory, "fixed")

    _validate(factory, tmp_path, _classification(relationship="RESOLVED", verification_state="baseline"))

    with triage.unit_of_work(factory, TENANT) as repository:
        assert repository.get("finding-1").state == "resolved"
        events = repository.list_events("finding-1")
    assert events[-1].command == "fix_validated"
    assert events[-1].actor == "plaidnox"
    assert events[-1].previous_state == "fix_pending"


def test_reverified_finding_reopens_a_rejected_fix(tmp_path: Path) -> None:
    factory = _factory()
    _apply(factory, "valid")
    _apply(factory, "fixed")

    _validate(factory, tmp_path, _classification())

    with triage.unit_of_work(factory, TENANT) as repository:
        assert repository.get("finding-1").state == "open"
        assert repository.list_events("finding-1")[-1].command == "fix_rejected"


def test_false_positive_verdict_survives_fix_validation(tmp_path: Path) -> None:
    factory = _factory()
    _apply(factory, "fp", reason="not reachable")

    _validate(factory, tmp_path, _classification(relationship="RESOLVED", verification_state="baseline"))
    _validate(factory, tmp_path, _classification())

    with triage.unit_of_work(factory, TENANT) as repository:
        assert repository.get("finding-1").state == "false_positive"


def test_reverified_confirmed_finding_records_no_event(tmp_path: Path) -> None:
    factory = _factory()
    _apply(factory, "valid")

    _validate(factory, tmp_path, _classification())

    with triage.unit_of_work(factory, TENANT) as repository:
        assert repository.get("finding-1").state == "confirmed"
        assert len(repository.list_events("finding-1")) == 1
