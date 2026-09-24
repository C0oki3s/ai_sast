from plaidnox_sast.assets import load_json
from plaidnox_sast.routers import (
    FRONTIER_PRIORITY_WEIGHT,
    CandidateRouter,
    FrontierRouter,
    ModelExecutionRouter,
    RetryRouter,
)
from plaidnox_sast.models import (
    Candidate,
    Depth,
    Evidence,
    ModelTier,
    Severity,
)
from plaidnox_sast.validation import FindingValidator


def test_candidate_router_escalates_ssrf_to_deep():
    candidate = Candidate(
        rule_id="ssrf",
        title="SSRF",
        vulnerability_class="CWE-918",
        severity=Severity.HIGH,
        confidence=0.8,
        message="message",
        evidence=Evidence("app.js", 1, 1),
        metadata={"category": "ssrf"},
    )
    decision = CandidateRouter().classify(candidate)
    assert decision.depth is Depth.DEEP
    assert decision.needs_cross_file == "likely"
    assert decision.needs_deep_falsification == "likely"
    assert decision.analysis_complexity == 4
    assert decision.task_class == "ssrf"
    assert decision.model_tier is ModelTier.DEEP
    assert decision.needs_deep_hunt is True


def test_candidate_router_classifies_other_severities_as_standard():
    candidate = Candidate(
        rule_id="info-leak",
        title="Info leak",
        vulnerability_class="CWE-200",
        severity=Severity.MEDIUM,
        confidence=0.5,
        message="message",
        evidence=Evidence("app.js", 1, 1),
        metadata={"category": "info_leak"},
    )
    decision = CandidateRouter().classify(candidate)
    assert decision.depth is Depth.STANDARD
    assert decision.needs_cross_file == "unlikely"
    assert decision.analysis_complexity == 2
    assert decision.model_tier is ModelTier.STANDARD


def test_validated_findings_record_candidate_route_classification(sample_repo):
    candidate = Candidate(
        "ssrf", "SSRF", "CWE-918", Severity.HIGH, 0.8, "request renderer", Evidence("app.js", 1, 1), {"category": "ssrf"}
    )
    finding = FindingValidator().validate(
        "owner/repo", sample_repo, candidate, CandidateRouter().classify(candidate)
    )
    assert finding is not None
    assert finding.metadata["route_task_class"] == "ssrf"
    assert finding.metadata["route_model_tier"] == "deep"
    assert finding.metadata["route_needs_deep_hunt"] is True


def test_frontier_priority_weight_orders_low_below_standard_below_high():
    assert FRONTIER_PRIORITY_WEIGHT["low"] < FRONTIER_PRIORITY_WEIGHT["standard"] < FRONTIER_PRIORITY_WEIGHT["high"]


def test_model_execution_router_uses_configured_fallback():
    decision = ModelExecutionRouter().classify({"operation": "hunt_plan"})

    assert decision.model_name == load_json("runtime/models.json")["agent_fallback_model_by_tier"]["standard"]
    assert decision.model_tier is ModelTier.STANDARD
    assert decision.reason == "configured model fallback"


def test_model_execution_router_does_not_pin_repository_context_to_a_model():
    decision = ModelExecutionRouter().classify({"operation": "repository_context"})

    assert load_json("runtime/models.json")["agent_model_override_by_operation"] == {}
    assert decision.model_name == load_json("runtime/models.json")["agent_fallback_model_by_tier"]["standard"]
    assert decision.model_tier is ModelTier.STANDARD
    assert decision.confidence == 0.0
    assert decision.reason == "configured model fallback"


def test_frontier_router_prioritizes_high_severity_capabilities_as_high():
    decision = FrontierRouter().prioritize({"severity": "critical", "capability": "remote code execution"})
    assert decision.priority == "high"
    assert decision.reason == "severity-safe frontier fallback"


def test_frontier_router_prioritizes_other_severities_as_standard():
    decision = FrontierRouter().prioritize({"severity": "medium", "capability": "read internal config"})
    assert decision.priority == "standard"


def test_retry_router_escalates_a_candidate_never_routed_to_deep():
    decision = RetryRouter().decide({"model_tier": "standard", "context_requests_pending": 1})
    assert decision.action == "escalate_model"
    assert decision.reason == "tier-safe retry fallback"


def test_retry_router_expands_context_for_a_deep_candidate_with_a_pending_request():
    decision = RetryRouter().decide({"model_tier": "deep", "context_requests_pending": 2})
    assert decision.action == "expand_context"
    assert decision.reason == "unresolved-context retry fallback"


def test_retry_router_marks_unresolved_when_deep_and_nothing_pending():
    decision = RetryRouter().decide({"model_tier": "deep", "context_requests_pending": 0})
    assert decision.action == "mark_unresolved"
    assert decision.reason == "no-further-signal retry fallback"
