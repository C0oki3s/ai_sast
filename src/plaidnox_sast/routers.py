from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .assets import load_json
from .models import Candidate, Depth, ModelTier, RouteDecision, Severity


class CandidateRouter:
    def classify(self, candidate: Candidate) -> RouteDecision:
        category = str(candidate.metadata.get("category", "unclassified"))
        task_class = _task_class(category)
        if candidate.severity in {Severity.CRITICAL, Severity.HIGH}:
            return RouteDecision(
                Depth.DEEP,
                "severity-safe routing fallback",
                task_class,
                ModelTier.DEEP,
                needs_cross_file="likely",
                needs_state_reconstruction="likely",
                needs_external_semantics="likely",
                needs_environment_context="likely",
                needs_deep_falsification="likely",
                analysis_complexity=4,
            )
        return RouteDecision(
            Depth.STANDARD,
            "provider-neutral routing fallback",
            task_class,
            ModelTier.STANDARD,
            needs_cross_file="unlikely",
            needs_state_reconstruction="unlikely",
            needs_external_semantics="unlikely",
            needs_environment_context="unlikely",
            needs_deep_falsification="unlikely",
            analysis_complexity=2,
        )


@dataclass(slots=True)
class ModelExecutionDecision:
    model_name: str
    model_tier: ModelTier
    confidence: float
    reason: str


class ModelExecutionRouter:
    """Select provider-neutral model tiers for non-candidate agent operations."""

    def __init__(self) -> None:
        registry = load_json("runtime/models.json")
        self.default_model = str(registry["agent_default_model"])
        self.fallback_by_tier = {
            ModelTier(str(tier)): str(model)
            for tier, model in registry["agent_fallback_model_by_tier"].items()
        }
        self.models = [dict(item) for item in registry["agent_models"]]
        self.model_override_by_operation = {
            str(operation): str(model)
            for operation, model in registry.get("agent_model_override_by_operation", {}).items()
        }

    def classify(self, operation_state: dict[str, Any]) -> ModelExecutionDecision:
        override_model = self.model_override_by_operation.get(str(operation_state.get("operation", "")))
        if override_model is not None:
            selected = next((item for item in self.models if item["name"] == override_model), None)
            override_tier = ModelTier(str(selected["tier"])) if selected is not None else ModelTier.STANDARD
            return ModelExecutionDecision(
                override_model,
                override_tier,
                1.0,
                "configured operation model override",
            )
        requested = str(operation_state.get("minimum_tier", ""))
        fallback_tier = ModelTier(requested) if requested else ModelTier.STANDARD
        fallback_model = self.fallback_by_tier.get(fallback_tier, self.default_model)
        return ModelExecutionDecision(
            fallback_model,
            fallback_tier,
            0.0,
            "configured model fallback",
        )


def _model_tier_weight(tier: ModelTier) -> int:
    return {
        ModelTier.FAST: 0,
        ModelTier.STANDARD: 1,
        ModelTier.DEEP: 2,
    }[tier]


FRONTIER_PRIORITY_WEIGHT = {"low": 0, "standard": 1, "high": 2}


@dataclass(slots=True)
class FrontierDecision:
    priority: str
    reason: str


class FrontierRouter:
    """Ranks confirmed gained-capability findings so a bounded pivot search spends
    its budget on the most promising part of the capability-chain frontier first."""

    def prioritize(self, finding_facts: dict[str, Any]) -> FrontierDecision:
        if str(finding_facts.get("severity", "medium")) in {"critical", "high"}:
            return FrontierDecision("high", "severity-safe frontier fallback")
        return FrontierDecision("standard", "provider-neutral frontier fallback")


@dataclass(slots=True)
class RetryDecision:
    action: str
    reason: str


class RetryRouter:
    """Chooses at most one bounded extra Deep Hunt round after context has already
    been expanded to its normal budget and a genuine evidence gap remains."""

    def decide(self, retry_facts: dict[str, Any]) -> RetryDecision:
        if str(retry_facts.get("model_tier", "")) != ModelTier.DEEP.value:
            return RetryDecision("escalate_model", "tier-safe retry fallback")
        if retry_facts.get("context_requests_pending", 0):
            return RetryDecision("expand_context", "unresolved-context retry fallback")
        return RetryDecision("mark_unresolved", "no-further-signal retry fallback")


def _task_class(category: str) -> str:
    """Normalize an open task label without imposing a vulnerability taxonomy."""
    normalized = "".join(character if character.isalnum() else "_" for character in category.lower())
    return normalized.strip("_") or "unclassified"
