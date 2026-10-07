"""Production dependency assembly for SCM review."""

from __future__ import annotations

from dataclasses import dataclass

from plaidnox_sast.llm import (
    LiteLLMConfigurationError,
    LiteLLMResponsesClient,
    LiteLLMSettings,
)
from plaidnox_sast.optimized_ai import OptimizedPlaidNoxDeepHuntAgent
from plaidnox_sast.models import ModelTier
from plaidnox_sast.routers import CandidateRouter, ModelExecutionRouter

from .application_context import SastApplicationContextBuilder
from .assets import load_json
from .l1_review import LiteLLMChangedFileReviewer
from .verification import SastDeepHuntVerifier


@dataclass(frozen=True, slots=True)
class ReviewDependencies:
    context_builder: SastApplicationContextBuilder
    l1_reviewer: LiteLLMChangedFileReviewer
    candidate_verifier: SastDeepHuntVerifier


def dependencies_from_environment() -> ReviewDependencies:
    """Use one LiteLLM SDK client for context, L1 discovery, and Deep Hunt."""

    review_runtime = load_json("runtime/review.json")
    review_models = review_runtime["models"]
    model = str(review_models["standard"])
    settings = LiteLLMSettings.from_environment(model)
    try:
        import litellm
    except ImportError as exc:
        raise LiteLLMConfigurationError("Install the AI extra with: pip install -e '.[ai]'") from exc
    client = LiteLLMResponsesClient(settings, litellm.responses)
    router = ModelExecutionRouter()
    router.default_model = model
    router.fallback_by_tier = {
        tier: str(review_models[tier.value]) for tier in ModelTier
    }
    router.model_override_by_operation["repository_context"] = str(
        review_models["repository_context"]
    )
    agent = OptimizedPlaidNoxDeepHuntAgent(client, model=model, model_execution_router=router)
    # Existing SCM schemas contain optional fields. OpenAI strict mode requires
    # every object property to be required; local parsing still validates output.
    agent.strict_output_schema = False
    agent.model_by_tier = {tier.value: str(review_models[tier.value]) for tier in ModelTier}
    return ReviewDependencies(
        context_builder=SastApplicationContextBuilder(agent),
        l1_reviewer=LiteLLMChangedFileReviewer(
            client, model=str(review_models[str(review_runtime["l1_model_tier"])])
        ),
        candidate_verifier=SastDeepHuntVerifier(agent, router=CandidateRouter()),
    )
