"""Production dependency assembly for SCM review."""

from __future__ import annotations

from dataclasses import dataclass

from plaidnox_sast.ai import PlaidNoxDeepHuntAgent
from plaidnox_sast.assets import load_json as load_sast_json
from plaidnox_sast.routers import CandidateRouter
from plaidnox_sast.llm import (
    LiteLLMConfigurationError,
    LiteLLMResponsesClient,
    LiteLLMSettings,
)

from .application_context import SastApplicationContextBuilder
from .l1_review import LiteLLMChangedFileReviewer
from .verification import SastDeepHuntVerifier


@dataclass(frozen=True, slots=True)
class ReviewDependencies:
    context_builder: SastApplicationContextBuilder
    l1_reviewer: LiteLLMChangedFileReviewer
    candidate_verifier: SastDeepHuntVerifier


def dependencies_from_environment() -> ReviewDependencies:
    """Use one LiteLLM SDK client for context, L1 discovery, and Deep Hunt."""

    models = load_sast_json("runtime/models.json")
    model = str(models["agent_default_model"])
    settings = LiteLLMSettings.from_environment(model)
    try:
        import litellm
    except ImportError as exc:
        raise LiteLLMConfigurationError("Install the AI extra with: pip install -e '.[ai]'") from exc
    client = LiteLLMResponsesClient(settings, litellm.responses)
    agent = PlaidNoxDeepHuntAgent(client, model=model)
    return ReviewDependencies(
        context_builder=SastApplicationContextBuilder(agent),
        l1_reviewer=LiteLLMChangedFileReviewer(client),
        candidate_verifier=SastDeepHuntVerifier(agent, router=CandidateRouter()),
    )
