from __future__ import annotations

from plaidnox_sast.models import ModelTier
from plaidnox_scm.production import dependencies_from_environment


def test_scm_production_routes_models_to_gpt(monkeypatch):
    monkeypatch.setenv("LITELLM_API_BASE", "http://litellm.test:4000")
    monkeypatch.setenv("LITELLM_API_KEY", "test-gateway-key")

    dependencies = dependencies_from_environment()
    agent = dependencies.context_builder._agent
    router = agent.model_execution_router

    assert agent.model == "gpt-5.4-mini"
    assert agent.strict_output_schema is False
    assert agent.model_by_tier["deep"] == "gpt-5.4"
    assert router.fallback_by_tier[ModelTier.FAST] == "gpt-5.4-mini"
    assert router.fallback_by_tier[ModelTier.DEEP] == "gpt-5.4"
    assert router.model_override_by_operation["repository_context"] == "gpt-5.4"
    assert dependencies.l1_reviewer._model == "gpt-5.4-mini"
