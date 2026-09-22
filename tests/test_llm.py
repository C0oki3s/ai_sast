from __future__ import annotations

from types import SimpleNamespace

import pytest

from plaidnox_sast.llm import (
    LiteLLMConfigurationError,
    LiteLLMResponsesClient,
    LiteLLMSettings,
)


def test_gateway_settings_require_a_virtual_key():
    with pytest.raises(LiteLLMConfigurationError):
        LiteLLMSettings.from_environment(
            "kimi-k2.7-code",
            {"LITELLM_API_BASE": "http://localhost:4000"},
        )


def test_perplexity_research_can_use_its_provider_key_through_litellm_sdk():
    settings = LiteLLMSettings.from_environment(
        "perplexity/perplexity/sonar",
        {
            "LITELLM_API_BASE": "http://localhost:4000",
            "LITELLM_API_KEY": "gateway-key",
            "IFRIT_PERPLEXITY_API_KEY": "research-key",
        },
        prefer_direct=True,
    )

    assert settings.use_gateway is False
    assert settings.api_base is None
    assert settings.api_key == "research-key"


def test_gateway_client_injects_litellm_proxy_transport_settings():
    requests = []

    def fake_responses(**kwargs):
        requests.append(kwargs)
        return SimpleNamespace(output_text="result")

    settings = LiteLLMSettings.from_environment(
        "kimi-k2.7-code",
        {
            "LITELLM_API_BASE": "http://localhost:4000",
            "LITELLM_API_KEY": "gateway-key",
        },
    )
    client = LiteLLMResponsesClient(settings, fake_responses)

    response = client.responses.create(model="kimi-k2.7-code", input="evidence")

    assert response.output_text == "result"
    assert requests[0]["api_base"] == "http://localhost:4000"
    assert requests[0]["api_key"] == "gateway-key"
    assert requests[0]["custom_llm_provider"] == "litellm_proxy"


def test_response_text_is_normalized_from_litellm_message_output():
    raw = SimpleNamespace(
        output=[
            {
                "type": "message",
                "content": [{"type": "output_text", "text": "structured result"}],
            }
        ]
    )
    client = LiteLLMResponsesClient(
        LiteLLMSettings(None, "provider-key", 30, 1, False),
        lambda **_kwargs: raw,
    )

    assert client.responses.create(model="provider/model", input="evidence").output_text == "structured result"
