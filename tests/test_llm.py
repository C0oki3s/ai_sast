from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from plaidnox_sast.llm import (
    LiteLLMConfigurationError,
    LiteLLMResponsesClient,
    LiteLLMSettings,
    parse_json_text,
    parse_structured,
    response_json,
    response_text,
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


def test_response_text_falls_back_to_reasoning_item_content() -> None:
    response = SimpleNamespace(
        output_text="",
        output=[
            SimpleNamespace(
                type="reasoning",
                content=[SimpleNamespace(type="text", text='{"supported": true}')],
            )
        ],
    )

    assert response_text(response) == '{"supported": true}'


@pytest.mark.parametrize(
    "text",
    [
        '{"architecture": "a", "applications": []}',
        '```json\n{"architecture": "a", "applications": []}\n```',
        'Here is the context:\n```\n{"architecture": "a", "applications": []}\n```\nDone.',
        'Here is the context: {"architecture": "a", "applications": []} -- hope it helps',
    ],
)
def test_structured_answers_tolerate_markdown_and_prose_wrappers(text: str) -> None:
    assert parse_json_text(text) == {"architecture": "a", "applications": []}


def test_truncated_structured_answer_still_fails() -> None:
    with pytest.raises(json.JSONDecodeError):
        parse_json_text('```json\n{"architecture": "a", "applications": [')


def test_response_json_reads_the_normalized_response_text() -> None:
    response = SimpleNamespace(output_text='```json\n{"supported": true}\n```')
    assert response_json(response) == {"supported": True}


_OBJECT_SCHEMA = {"type": "object", "required": ["architecture", "applications"]}


@pytest.mark.parametrize(
    "text",
    [
        '[{"architecture": "api", "applications": []}]',
        '{"repository_context": {"architecture": "api", "applications": []}}',
        'See [a] and ["b"]: {"architecture": "api", "applications": []}',
    ],
)
def test_parse_structured_unwraps_arrays_envelopes_and_bracketed_prose(text):
    assert parse_structured(text, _OBJECT_SCHEMA) == ({"architecture": "api", "applications": []}, True)


def test_parse_structured_prefers_the_outer_object_over_a_nested_namesake():
    text = '{"architecture": "api", "applications": [{"architecture": "x", "applications": [], "extra": 1}]}'

    value, shaped = parse_structured(text, _OBJECT_SCHEMA)

    assert shaped is True
    assert value["architecture"] == "api"


def test_parse_structured_accepts_a_sparse_but_correctly_shaped_object():
    assert parse_structured('{"architecture": "api"}', _OBJECT_SCHEMA) == ({"architecture": "api"}, True)


def test_parse_structured_flags_a_wrong_shape_and_rejects_non_json():
    assert parse_structured('["app.js"]', _OBJECT_SCHEMA) == (["app.js"], False)
    with pytest.raises(json.JSONDecodeError):
        parse_structured("no json here", _OBJECT_SCHEMA)
