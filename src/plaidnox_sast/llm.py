"""Provider-neutral LiteLLM SDK boundary for every generative model call."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .assets import load_json


class LiteLLMConfigurationError(RuntimeError):
    """Raised when neither a LiteLLM gateway nor an allowed provider key is configured."""


@dataclass(frozen=True, slots=True)
class LiteLLMSettings:
    api_base: str | None
    api_key: str
    timeout_seconds: float
    max_retries: int
    use_gateway: bool

    @classmethod
    def from_environment(
        cls,
        model: str,
        environment: Mapping[str, str] | None = None,
        prefer_direct: bool = False,
    ) -> LiteLLMSettings:
        runtime = load_json("runtime/litellm.json")
        values = environment if environment is not None else os.environ
        api_base = values.get(str(runtime["api_base_environment"]), "").strip() or None
        gateway_key = values.get(str(runtime["api_key_environment"]), "").strip()
        direct = _direct_provider_key(model, runtime, values)
        if direct is not None and prefer_direct:
            return cls(
                api_base=None,
                api_key=direct,
                timeout_seconds=float(runtime["request_timeout_seconds"]),
                max_retries=int(runtime["request_max_retries"]),
                use_gateway=False,
            )
        if api_base:
            if not gateway_key:
                raise LiteLLMConfigurationError(
                    f"{runtime['api_key_environment']} is required when {runtime['api_base_environment']} is set"
                )
            return cls(
                api_base=api_base,
                api_key=gateway_key,
                timeout_seconds=float(runtime["request_timeout_seconds"]),
                max_retries=int(runtime["request_max_retries"]),
                use_gateway=True,
            )

        if direct is not None:
            return cls(
                api_base=None,
                api_key=direct,
                timeout_seconds=float(runtime["request_timeout_seconds"]),
                max_retries=int(runtime["request_max_retries"]),
                use_gateway=False,
            )
        raise LiteLLMConfigurationError(
            "Configure LITELLM_API_BASE and LITELLM_API_KEY, or select an allowed direct LiteLLM provider model"
        )


class LiteLLMResponse:
    """Normalize LiteLLM Responses output while preserving provider metadata."""

    def __init__(self, response: Any) -> None:
        self._response = response
        self.output_text = response_text(response)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)


class _LiteLLMResponses:
    def __init__(
        self,
        settings: LiteLLMSettings,
        responses_function: Callable[..., Any],
    ) -> None:
        self.settings = settings
        self.responses_function = responses_function

    def create(self, **kwargs: Any) -> LiteLLMResponse:
        request = {
            **kwargs,
            "api_key": self.settings.api_key,
            "timeout": self.settings.timeout_seconds,
            "max_retries": self.settings.max_retries,
        }
        if self.settings.api_base:
            request["api_base"] = self.settings.api_base
        if self.settings.use_gateway:
            request["custom_llm_provider"] = "litellm_proxy"
        return LiteLLMResponse(self.responses_function(**request))


class LiteLLMResponsesClient:
    """Small client shape used by the agent while LiteLLM owns provider routing."""

    def __init__(
        self,
        settings: LiteLLMSettings,
        responses_function: Callable[..., Any],
    ) -> None:
        self.responses = _LiteLLMResponses(settings, responses_function)

    @classmethod
    def from_environment(
        cls,
        model: str,
        prefer_direct: bool = False,
    ) -> LiteLLMResponsesClient:
        try:
            import litellm
        except ImportError as exc:
            raise LiteLLMConfigurationError(
                "Install the AI extra with: pip install -e '.[ai]'"
            ) from exc
        return cls(
            LiteLLMSettings.from_environment(model, prefer_direct=prefer_direct),
            litellm.responses,
        )


def _direct_provider_key(
    model: str,
    runtime: dict[str, Any],
    values: Mapping[str, str],
) -> str | None:
    for prefix, variable in runtime["direct_provider_key_environment_by_model_prefix"].items():
        if not model.startswith(str(prefix)):
            continue
        provider_key = values.get(str(variable), "").strip()
        if not provider_key:
            raise LiteLLMConfigurationError(f"{variable} is required for LiteLLM model {model!r}")
        return provider_key
    return None


def response_text(response: Any) -> str:
    """Extract structured answer text across provider-specific Responses shapes."""

    direct = getattr(response, "output_text", None)
    if direct:
        return str(direct)
    output_values: list[str] = []
    message_values: list[str] = []
    fallback_values: list[str] = []
    for raw_item in getattr(response, "output", None) or []:
        item = _object_dict(raw_item)
        for raw_content in item.get("content") or []:
            content = _object_dict(raw_content)
            text = content.get("text")
            if not text:
                continue
            value = str(text)
            fallback_values.append(value)
            if content.get("type") == "output_text":
                output_values.append(value)
            elif item.get("type") == "message":
                message_values.append(value)
    values = output_values or message_values or fallback_values
    return "\n".join(values)


def _object_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return dict(value.model_dump())
    if isinstance(value, dict):
        return value
    return dict(vars(value)) if hasattr(value, "__dict__") else {}
