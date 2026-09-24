"""Provider-neutral LiteLLM SDK boundary for scan-reasoning model calls."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterator, Mapping
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
        request = {**kwargs, "api_key": self.settings.api_key}
        # Callers may apply a tighter operation-specific policy. The client
        # settings remain the transport fallback rather than silently
        # overwriting that policy with the global timeout/retry budget.
        request.setdefault("timeout", self.settings.timeout_seconds)
        request.setdefault("max_retries", self.settings.max_retries)
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


_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def response_json(response: Any) -> Any:
    """Decode a structured model answer, tolerating wrappers some gateways add.

    Providers behind LiteLLM do not all honour ``json_schema`` strictly: some
    wrap the object in a Markdown fence or add a sentence around it. Strict
    ``json.loads`` then failed the whole scan stage. A truncated or otherwise
    malformed answer still raises ``json.JSONDecodeError``.
    """

    return parse_json_text(response_text(response))


def parse_json_text(text: str) -> Any:
    stripped = text.strip()
    try:
        return _reject_storage_truncation(json.loads(stripped), stripped)
    except json.JSONDecodeError as strict_error:
        candidates = [match.group(1).strip() for match in _JSON_FENCE.finditer(stripped)]
        start = min((index for index in (stripped.find("{"), stripped.find("[")) if index >= 0), default=-1)
        if start >= 0:
            candidates.append(stripped[start:])
        decoder = json.JSONDecoder()
        for candidate in candidates:
            try:
                value, _ = decoder.raw_decode(candidate)
            except json.JSONDecodeError:
                continue
            return _reject_storage_truncation(value, stripped)
        raise strict_error


def _reject_storage_truncation(value: Any, source: str) -> Any:
    markers = [
        str(item).lower()
        for item in load_json("runtime/litellm.json")["response_rejection_markers"]
    ]

    def contains(item: Any) -> bool:
        if isinstance(item, str):
            lowered = item.lower()
            return any(marker in lowered for marker in markers)
        if isinstance(item, dict):
            return any(contains(key) or contains(child) for key, child in item.items())
        if isinstance(item, (list, tuple)):
            return any(contains(child) for child in item)
        return False

    if contains(value):
        raise json.JSONDecodeError("LiteLLM response contains a storage-truncation marker", source, 0)
    return value


class StructuredResponse:
    """A model response whose answer text was reshaped into the requested schema."""

    def __init__(self, response: Any, payload: Any) -> None:
        self._response = response
        self.output_text = json.dumps(payload, ensure_ascii=False)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)


_MAX_JSON_START_POSITIONS = 64
_MAX_UNWRAP_DEPTH = 2
_MAX_UNWRAP_ITEMS = 50


def parse_structured(text: str, schema: Mapping[str, Any]) -> tuple[Any, bool]:
    """Decode the answer value that best fits an object ``schema``.

    Gateways that ignore ``json_schema`` may return the object wrapped in a
    one-key envelope (``{"repository_context": {...}}``), inside an array
    (``[{...}]``), or after prose that itself contains brackets. Every JSON
    value in the text is considered, single-key envelopes and arrays are
    unwrapped, and the first object (in text order, outermost first) that
    carries any required key wins. Ranking by key count instead would pick a
    nested item that happens to reuse top-level field names. Returns
    ``(value, shaped)``; a sparse but correctly shaped object is left for the
    caller's own field checks, since only a wrong shape is worth a retry.
    Raises ``json.JSONDecodeError`` when no JSON value can be decoded at all.
    """

    required = {str(key) for key in schema.get("required", ())}
    decoded = _decoded_values(text.strip())
    if schema.get("type") != "object" or not required:
        return decoded[0], True
    for value in decoded:
        for candidate in _unwrapped(value, 0):
            if isinstance(candidate, dict) and required.intersection(candidate):
                return candidate, True
    return decoded[0], False


def _decoded_values(text: str) -> list[Any]:
    try:
        return [json.loads(text)]
    except json.JSONDecodeError as strict_error:
        sources = [match.group(1).strip() for match in _JSON_FENCE.finditer(text)]
        starts = [index for index, char in enumerate(text) if char in "{["][:_MAX_JSON_START_POSITIONS]
        sources.extend(text[index:] for index in starts)
        decoder = json.JSONDecoder()
        values: list[Any] = []
        for source in sources:
            try:
                value, _ = decoder.raw_decode(source)
            except json.JSONDecodeError:
                continue
            values.append(value)
        if not values:
            raise strict_error
        return values


def _unwrapped(value: Any, depth: int) -> Iterator[Any]:
    yield value
    if depth >= _MAX_UNWRAP_DEPTH:
        return
    if isinstance(value, list):
        for item in value[:_MAX_UNWRAP_ITEMS]:
            yield from _unwrapped(item, depth + 1)
    elif isinstance(value, dict) and len(value) == 1:
        yield from _unwrapped(next(iter(value.values())), depth + 1)


def _object_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return dict(value.model_dump())
    if isinstance(value, dict):
        return value
    return dict(vars(value)) if hasattr(value, "__dict__") else {}
