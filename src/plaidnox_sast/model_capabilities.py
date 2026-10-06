"""Provider request features declared by versioned model runtime assets."""

from __future__ import annotations

from .assets import load_json


def supports_reasoning_effort(model: str) -> bool:
    """Whether a routed model accepts the Responses API reasoning-effort field."""

    return _supports(model, "reasoning_effort_model_prefixes")


def supports_text_verbosity(model: str) -> bool:
    """Whether a routed model accepts the Responses API text-verbosity field."""

    return _supports(model, "text_verbosity_model_prefixes")


def _supports(model: str, capability: str) -> bool:
    configured = load_json("runtime/models.json").get("request_capabilities", {})
    prefixes = tuple(str(prefix) for prefix in configured.get(capability, ()))
    return model.startswith(prefixes)
