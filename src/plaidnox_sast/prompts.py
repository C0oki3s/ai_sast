"""Strict Jinja rendering for versioned agent prompts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import (
    Environment,
    FileSystemLoader,
    StrictUndefined,
    TemplateError,
    TemplateNotFound,
)

from .assets import load_json


class PromptTemplateError(RuntimeError):
    """Raised when a prompt template is absent or cannot be rendered safely."""


@lru_cache(maxsize=1)
def _environment() -> Environment:
    prompt_root = Path(__file__).resolve().parent / "assets" / "prompts"
    environment = Environment(
        loader=FileSystemLoader(prompt_root),
        undefined=StrictUndefined,
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    environment.filters["json"] = lambda value, indent=None: json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=indent,
    )
    return environment


def render_prompt(template_name: str, **values: Any) -> str:
    """Render a packaged prompt and reject missing inputs instead of hiding them."""
    try:
        template = _environment().get_template(template_name)
        rendered = template.render(**values).strip()
    except (TemplateNotFound, TemplateError, RuntimeError, TypeError) as exc:
        raise PromptTemplateError(f"Unable to render prompt template {template_name!r}") from exc
    if not rendered:
        raise PromptTemplateError(f"Prompt template {template_name!r} rendered an empty prompt")
    return rendered


def render_operation(
    operation: str,
    payload: dict[str, Any],
    *,
    output_schema: Mapping[str, Any],
) -> tuple[str, str]:
    """Render the stable system prefix and the dynamic evidence message separately.

    `output_schema` must be the exact schema object sent with the request.
    The prompt states it verbatim, so gateways or models that ignore the
    API-level `json_schema` format still receive the output contract, and
    the prompt can never describe a different shape from the one enforced.
    """
    manifest = load_json("prompts/manifest.json")
    try:
        specification = manifest["operations"][operation]
        system_template = str(specification["system"])
        user_template = str(specification["user"])
    except (KeyError, TypeError) as exc:
        raise PromptTemplateError(f"Unknown prompt operation {operation!r}") from exc
    system = "\n\n".join(
        (
            render_prompt(system_template),
            render_prompt("_partials/output_contract.md", output_schema=dict(output_schema)),
        )
    )
    user = render_prompt(user_template, payload=payload)
    return system, user
