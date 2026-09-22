"""Strict Jinja rendering for SCM-owned prompt operations."""

from __future__ import annotations

import json
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


class SCMPromptError(RuntimeError):
    """Raised when an SCM prompt cannot be loaded or rendered."""


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
        value, ensure_ascii=False, sort_keys=True, indent=indent
    )
    return environment


def render_operation(operation: str, payload: dict[str, Any]) -> tuple[str, str]:
    manifest = load_json("prompts/manifest.json")
    try:
        specification = manifest["operations"][operation]
        system_name = str(specification["system"])
        user_name = str(specification["user"])
        system = _environment().get_template(system_name).render().strip()
        user = _environment().get_template(user_name).render(payload=payload).strip()
    except (KeyError, TemplateNotFound, TemplateError, TypeError) as exc:
        raise SCMPromptError(f"Unable to render SCM prompt operation {operation!r}") from exc
    if not system or not user:
        raise SCMPromptError(f"SCM prompt operation {operation!r} rendered empty content")
    return system, user
