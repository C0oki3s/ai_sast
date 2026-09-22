"""Versioned runtime assets owned by the SCM review package."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

ASSET_ROOT = Path(__file__).resolve().parent / "assets"


class SCMAssetError(RuntimeError):
    """Raised when an SCM runtime asset is absent or malformed."""


@cache
def load_text(relative_path: str) -> str:
    path = _asset_path(relative_path)
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SCMAssetError(f"Unable to read SCM runtime asset: {relative_path}") from exc


@cache
def load_json(relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(load_text(relative_path))
    except json.JSONDecodeError as exc:
        raise SCMAssetError(f"SCM runtime asset is not valid JSON: {relative_path}") from exc
    if not isinstance(value, dict):
        raise SCMAssetError(f"SCM runtime asset must be a JSON object: {relative_path}")
    return value


def _asset_path(relative_path: str) -> Path:
    path = (ASSET_ROOT / relative_path).resolve()
    if ASSET_ROOT not in path.parents:
        raise SCMAssetError("SCM runtime asset path escapes the asset directory")
    return path
