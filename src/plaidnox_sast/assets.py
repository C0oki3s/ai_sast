"""Versioned runtime assets: prompts, schemas, routing policy, and migrations."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


ASSET_ROOT = Path(__file__).resolve().parent / "assets"


class AssetConfigurationError(RuntimeError):
    """Raised when a deployable runtime asset is missing or malformed."""


@lru_cache(maxsize=None)
def load_text(relative_path: str) -> str:
    path = _asset_path(relative_path)
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise AssetConfigurationError(f"Unable to read runtime asset: {relative_path}") from exc


@lru_cache(maxsize=None)
def load_json(relative_path: str) -> dict[str, Any]:
    try:
        value = json.loads(load_text(relative_path))
    except json.JSONDecodeError as exc:
        raise AssetConfigurationError(f"Runtime asset is not valid JSON: {relative_path}") from exc
    if not isinstance(value, dict):
        raise AssetConfigurationError(f"Runtime asset must be a JSON object: {relative_path}")
    return value


def _asset_path(relative_path: str) -> Path:
    path = (ASSET_ROOT / relative_path).resolve()
    if ASSET_ROOT not in path.parents:
        raise AssetConfigurationError("Runtime asset path escapes the asset directory")
    return path
