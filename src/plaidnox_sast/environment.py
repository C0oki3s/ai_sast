"""External environment and mounted-secret configuration."""

from __future__ import annotations

import os
from collections.abc import MutableMapping
from pathlib import Path

from .assets import load_json


class EnvironmentConfigurationError(RuntimeError):
    pass


def load_mounted_secrets(environment: MutableMapping[str, str] | None = None) -> None:
    """Materialize configured ``*_FILE`` values without exposing their content."""

    values = environment if environment is not None else os.environ
    policy = load_json("runtime/environment.json")
    maximum_bytes = int(policy["maximum_secret_file_bytes"])
    for source, target in policy["secret_file_variables"].items():
        configured = values.get(str(source), "").strip()
        if not configured or values.get(str(target), ""):
            continue
        path = Path(configured)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise EnvironmentConfigurationError(f"mounted secret for {target} is unavailable") from exc
        if not path.is_file() or size <= 0 or size > maximum_bytes:
            raise EnvironmentConfigurationError(f"mounted secret for {target} is not a bounded regular file")
        try:
            value = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise EnvironmentConfigurationError(f"mounted secret for {target} is unreadable") from exc
        if not value:
            raise EnvironmentConfigurationError(f"mounted secret for {target} is empty")
        values[str(target)] = value
