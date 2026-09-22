from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(slots=True)
class PolicyConfig:
    block_severities: set[str] = field(default_factory=lambda: {"critical", "high"})
    warn_severities: set[str] = field(default_factory=lambda: {"medium"})
    minimum_confidence: float = 0.70


@dataclass(slots=True)
class ProjectConfig:
    version: int = 1
    exclude: list[str] = field(default_factory=lambda: ["node_modules/**", "vendor/**", ".git/**"])
    max_file_bytes: int = 1_000_000
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    security_context: str = ""
    business_context: str = ""
    source_ref: str = "built-in-defaults"


def load_local_project_config(root: Path) -> ProjectConfig:
    """Load configuration from an already acquired immutable source snapshot."""

    config_root = (root / ".plaidnox").resolve()
    if root.resolve() not in config_root.parents:
        raise ValueError("project configuration path escapes the source snapshot")
    config_text = _read_optional(config_root / "config.yaml")
    context = _read_optional(config_root / "security.md") or ""
    business_context = _read_optional(config_root / "business-context.md") or ""
    if config_text is None:
        return ProjectConfig(
            security_context=context,
            business_context=business_context,
            source_ref="local-snapshot-defaults",
        )
    raw = yaml.safe_load(config_text) or {}
    policy_raw = raw.get("policy", {})
    return ProjectConfig(
        version=int(raw.get("version", 1)),
        exclude=[str(item) for item in raw.get("exclude", ProjectConfig().exclude)],
        max_file_bytes=int(raw.get("max_file_bytes", 1_000_000)),
        policy=PolicyConfig(
            block_severities=set(policy_raw.get("block_severities", ["critical", "high"])),
            warn_severities=set(policy_raw.get("warn_severities", ["medium"])),
            minimum_confidence=float(policy_raw.get("minimum_confidence", 0.70)),
        ),
        security_context=context,
        business_context=business_context,
        source_ref="local-snapshot",
    )


def _read_optional(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
