"""Signed, release-independent policy and runtime asset bundles."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from collections.abc import Mapping

from .assets import ASSET_ROOT, AssetConfigurationError, load_json


class AssetBundleError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedAssetBundle:
    bundle_version: str
    key_id: str
    asset_count: int
    expires_at: datetime


def create_asset_bundle(
    bundle_version: str,
    key_id: str,
    signing_key: str,
    *,
    validity_days: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    policy = load_json("runtime/production_controls.json")["asset_bundle"]
    _validate_key(signing_key, int(policy["minimum_key_bytes"]))
    maximum_days = int(policy["maximum_validity_days"])
    if validity_days < 1 or validity_days > maximum_days:
        raise AssetBundleError(f"bundle validity must be between 1 and {maximum_days} days")
    issued_at = _utc(now)
    payload: dict[str, Any] = {
        "schema_version": int(load_json("runtime/asset_bundle.json")["schema_version"]),
        "bundle_version": _required(bundle_version, "bundle_version"),
        "key_id": _required(key_id, "key_id"),
        "algorithm": str(policy["signature_algorithm"]),
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(days=validity_days)).isoformat(),
        "assets": _asset_hashes(),
    }
    payload["signature"] = _signature(payload, signing_key)
    return payload


def verify_asset_bundle(
    bundle: dict[str, Any],
    signing_key: str,
    *,
    now: datetime | None = None,
) -> VerifiedAssetBundle:
    policy = load_json("runtime/production_controls.json")["asset_bundle"]
    _validate_key(signing_key, int(policy["minimum_key_bytes"]))
    expected_algorithm = str(policy["signature_algorithm"])
    if bundle.get("algorithm") != expected_algorithm:
        raise AssetBundleError("unsupported asset bundle signature algorithm")
    supplied_signature = str(bundle.get("signature", ""))
    unsigned = {key: value for key, value in bundle.items() if key != "signature"}
    if not supplied_signature or not hmac.compare_digest(supplied_signature, _signature(unsigned, signing_key)):
        raise AssetBundleError("asset bundle signature is invalid")
    expires_at = _parse_time(bundle.get("expires_at"), "expires_at")
    issued_at = _parse_time(bundle.get("issued_at"), "issued_at")
    current = _utc(now)
    if issued_at > current + timedelta(minutes=5):
        raise AssetBundleError("asset bundle issue time is in the future")
    if expires_at <= current:
        raise AssetBundleError("asset bundle has expired")
    actual = _asset_hashes()
    expected = bundle.get("assets")
    if not isinstance(expected, dict) or expected != actual:
        raise AssetBundleError("installed runtime assets do not match the signed bundle")
    return VerifiedAssetBundle(
        bundle_version=_required(str(bundle.get("bundle_version", "")), "bundle_version"),
        key_id=_required(str(bundle.get("key_id", "")), "key_id"),
        asset_count=len(actual),
        expires_at=expires_at,
    )


def load_asset_bundle(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssetBundleError(f"unable to load asset bundle: {path}") from exc
    if not isinstance(value, dict):
        raise AssetBundleError("asset bundle must be a JSON object")
    return value


def write_asset_bundle(bundle: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_configured_asset_bundle(
    environment: Mapping[str, str] | None = None,
    *,
    now: datetime | None = None,
) -> VerifiedAssetBundle | None:
    values = environment if environment is not None else os.environ
    policy = load_json("runtime/production_controls.json")["asset_bundle"]
    required = values.get(str(policy["required_environment_variable"]), "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    configured_path = values.get(str(policy["path_environment_variable"]), "").strip()
    if not configured_path:
        if required:
            raise AssetBundleError("a signed runtime asset bundle is required")
        return None
    key = values.get(str(policy["key_environment_variable"]), "")
    return verify_asset_bundle(load_asset_bundle(Path(configured_path)), key, now=now)


def _asset_hashes() -> dict[str, str]:
    manifest = load_json("runtime/asset_bundle.json")
    extensions = {str(value) for value in manifest["included_extensions"]}
    hashes: dict[str, str] = {}
    for directory in manifest["included_directories"]:
        root = (ASSET_ROOT / str(directory)).resolve()
        if ASSET_ROOT not in root.parents or not root.is_dir():
            raise AssetConfigurationError(f"Asset bundle directory is invalid: {directory}")
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in extensions:
                continue
            relative = path.relative_to(ASSET_ROOT).as_posix()
            hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def _signature(payload: dict[str, Any], key: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def _validate_key(key: str, minimum_bytes: int) -> None:
    if len(key.encode("utf-8")) < minimum_bytes:
        raise AssetBundleError(f"asset bundle signing key must contain at least {minimum_bytes} bytes")


def _parse_time(value: Any, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise AssetBundleError(f"asset bundle {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise AssetBundleError(f"asset bundle {field} must include a timezone")
    return parsed.astimezone(UTC)


def _utc(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise AssetBundleError("bundle time must include a timezone")
    return current.astimezone(UTC)


def _required(value: str, field: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise AssetBundleError(f"{field} is required")
    return cleaned
