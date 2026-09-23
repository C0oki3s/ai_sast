from datetime import UTC, datetime, timedelta

import pytest

from plaidnox_sast.asset_bundle import (
    AssetBundleError,
    create_asset_bundle,
    verify_asset_bundle,
    verify_configured_asset_bundle,
    write_asset_bundle,
)

KEY = "unit-test-signing-key-that-is-long-enough"
NOW = datetime(2026, 9, 23, tzinfo=UTC)


def test_signed_asset_bundle_round_trips_current_runtime_assets() -> None:
    bundle = create_asset_bundle("policy-2026.09.23", "test-key", KEY, validity_days=7, now=NOW)

    verified = verify_asset_bundle(bundle, KEY, now=NOW + timedelta(days=1))

    assert verified.bundle_version == "policy-2026.09.23"
    assert verified.asset_count > 20


def test_asset_bundle_rejects_tampered_manifest() -> None:
    bundle = create_asset_bundle("policy-1", "test-key", KEY, validity_days=7, now=NOW)
    bundle["assets"] = {**bundle["assets"], "policy/priority.json": "0" * 64}

    with pytest.raises(AssetBundleError, match="signature"):
        verify_asset_bundle(bundle, KEY, now=NOW)


def test_asset_bundle_rejects_expired_bundle() -> None:
    bundle = create_asset_bundle("policy-1", "test-key", KEY, validity_days=1, now=NOW)

    with pytest.raises(AssetBundleError, match="expired"):
        verify_asset_bundle(bundle, KEY, now=NOW + timedelta(days=2))


def test_asset_bundle_requires_a_secret_manager_sized_key() -> None:
    with pytest.raises(AssetBundleError, match="at least"):
        create_asset_bundle("policy-1", "test-key", "short", validity_days=1, now=NOW)


def test_required_asset_bundle_fails_closed_when_path_is_missing() -> None:
    with pytest.raises(AssetBundleError, match="required"):
        verify_configured_asset_bundle({"PLAIDNOX_REQUIRE_SIGNED_ASSETS": "true"}, now=NOW)


def test_configured_asset_bundle_is_verified_before_runtime_use(tmp_path) -> None:
    path = tmp_path / "bundle.json"
    write_asset_bundle(create_asset_bundle("policy-1", "test-key", KEY, validity_days=7, now=NOW), path)

    verified = verify_configured_asset_bundle(
        {
            "PLAIDNOX_REQUIRE_SIGNED_ASSETS": "true",
            "PLAIDNOX_ASSET_BUNDLE_PATH": str(path),
            "PLAIDNOX_ASSET_BUNDLE_SIGNING_KEY": KEY,
        },
        now=NOW,
    )

    assert verified is not None
    assert verified.bundle_version == "policy-1"
