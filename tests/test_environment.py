from pathlib import Path

import pytest

from plaidnox_sast.environment import EnvironmentConfigurationError, load_mounted_secrets


def test_mounted_secret_is_loaded_from_external_policy(tmp_path: Path) -> None:
    secret = tmp_path / "database-url"
    secret.write_text("postgresql+psycopg://scanner:secret@db/code_scanning\n", encoding="utf-8")
    environment = {"PLAIDNOX_DATABASE_URL_FILE": str(secret)}

    load_mounted_secrets(environment)

    assert environment["PLAIDNOX_DATABASE_URL"].endswith("@db/code_scanning")


def test_existing_value_takes_precedence_over_mounted_secret(tmp_path: Path) -> None:
    secret = tmp_path / "gateway-key"
    secret.write_text("mounted", encoding="utf-8")
    environment = {
        "LITELLM_API_KEY": "existing",
        "LITELLM_API_KEY_FILE": str(secret),
    }

    load_mounted_secrets(environment)

    assert environment["LITELLM_API_KEY"] == "existing"


def test_missing_mounted_secret_fails_without_leaking_path_or_value(tmp_path: Path) -> None:
    environment = {"LITELLM_API_KEY_FILE": str(tmp_path / "missing-secret")}

    with pytest.raises(EnvironmentConfigurationError, match="LITELLM_API_KEY is unavailable") as error:
        load_mounted_secrets(environment)

    assert str(tmp_path) not in str(error.value)
