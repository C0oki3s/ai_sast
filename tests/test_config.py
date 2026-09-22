from plaidnox_sast.config import load_local_project_config


def test_missing_local_configuration_uses_safe_defaults(tmp_path):
    config = load_local_project_config(tmp_path)

    assert config.policy.block_severities == {"critical", "high"}
    assert config.source_ref == "local-snapshot-defaults"


def test_local_snapshot_configuration_does_not_require_scm(tmp_path):
    config_directory = tmp_path / ".plaidnox"
    config_directory.mkdir()
    (config_directory / "config.yaml").write_text(
        "max_file_bytes: 2048\nexclude:\n  - generated/**\n",
        encoding="utf-8",
    )
    (config_directory / "business-context.md").write_text(
        "Customer account service.",
        encoding="utf-8",
    )

    config = load_local_project_config(tmp_path)

    assert config.max_file_bytes == 2048
    assert config.exclude == ["generated/**"]
    assert config.business_context == "Customer account service."
    assert config.source_ref == "local-snapshot"
