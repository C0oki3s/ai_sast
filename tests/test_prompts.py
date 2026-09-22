from __future__ import annotations

from pathlib import Path

import pytest

import plaidnox_sast.prompts as prompt_module
from plaidnox_sast.assets import load_json
from plaidnox_sast.prompts import PromptTemplateError, render_operation, render_prompt

OPERATIONS = (
    "recon_search_plan",
    "repository_context",
    "hunt_plan",
    "search_query_plan",
    "vulnerability_discovery",
    "security_review",
    "metadata_exposure_review",
    "variant_sweep",
    "capability_chain",
    "finding_consolidation",
    "finding_group_narratives",
    "knowledge_research",
    "patch_proposal",
)


def test_every_agent_operation_has_a_renderable_jinja_prompt_pair():
    for operation in OPERATIONS:
        system, user = render_operation(operation, {"operation": operation})
        assert "PlaidNox Deep Hunt operating contract" in system
        assert f'"operation": "{operation}"' in user


def test_prompt_manifest_declares_every_supported_operation():
    manifest = load_json("prompts/manifest.json")

    assert manifest["version"]
    assert set(manifest["operations"]) == set(OPERATIONS)


def test_prompt_corpus_uses_markdown_templates_only():
    prompt_root = Path(prompt_module.__file__).resolve().parent / "assets" / "prompts"
    manifest = load_json("prompts/manifest.json")

    assert not [
        path
        for path in prompt_root.rglob("*")
        if path.is_file() and path.suffix not in {".md", ".json"}
    ]
    assert all(
        str(path).endswith(".md")
        for operation in manifest["operations"].values()
        for path in operation.values()
    )


def test_dynamic_evidence_is_separate_from_stable_system_prompt():
    first_system, first_user = render_operation("security_review", {"path": "first.py"})
    second_system, second_user = render_operation("security_review", {"path": "second.py"})

    assert first_system == second_system
    assert first_user != second_user
    assert "first.py" not in first_system


def test_jinja_uses_strict_undefined_values():
    with pytest.raises(PromptTemplateError):
        render_prompt("_partials/user_payload.md")


def test_unknown_prompt_operation_fails_closed():
    with pytest.raises(PromptTemplateError, match="Unknown prompt operation"):
        render_operation("unregistered_operation", {})
