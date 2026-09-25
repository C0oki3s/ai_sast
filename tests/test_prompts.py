from __future__ import annotations

import json
from pathlib import Path

import pytest

import plaidnox_sast.prompts as prompt_module
from plaidnox_sast.assets import load_json
from plaidnox_sast.prompts import PromptTemplateError, render_operation, render_prompt

OPERATIONS = (
    "recon_search_plan",
    "repository_context",
    "hunt_plan",
    "graph_investigation_planning",
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

# Consolidation and narrative schemas are built at call time; every other
# operation sends the packaged schema of the same (or a shared) name.
SCHEMA_FILES = {
    "security_review": "deep_hunt_review",
    "metadata_exposure_review": "deep_hunt_review",
    "graph_investigation_planning": "graph_investigation_plan",
}
DYNAMIC_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["dynamic_marker"],
    "properties": {"dynamic_marker": {"type": "string"}},
}


def _schema(operation: str) -> dict:
    if operation in {"finding_consolidation", "finding_group_narratives"}:
        return DYNAMIC_SCHEMA
    return load_json(f"schemas/{SCHEMA_FILES.get(operation, operation)}.json")


def test_every_agent_operation_has_a_renderable_jinja_prompt_pair():
    for operation in OPERATIONS:
        system, user = render_operation(operation, {"operation": operation}, output_schema=_schema(operation))
        assert "PlaidNox Deep Hunt operating contract" in system
        assert f'"operation": "{operation}"' in user


@pytest.mark.parametrize("operation", OPERATIONS)
def test_every_operation_states_the_exact_output_schema_it_is_sent(operation):
    schema = _schema(operation)
    system, user = render_operation(operation, {"operation": operation}, output_schema=schema)

    assert "## Output contract" in system
    assert "exactly one JSON object" in system
    assert json.dumps(schema, ensure_ascii=False, sort_keys=True) in system
    assert "Output contract" not in user


def test_output_contract_is_required_for_every_render():
    with pytest.raises(TypeError):
        render_operation("security_review", {"path": "first.py"})  # type: ignore[call-arg]


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
        for name, path in operation.items()
        if name in {"system", "user"}
    )
    assert manifest["operations"]["vulnerability_discovery"]["contract_version"]


def test_dynamic_evidence_is_separate_from_stable_system_prompt():
    schema = _schema("security_review")
    first_system, first_user = render_operation("security_review", {"path": "first.py"}, output_schema=schema)
    second_system, second_user = render_operation("security_review", {"path": "second.py"}, output_schema=schema)

    assert first_system == second_system
    assert first_user != second_user
    assert "first.py" not in first_system


def test_jinja_uses_strict_undefined_values():
    with pytest.raises(PromptTemplateError):
        render_prompt("_partials/user_payload.md")


def test_unknown_prompt_operation_fails_closed():
    with pytest.raises(PromptTemplateError, match="Unknown prompt operation"):
        render_operation("unregistered_operation", {}, output_schema=DYNAMIC_SCHEMA)
