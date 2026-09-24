import sqlite3

from plaidnox_sast.assets import load_json
from plaidnox_sast.context_fabric import ContextFabricStore
from plaidnox_sast.prompts import render_operation, render_prompt


def test_model_prompts_and_schemas_are_versioned_runtime_assets():
    system, user = render_operation(
        "security_review",
        {"candidate": "example"},
        output_schema=load_json("schemas/deep_hunt_review.json"),
    )
    assert "attacker-first" in system
    assert "adversarial verification gates" in system.lower()
    assert '"candidate": "example"' in user
    assert load_json("schemas/deep_hunt_review.json")["required"][0] == "supported"
    models = load_json("runtime/models.json")
    assert len(models["agent_models"]) > 3
    assert all(item["cost"] != "high" for item in models["agent_models"])
    configured_model_names = {item["name"] for item in models["agent_models"]}
    assert "claude-opus-5" not in configured_model_names
    assert {"gpt-5.4-mini", "gpt-5.4"}.issubset(configured_model_names)
    assert models["agent_default_model"] == "gpt-5.4-mini"
    assert all(
        name.startswith(("claude-haiku-", "claude-sonnet-", "deepseek-", "glm-", "gpt-", "kimi-", "llama-", "qwen"))
        for name in configured_model_names
    )
    assert load_json("schemas/hunt_plan.json")["properties"]["tasks"]["minItems"] == 1
    assert "maxItems" not in load_json("schemas/vulnerability_discovery.json")["properties"]["candidates"]
    assert "Every production area" in render_prompt("operations/hunt_plan/system.md")
    assert load_json("schemas/finding_consolidation.json")["type"] == "object"
    assert load_json("schemas/finding_group_narratives.json")["type"] == "object"
    assert load_json("schemas/finding_group.json")["type"] == "object"
    assert "same exploitable root cause" in render_prompt("operations/finding_consolidation/system.md")
    assert load_json("policy/priority.json")["maximum_score"] == 100
    assert load_json("runtime/litellm.json")["cache_managed_by"] == "litellm_gateway"
    assert load_json("runtime/code_intelligence.json")["maximum_dynamic_queries_per_task"] > 0
    assert load_json("runtime/models.json")["agent_default_model"]
    assert load_json("runtime/production_controls.json")["model_budget"]["maximum_calls_per_scan"] > 0
    assert load_json("schemas/search_query_plan.json")["properties"]["queries"]["minItems"] == 1
    assert "literal ripgrep search terms" in render_prompt("operations/search_query_plan/system.md")
    assert "perplexity_sonar" in load_json("research/providers.json")["providers"]
    assert "gate_results" in load_json("schemas/deep_hunt_review.json")["required"]
    discovery_schema = load_json("schemas/vulnerability_discovery.json")
    assert "obligation_results" in discovery_schema["required"]
    statuses = discovery_schema["properties"]["obligation_results"]["items"]["properties"]["status"]["enum"]
    assert statuses == [
        "NO_ISSUE",
        "NOT_APPLICABLE",
        "CANDIDATE_FOUND",
        "NEEDS_CONTEXT",
        "UNRESOLVED",
    ]
    assert "security_invariants" in load_json("schemas/repository_context.json")["required"]
    assert "coverage_obligations" in (
        load_json("schemas/hunt_plan.json")["properties"]["tasks"]["items"]["required"]
    )
    assert load_json("prompts/manifest.json")["version"]


def test_perplexity_sonar_uses_the_direct_native_provider_boundary():
    provider = load_json("research/providers.json")["providers"]["perplexity_sonar"]

    assert provider["api_key_environment"] == "IFRIT_PERPLEXITY_API_KEY"
    assert provider["default_api_base"] == "https://api.perplexity.ai"
    assert "litellm_model_prefix" not in provider
    assert provider["provenance"] == "perplexity-sonar-direct"
    assert provider["default_model"] == "sonar"


def test_context_fabric_uses_the_separate_sql_migration(tmp_path):
    database = tmp_path / "context.sqlite"
    ContextFabricStore(database)
    with sqlite3.connect(database) as connection:
        names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {
        "context_bases",
        "security_memories",
        "finding_dependencies",
        "security_knowledge",
        "hunt_plans",
        "hunt_tasks",
        "hunt_plan_versions",
    }.issubset(names)
