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
    assert "analysis_depth" in load_json("routing/jev.json")["questions"]
    assert "knowledge_action" in load_json("routing/knowledge_retrieval.json")["questions"]
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
    assert load_json("runtime/jev.json")["request_timeout_seconds"] > 0
    assert load_json("runtime/production_controls.json")["model_budget"]["maximum_calls_per_scan"] > 0
    assert load_json("schemas/search_query_plan.json")["properties"]["queries"]["minItems"] == 1
    assert "Rust-compatible ripgrep" in render_prompt("operations/search_query_plan/system.md")
    assert "perplexity_sonar" in load_json("research/providers.json")["providers"]
    assert "gate_results" in load_json("schemas/deep_hunt_review.json")["required"]
    assert "coverage" in load_json("schemas/vulnerability_discovery.json")["required"]
    assert "security_invariants" in load_json("schemas/repository_context.json")["required"]
    assert "coverage_obligations" in (
        load_json("schemas/hunt_plan.json")["properties"]["tasks"]["items"]["required"]
    )
    assert load_json("prompts/manifest.json")["version"]


def test_perplexity_sonar_is_routed_through_litellm():
    provider = load_json("research/providers.json")["providers"]["perplexity_sonar"]

    assert provider["litellm_model_prefix"] == "perplexity/perplexity/"
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
