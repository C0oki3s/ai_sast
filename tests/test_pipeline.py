from types import SimpleNamespace
from typing import ClassVar

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from plaidnox_sast.models import PolicyDecision
from plaidnox_sast.persistence.models import Base
from plaidnox_sast.persistence.repositories import unit_of_work
from plaidnox_sast.pipeline import SastPipeline, _stable_id


def test_pipeline_requires_the_deep_hunt_agent(sample_repo):
    from plaidnox_sast.ai import AIConfigurationError

    with pytest.raises(AIConfigurationError, match="required"):
        SastPipeline().scan_snapshot(sample_repo, "plaidnox/test-fixture")


def test_pipeline_scans_a_non_git_source_snapshot(tmp_path):
    (tmp_path / "app.js").write_text(
        "const app = express();\napp.get('/accounts/:id', handler);\n",
        encoding="utf-8",
    )

    result = SastPipeline().scan_snapshot(
        tmp_path,
        "local/account-service",
        deep_hunt_agent=FakeContextualAI(),
    )

    assert result.revision.startswith("snapshot-")
    assert result.metrics["target_code_executed"] is False
    assert result.findings


def test_pipeline_deep_hunt_vertical_slice(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeContextualAI(),
    )
    assert result.policy.decision is PolicyDecision.BLOCK
    assert result.metrics["target_code_executed"] is False
    assert result.metrics["ai_discovery_candidates"] == 1
    assert all(finding.state.value == "validated" for finding in result.findings)


class FakeAIValidator:
    def review(self, root, candidate, finding, security_context, model_tier=None, route=None):
        from plaidnox_sast.ai import AIReview

        return AIReview(True, 0.9, "supported", "source -> sink", "escape output")

    def build_repository_context(self, root, repository, commit, graph, business_context=""):
        return FakeRepositoryContext()

    def plan_tasks(self, context, security_context=""):
        return FakePlan()

    def discover_candidates(self, root, context, plan=None):
        return [], 0

    def sweep_variants(self, root, context, plan, verified):
        return [], 0

    def consolidate_findings(self, findings):
        return findings


class FakePlan:
    def to_dict(self):
        return {
            "plan_id": "plan-test",
            "strategy": "Review all reachable fixture paths.",
            "tasks": [{"task_id": "fixture-review", "title": "Fixture review"}],
        }


class FakeRepositoryContext:
    def to_dict(self):
        return {
            "schema_version": 1,
            "repository": "plaidnox/test-fixture",
            "commit": "fixture",
            "architecture": "Fixture application.",
            "applications": [],
            "source_inventory": [],
            "graph_symbols": 0,
            "graph_routes": 0,
        }


class FakeContextualAI(FakeAIValidator):
    def build_repository_context(self, root, repository, commit, graph, business_context=""):
        return FakeRepositoryContext()

    def discover_candidates(self, root, context, plan=None):
        from plaidnox_sast.models import Candidate, Evidence, Severity

        return [
            Candidate(
                rule_id="plaidnox.ai.authorization",
                title="Missing object ownership check",
                vulnerability_class="CWE-639",
                severity=Severity.HIGH,
                confidence=0.84,
                message="A request parameter selects an object without an ownership constraint.",
                evidence=Evidence("app.js", 1, 1, "const app = express();", "GET /", "authorization", ["request", "object"]),
                metadata={
                    "category": "authorization",
                    "engine": "plaidnox-litellm-discovery",
                    "ai_discovery": True,
                    "ai_remediation": "Check ownership before returning the object.",
                },
            )
        ], 0


class FakeManyHighSeverityCandidatesAI(FakeContextualAI):
    def discover_candidates(self, root, context, plan=None):
        from plaidnox_sast.models import Candidate, Evidence, Severity

        candidates = []
        for index, confidence in enumerate((0.95, 0.85, 0.75)):
            candidates.append(
                Candidate(
                    rule_id=f"plaidnox.ai.authorization.{index}",
                    title=f"Missing object ownership check {index}",
                    vulnerability_class="CWE-639",
                    severity=Severity.HIGH,
                    confidence=confidence,
                    message="A request parameter selects an object without an ownership constraint.",
                    evidence=Evidence(
                        f"app{index}.js", 1, 1, "const app = express();", "GET /", f"authorization{index}", ["request", "object"]
                    ),
                    metadata={
                        "category": "authorization",
                        "engine": "plaidnox-litellm-discovery",
                        "ai_discovery": True,
                        "ai_remediation": "Check ownership before returning the object.",
                    },
                )
            )
        return candidates, 0


class FakeFailingDiscoveryAI(FakeContextualAI):
    discovery_error_types: ClassVar[list[str]] = ["AIResponseError"]
    discovery_unexpected_failures = 0

    def discover_candidates(self, root, context, plan=None):
        return [], 1


class FakeUnexpectedFailingDiscoveryAI(FakeContextualAI):
    discovery_error_types: ClassVar[list[str]] = ["ValueError"]
    discovery_unexpected_failures = 1

    def discover_candidates(self, root, context, plan=None):
        return [], 1


class FakeInvalidSearchQueryAI(FakeAIValidator):
    search_query_errors: list[dict] = []

    def discover_candidates(self, root, context, plan=None):
        self.search_query_errors = [
            {
                "phase": "candidate_discovery",
                "query_id": "invalid-query",
                "pattern_hash": "a" * 64,
                "exit_code": 2,
                "diagnostic": "regex parse error",
            }
        ]
        return [], 0


def test_pipeline_marks_invalid_ai_search_query_as_incomplete_without_crashing(sample_repo) -> None:
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeInvalidSearchQueryAI(),
    )

    assert result.policy.decision is PolicyDecision.INCOMPLETE
    assert result.metrics["ai_search_query_failures"] == 1
    assert result.metrics["ai_search_query_errors"][0]["query_id"] == "invalid-query"


class FakeCrashingContextAI(FakeAIValidator):
    def build_repository_context(self, root, repository, commit, graph, business_context=""):
        raise ValueError("unexpected context crash")


class FakeVariantAI(FakeContextualAI):
    def sweep_variants(self, root, context, plan, verified):
        discovered = [(candidate, finding) for candidate, finding in verified if candidate.metadata.get("ai_discovery")]
        if not discovered:
            return [], 0
        _candidate, finding = discovered[0]
        from plaidnox_sast.models import Candidate, Evidence, Severity

        return [
            Candidate(
                rule_id="plaidnox.ai.variant.account-list",
                title="Sibling account listing misses ownership scope",
                vulnerability_class="CWE-639",
                severity=Severity.HIGH,
                confidence=0.77,
                message="A sibling route exposes account data without an ownership condition.",
                evidence=Evidence("app.js", 2, 2, "const express = require('express');"),
                metadata={"category": "authorization", "variant_of": finding.fingerprint},
            )
        ], 0


class FakeCapabilityChainAI(FakeContextualAI):
    def review(self, root, candidate, finding, security_context, model_tier=None, route=None):
        from plaidnox_sast.ai import AIReview

        gained_capability = "SERVER_SIDE_REQUEST" if not candidate.metadata.get("capability_pivot_of") else ""
        return AIReview(True, 0.9, "supported", "source -> sink", "escape output", gained_capability=gained_capability)

    def chain_capability_pivots(self, root, context, plan, verified):
        capable = [
            (candidate, finding)
            for candidate, finding in verified
            if finding.metadata.get("deep_hunt", {}).get("gained_capability")
        ]
        if not capable:
            return [], 0
        _candidate, finding = capable[0]
        from plaidnox_sast.models import Candidate, Evidence, Severity

        return [
            Candidate(
                rule_id="plaidnox.ai.pivot.identity-token-reuse",
                title="Gained server-side request reach mints a trusted identity token",
                vulnerability_class="CWE-441",
                severity=Severity.HIGH,
                confidence=0.8,
                message="The capability gained from the verified root reaches a token-minting boundary.",
                evidence=Evidence("app.js", 3, 3, "app.post(\"/signin\", async (req, res) => {"),
                metadata={"category": "identity", "capability_pivot_of": [finding.fingerprint]},
            )
        ], 0


class FakeFailedVerdictAI(FakeContextualAI):
    def review(self, root, candidate, finding, security_context, model_tier=None, route=None):
        raise RuntimeError("model unavailable")


class FakeRecognizedFailedVerdictAI(FakeContextualAI):
    def review(self, root, candidate, finding, security_context, model_tier=None, route=None):
        from plaidnox_sast.ai import AIResponseError

        raise AIResponseError("model returned a malformed verdict")


class FakePatchingAI(FakeContextualAI):
    def propose_patch(self, root, finding, model_tier=None):
        from plaidnox_sast.ai import PatchProposal

        return PatchProposal(
            proposed=True,
            patch="--- a/app.js\n+++ b/app.js\n@@ -1,1 +1,1 @@\n-old\n+new\n",
            summary="Fix the finding.",
            files_changed=["app.js"],
            risk_notes="",
            confidence=0.9,
        )

    def verify_patch(self, root, finding, proposal, security_context="", model_tier=None):
        from plaidnox_sast.ai import PatchVerification

        return PatchVerification(applied=True, verified=True, rescan_supported=False, rescan_confidence=0.1)


class FakeCrashingPatchAI(FakeContextualAI):
    def propose_patch(self, root, finding, model_tier=None):
        raise ValueError("patch proposal crashed")

    def verify_patch(self, root, finding, proposal, security_context="", model_tier=None):
        raise AssertionError("verify_patch must not run when propose_patch fails")


class FakeFailedConsolidationAI(FakeContextualAI):
    def consolidate_findings(self, findings):
        raise RuntimeError("invalid consolidation response")


class FakeRecognizedFailedConsolidationAI(FakeContextualAI):
    def consolidate_findings(self, findings):
        from plaidnox_sast.ai import AIResponseError

        raise AIResponseError("consolidation response did not match the schema")


def test_pipeline_uses_ai_only_for_eligible_deep_candidates(sample_repo):
    (sample_repo / "app.js").write_text(
        """const html_to_pdf = require("html-pdf-node");
const express = require("express");
const app = express();
app.post("/reports", async (req, res) => {
  const reportData = `${req.body.name}`;
  return html_to_pdf.generatePdf({ content: reportData });
});
"""
    )
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeContextualAI(),
    )
    reviewed = [finding for finding in result.findings if "deep_hunt" in finding.metadata]
    assert len(reviewed) == 1
    assert all(finding.validator == "plaidnox-deep-hunt" for finding in reviewed)
    assert result.metrics["ai_reviews"] == 1
    assert result.metrics["ai_review_failures"] == 0


def test_pipeline_demotes_the_lowest_priority_excess_deep_routes_to_respect_the_scan_budget(sample_repo, monkeypatch):
    import plaidnox_sast.pipeline as pipeline_module
    from plaidnox_sast.assets import load_json as real_load_json

    def patched_load_json(name):
        data = real_load_json(name)
        if name == "runtime/agent.json":
            data = dict(data)
            data["deep_hunt_budget_max"] = 1
        return data

    monkeypatch.setattr(pipeline_module, "load_json", patched_load_json)

    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeManyHighSeverityCandidatesAI(),
    )

    tiers_by_title = {finding.title: finding.metadata["jev_model_tier"] for finding in result.findings}
    assert tiers_by_title["Missing object ownership check 0"] == "deep"
    assert tiers_by_title["Missing object ownership check 1"] == "standard"
    assert tiers_by_title["Missing object ownership check 2"] == "standard"
    assert result.metrics["jev_deep_budget_demotions"] == 2
    # Demotion never blocks disposition: every candidate still gets a Deep Hunt verdict.
    assert len(result.findings) == 3


def test_pipeline_does_not_demote_deep_routes_within_the_configured_budget(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeManyHighSeverityCandidatesAI(),
    )

    assert result.metrics["jev_deep_budget_demotions"] == 0
    assert all(finding.metadata["jev_model_tier"] == "deep" for finding in result.findings)


def test_pipeline_keeps_ai_repository_context_and_discovered_candidates(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeContextualAI(),
    )
    discovered = [finding for finding in result.findings if finding.metadata.get("ai_discovery")]
    assert result.repository_context["architecture"] == "Fixture application."
    assert result.metrics["ai_discovery_candidates"] == 1
    assert len(discovered) == 1
    assert discovered[0].validator == "plaidnox-deep-hunt"


def test_pipeline_marks_the_scan_incomplete_when_contextual_ai_discovery_fails(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeFailingDiscoveryAI(),
    )
    assert result.policy.decision is PolicyDecision.INCOMPLETE
    assert result.metrics["ai_discovery_failures"] == 1
    assert result.metrics["ai_discovery_error_types"] == ["AIResponseError"]
    assert result.metrics["ai_discovery_unexpected_failures"] == 0
    assert result.metrics["ai_scan_incomplete"] is True


def test_pipeline_flags_unrecognized_discovery_failures_as_unexpected(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeUnexpectedFailingDiscoveryAI(),
    )
    assert result.metrics["ai_discovery_error_types"] == ["ValueError"]
    assert result.metrics["ai_discovery_unexpected_failures"] == 1


def test_pipeline_flags_unrecognized_context_failures_as_unexpected(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeCrashingContextAI(),
    )
    assert result.policy.decision is PolicyDecision.INCOMPLETE
    assert result.metrics["ai_context_error_type"] == "ValueError"
    assert result.metrics["ai_context_unexpected_failures"] == 1


def test_pipeline_deep_hunts_root_cause_variants_before_reporting(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeVariantAI(),
    )

    variants = [finding for finding in result.findings if finding.metadata.get("variant_of")]
    assert len(variants) == 1
    assert variants[0].validator == "plaidnox-deep-hunt"
    assert result.metrics["ai_variant_candidates"] == 1
    assert result.metrics["ai_variant_rounds"] == 2
    assert result.metrics["ai_variant_unexpected_failures"] == 0


def test_pipeline_chains_a_gained_capability_into_a_new_independently_verified_finding(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeCapabilityChainAI(),
    )

    pivots = [finding for finding in result.findings if finding.metadata.get("capability_pivot_of")]
    assert len(pivots) == 1
    assert pivots[0].validator == "plaidnox-deep-hunt"
    assert pivots[0].rule_id == "plaidnox.ai.pivot.identity-token-reuse"
    assert result.metrics["ai_capability_chain_candidates"] == 1
    assert result.metrics["ai_capability_chain_failures"] == 0
    # Round 1 chains the gained capability into the pivot; round 2 reviews the pivot itself
    # (no further gained_capability), finds nothing to chain, and the loop ends.
    assert result.metrics["ai_capability_chain_rounds"] == 2


def test_pipeline_never_reports_a_candidate_without_an_ai_verdict(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeFailedVerdictAI(),
    )

    assert result.findings == []
    assert result.policy.decision is PolicyDecision.INCOMPLETE
    assert result.metrics["ai_review_failures"] == 1
    assert result.metrics["ai_review_error_types"] == ["RuntimeError"]
    assert result.metrics["ai_review_errors"] == ["model unavailable"]
    assert result.metrics["ai_review_unexpected_failures"] == 1


def test_pipeline_does_not_flag_a_recognized_ai_stage_error_as_unexpected(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeRecognizedFailedVerdictAI(),
    )

    assert result.metrics["ai_review_error_types"] == ["AIResponseError"]
    assert result.metrics["ai_review_unexpected_failures"] == 0


def test_pipeline_preserves_findings_and_records_failed_ai_consolidation(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeFailedConsolidationAI(),
    )

    assert result.findings
    assert result.metrics["ai_consolidation_failures"] == 1
    assert result.metrics["ai_pre_consolidation_findings"] == len(result.findings)
    assert result.metrics["ai_consolidation_unexpected_failure"] is True


def test_pipeline_does_not_flag_a_recognized_consolidation_error_as_unexpected(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeRecognizedFailedConsolidationAI(),
    )

    assert result.metrics["ai_consolidation_error_type"] == "AIResponseError"
    assert result.metrics["ai_consolidation_unexpected_failure"] is False


def test_pipeline_does_not_propose_patches_unless_enabled(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakePatchingAI(),
    )

    assert result.metrics["ai_patch_proposals"] == 0
    assert all("patch_proposal" not in finding.metadata for finding in result.findings)


def test_pipeline_proposes_and_verifies_patches_when_enabled(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakePatchingAI(),
        propose_patches=True,
    )

    assert result.findings
    assert result.metrics["ai_patch_proposals"] == len(result.findings)
    assert result.metrics["ai_patch_verified"] == len(result.findings)
    assert result.metrics["ai_patch_unverified"] == 0
    assert result.metrics["ai_patch_proposal_failures"] == 0
    for finding in result.findings:
        assert finding.metadata["patch_proposal"]["proposed"] is True
        assert finding.metadata["patch_verification"]["verified"] is True


def test_pipeline_flags_unrecognized_patch_proposal_failures_as_unexpected(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeCrashingPatchAI(),
        propose_patches=True,
    )

    assert result.metrics["ai_patch_proposal_failures"] == len(result.findings)
    assert result.metrics["ai_patch_unexpected_failures"] == len(result.findings)
    assert result.policy.decision is not PolicyDecision.INCOMPLETE


def _sqlite_session_factory():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_pipeline_persists_codebase_snapshot_security_ir_and_findings_when_session_factory_is_configured(sample_repo):
    factory = _sqlite_session_factory()

    result = SastPipeline(session_factory=factory, tenant_id="tenant-a").scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeContextualAI(),
    )

    assert result.findings
    assert result.metrics["persistence_enabled"] is True
    assert result.metrics["persistence_indexed"] is True
    assert result.metrics["persistence_error_type"] == ""
    assert result.metrics["persistence_findings_saved"] == len(result.findings)
    assert result.metrics["persistence_finding_error_type"] == ""

    codebase_id = _stable_id("codebase", "tenant-a", "plaidnox/test-fixture")
    snapshot_id = _stable_id("snapshot", "tenant-a", "plaidnox/test-fixture", result.revision)
    with unit_of_work(factory, "tenant-a") as repository:
        assert repository.get_codebase(codebase_id) is not None
        assert repository.get_snapshot(snapshot_id) is not None
        for finding in result.findings:
            finding_id = _stable_id("finding", codebase_id, finding.fingerprint)
            stored = repository.get_finding(finding_id)
            assert stored is not None
            assert stored.fingerprint == finding.fingerprint
            assert stored.title == finding.title
            assert stored.dependencies
            assert all(item.dependency_type == "symbol" for item in stored.dependencies)


def test_pipeline_does_not_touch_the_database_when_session_factory_is_not_configured(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeContextualAI(),
    )

    assert result.findings
    assert result.metrics["persistence_enabled"] is False
    assert result.metrics["persistence_indexed"] is False
    assert result.metrics["persistence_findings_saved"] == 0


class _ExplodingSessionFactory:
    def __call__(self):
        raise RuntimeError("database is unreachable")


def test_pipeline_tolerates_a_persistence_failure_without_failing_the_scan(sample_repo):
    result = SastPipeline(session_factory=_ExplodingSessionFactory()).scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeContextualAI(),
    )

    assert result.findings
    assert result.metrics["persistence_enabled"] is True
    assert result.metrics["persistence_indexed"] is False
    assert result.metrics["persistence_error_type"] == "RuntimeError"
    assert result.metrics["persistence_findings_saved"] == 0
    assert result.metrics["ai_scan_incomplete"] is False


def test_pipeline_flags_a_finding_for_revalidation_once_its_dependency_changes_on_rescan(sample_repo):
    """End-to-end mutation test for the Phase 2 exit condition: editing the code a
    finding depends on flags that finding for revalidation on the next scan, while
    a second, untouched finding elsewhere in the codebase is left alone."""

    (sample_repo / "util.js").write_text("function formatDate(value) { return value; }\n")
    factory = _sqlite_session_factory()
    pipeline = SastPipeline(session_factory=factory, tenant_id="tenant-a")

    first = pipeline.scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        revision="revision-1",
        deep_hunt_agent=FakeContextualAI(),
    )
    assert first.metrics["persistence_indexed"] is True
    assert first.metrics["persistence_findings_flagged_for_revalidation"] == 0

    codebase_id = _stable_id("codebase", "tenant-a", "plaidnox/test-fixture")
    with unit_of_work(factory, "tenant-a") as repository:
        stored_states = {
            finding.fingerprint: repository.get_finding(_stable_id("finding", codebase_id, finding.fingerprint)).state
            for finding in first.findings
        }
    assert stored_states and all(state == "validated" for state in stored_states.values())

    # Only app.js -- what the fixture's findings actually depend on -- changes;
    # util.js, an unrelated file, is left untouched.
    (sample_repo / "app.js").write_text(
        (sample_repo / "app.js").read_text() + "\n// a trailing comment mutates app.js's content hash\n"
    )

    second = pipeline.scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        revision="revision-2",
        deep_hunt_agent=FakeContextualAI(),
    )
    assert second.metrics["persistence_indexed"] is True
    assert second.metrics["persistence_findings_flagged_for_revalidation"] >= 1


def test_pipeline_records_model_usage_for_the_tenant_cost_quota(sample_repo):
    from plaidnox_sast.controls import ModelUsageBudget
    from plaidnox_sast.persistence.models import UsageEventRecord

    factory = _sqlite_session_factory()
    agent = FakeContextualAI()
    budget = ModelUsageBudget()
    reservation = budget.reserve("deep", 10, 10)
    budget.complete(
        reservation,
        SimpleNamespace(usage=SimpleNamespace(input_tokens=12, output_tokens=3), _hidden_params={"response_cost": 0.2}),
    )
    agent.model_budget = budget
    pipeline = SastPipeline(session_factory=factory, tenant_id="tenant-a")

    for _ in range(2):  # a rescan of the same revision really spends again
        pipeline.scan_snapshot(sample_repo, "plaidnox/test-fixture", deep_hunt_agent=agent)

    with factory() as session:
        events = session.scalars(select(UsageEventRecord)).all()
    assert [(event.model_alias, event.input_tokens, event.output_tokens) for event in events] == [
        ("deep", 12, 3),
        ("deep", 12, 3),
    ]
    assert all(event.tenant_id == "tenant-a" for event in events)
