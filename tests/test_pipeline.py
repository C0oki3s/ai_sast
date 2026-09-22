import pytest
from plaidnox_sast.models import PolicyDecision
from plaidnox_sast.pipeline import SastPipeline


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
    def review(self, root, candidate, finding, security_context):
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


class FakeFailingDiscoveryAI(FakeContextualAI):
    discovery_error_types = ["AIResponseError"]

    def discover_candidates(self, root, context, plan=None):
        return [], 1


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


class FakeFailedVerdictAI(FakeContextualAI):
    def review(self, root, candidate, finding, security_context):
        raise RuntimeError("model unavailable")


class FakeFailedConsolidationAI(FakeContextualAI):
    def consolidate_findings(self, findings):
        raise RuntimeError("invalid consolidation response")


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


def test_pipeline_warns_when_contextual_ai_discovery_is_incomplete(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeFailingDiscoveryAI(),
    )
    assert result.policy.decision is PolicyDecision.WARN
    assert result.metrics["ai_discovery_failures"] == 1
    assert result.metrics["ai_discovery_error_types"] == ["AIResponseError"]


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


def test_pipeline_never_reports_a_candidate_without_an_ai_verdict(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeFailedVerdictAI(),
    )

    assert result.findings == []
    assert result.policy.decision is PolicyDecision.WARN
    assert result.metrics["ai_review_failures"] == 1


def test_pipeline_preserves_findings_and_records_failed_ai_consolidation(sample_repo):
    result = SastPipeline().scan_snapshot(
        sample_repo,
        "plaidnox/test-fixture",
        deep_hunt_agent=FakeFailedConsolidationAI(),
    )

    assert result.findings
    assert result.metrics["ai_consolidation_failures"] == 1
    assert result.metrics["ai_pre_consolidation_findings"] == len(result.findings)
