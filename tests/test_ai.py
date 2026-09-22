from __future__ import annotations

import json
import threading

import pytest

from plaidnox_sast.ai import (
    AIRepositoryContext,
    AIResponseError,
    HuntPlan,
    HuntTask,
    PlaidNoxDeepHuntAgent,
    _resolve_context_request,
    load_env_file,
)
from plaidnox_sast.graph import build_structural_graph
from plaidnox_sast.models import (
    Candidate,
    Evidence,
    Finding,
    FindingState,
    ModelTier,
    Severity,
)


def review_payload(**overrides):
    payload = {
            "supported": True,
            "confidence": 0.91,
            "title": "Server-side request through PDF renderer",
            "vulnerability_class": "CWE-918",
            "classification_references": [
                {
                    "namespace": "CWE",
                    "identifier": "CWE-918",
                    "name": "Server-Side Request Forgery",
                    "source_url": "https://cwe.mitre.org/data/definitions/918.html",
                }
            ],
            "severity": "high",
            "message": "Request input reaches a browser-backed renderer.",
            "business_impact": "An attacker can make the renderer access protected resources.",
            "reasoning": "Request input reaches the renderer through the report template.",
            "attack_path": "request body -> report template -> PDF renderer",
            "remediation_note": "Escape fields and disable remote resources.",
            "falsification_attempts": ["No URL allowlist was present in the supplied path."],
            "required_preconditions": ["Attacker can submit report content."],
            "evidence_gaps": [],
            "security_invariant": "Untrusted report content must not control renderer network access.",
            "rejection_reason": "",
            "gate_results": [
                {"gate": gate, "verdict": "pass", "evidence": ["app.js:2-4"], "explanation": "Supported by supplied evidence."}
                for gate in (
                    "design_invariant",
                    "reachability",
                    "attacker_control",
                    "effective_defense",
                    "new_capability",
                    "falsification",
                    "reproduction",
                    "remediation_invariant",
                )
            ],
            "evidence_locations": [
                {"path": "app.js", "start_line": 2, "end_line": 4, "role": "propagation"}
            ],
            "proof_plan": "Submit controlled content and observe the renderer request boundary.",
            "regression_test": "Assert remote resources are rejected for attacker-controlled report content.",
            "context_requests": [],
        }
    payload.update(overrides)
    return payload


class FakeResponse:
    status = "completed"

    def __init__(self, payload=None):
        self.output_text = json.dumps(payload or review_payload())


class FakeResponses:
    def __init__(self, payload=None):
        self.kwargs = None
        self.payload = payload

    def create(self, **kwargs):
        self.kwargs = kwargs
        return FakeResponse(self.payload)


class FakeClient:
    def __init__(self, payload=None):
        self.responses = FakeResponses(payload)


class QueueResponses:
    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.requests = []
        self.lock = threading.Lock()

    def create(self, **kwargs):
        with self.lock:
            self.requests.append(kwargs)
            payload = self.payloads.pop(0) if self.payloads else {
                "candidates": [],
                "coverage_complete": True,
                "next_focus": "",
            }
        return type("Response", (), {"status": "completed", "output_text": json.dumps(payload)})()


class QueueClient:
    def __init__(self, payloads):
        self.responses = QueueResponses(payloads)


class SchemaResponses:
    def __init__(self, payloads):
        self.payloads = payloads
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        name = kwargs["text"]["format"]["name"]
        payload = self.payloads[name]
        return type("Response", (), {"status": "completed", "output_text": json.dumps(payload)})()


class SchemaClient:
    def __init__(self, payloads):
        self.responses = SchemaResponses(payloads)


def deep_candidate() -> Candidate:
    return Candidate(
        rule_id="plaidnox.javascript.dynamic-html-to-pdf",
        title="Dynamic HTML to PDF",
        vulnerability_class="CWE-918",
        severity=Severity.HIGH,
        confidence=0.88,
        message="Request data reaches a PDF renderer.",
        evidence=Evidence(
            "app.js",
            5,
            5,
            "html_to_pdf.generatePdf(file)",
            "POST /reports",
            "html_to_pdf.generatePdf",
            ["request body", "reportData", "html_to_pdf.generatePdf"],
        ),
        metadata={"category": "ssrf"},
    )


def finding() -> Finding:
    candidate = deep_candidate()
    return Finding(
        fingerprint="fingerprint",
        repository="org/repo",
        rule_id=candidate.rule_id,
        title=candidate.title,
        vulnerability_class=candidate.vulnerability_class,
        severity=candidate.severity,
        confidence=candidate.confidence,
        state=FindingState.VALIDATED,
        message=candidate.message,
        impact="impact",
        remediation="remediation",
        evidence=candidate.evidence,
        priority_score=75,
        validator="deterministic",
    )


def test_ai_review_uses_strict_schema_and_redacts_source(sample_repo):
    (sample_repo / "app.js").write_text(
        """const uri = "mongodb+srv://admin:secret@host/db";
app.post("/reports", async (req, res) => {
  const reportData = `${req.body.name}`;
  return html_to_pdf.generatePdf({ content: reportData });
});
"""
    )
    client = FakeClient()
    review = PlaidNoxDeepHuntAgent(client, model="test-model").review(
        sample_repo, deep_candidate(), finding()
    )

    assert review.supported is True
    request = client.responses.kwargs
    assert request["model"] == "test-model"
    assert "prompt_cache_key" not in request
    assert request["text"]["format"]["strict"] is True
    supplied = request["input"][1]["content"]
    assert "untrusted evidence" in request["input"][0]["content"]
    assert "mongodb+srv://" not in supplied
    assert "secret@host" not in supplied
    assert "<redacted-mongodb-uri>" in supplied


def test_ai_review_routes_to_the_model_configured_for_the_jev_model_tier(sample_repo):
    (sample_repo / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/reports', async (req, res) => {\n"
        "  return html_to_pdf.generatePdf({ content: req.body.name });\n"
        "});\n"
    )
    client = FakeClient()
    agent = PlaidNoxDeepHuntAgent(client, model="test-model")

    agent.review(sample_repo, deep_candidate(), finding(), model_tier=ModelTier.DEEP)
    assert client.responses.kwargs["model"] == agent.model_by_tier["deep"]
    assert client.responses.kwargs["model"] != "test-model"

    agent.review(sample_repo, deep_candidate(), finding(), model_tier=ModelTier.FAST)
    assert client.responses.kwargs["model"] == agent.model_by_tier["fast"]

    agent.review(sample_repo, deep_candidate(), finding())
    assert client.responses.kwargs["model"] == "test-model"


def test_ai_review_redacts_secrets_from_every_payload_field_not_only_source(sample_repo):
    (sample_repo / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/reports', async (req, res) => {\n"
        "  return html_to_pdf.generatePdf({ content: req.body.name });\n"
        "});\n"
    )
    client = FakeClient()
    candidate = deep_candidate()
    candidate.message = "Leak via mongodb+srv://admin:secret@host/db in the discovery message"
    review = PlaidNoxDeepHuntAgent(client, model="test-model").review(sample_repo, candidate, finding())

    assert review.supported is True
    supplied = client.responses.kwargs["input"][1]["content"]
    assert "mongodb+srv://admin:secret" not in supplied
    assert "<redacted-mongodb-uri>" in supplied


def test_ai_review_never_reads_a_path_excluded_by_the_project_source_policy(sample_repo):
    client = FakeClient()
    agent = PlaidNoxDeepHuntAgent(client, model="test-model")
    agent.configure_source_policy(["app.js"], 1024 * 1024)

    with pytest.raises(AIResponseError, match="not admitted by the project source policy"):
        agent.review(sample_repo, deep_candidate(), finding())

    assert client.responses.kwargs is None


def test_ai_review_keeps_sensitive_contents_out_of_metadata_review(sample_repo):
    candidate = deep_candidate()
    candidate.metadata["sensitive_evidence"] = True
    client = FakeClient(review_payload(evidence_locations=[]))
    review = PlaidNoxDeepHuntAgent(client).review(sample_repo, candidate, finding())

    assert review.supported is True
    assert "[contents intentionally unavailable]" in client.responses.kwargs["input"][1]["content"]
    assert "Metadata-only verification" in client.responses.kwargs["input"][0]["content"]
    supplied = json.loads(client.responses.kwargs["input"][1]["content"])
    assert supplied["security_ir_context"] == {}


def test_ai_review_rejects_supported_result_with_incomplete_gates(sample_repo):
    payload = review_payload()
    payload["gate_results"] = payload["gate_results"][:-1]

    with pytest.raises(AIResponseError, match="exactly one verdict"):
        PlaidNoxDeepHuntAgent(FakeClient(payload)).review(
            sample_repo, deep_candidate(), finding()
        )


def test_metadata_review_rejects_invented_source_locations(sample_repo):
    candidate = deep_candidate()
    candidate.metadata["sensitive_evidence"] = True

    with pytest.raises(AIResponseError, match="invented source-code evidence"):
        PlaidNoxDeepHuntAgent(FakeClient()).review(sample_repo, candidate, finding())


def test_ai_review_resolves_an_on_demand_context_request_before_the_final_verdict(sample_repo):
    (sample_repo / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/reports', async (req, res) => {\n"
        "  return html_to_pdf.generatePdf({ content: req.body.name });\n"
        "});\n"
    )
    first_round = review_payload(
        supported=False,
        rejection_reason="Evidence gap: the imports of app.js are not yet available.",
        evidence_gaps=["Need to see the imports of app.js before ruling on reachability."],
        context_requests=[
            {"kind": "window", "path": "app.js", "symbol": "", "start_line": 1, "end_line": 2}
        ],
    )
    second_round = review_payload()
    client = QueueClient([first_round, second_round])

    review = PlaidNoxDeepHuntAgent(client).review(sample_repo, deep_candidate(), finding())

    assert review.supported is True
    assert len(client.responses.requests) == 2
    second_request_payload = json.loads(client.responses.requests[1]["input"][1]["content"])
    expansions = second_request_payload["context_expansions"]
    assert len(expansions) == 1
    assert expansions[0]["kind"] == "window"
    assert expansions[0]["resolved"] is True
    assert "express" in expansions[0]["content"]


def test_ai_review_stops_requesting_context_at_the_configured_round_limit(sample_repo):
    (sample_repo / "app.js").write_text("const express = require('express');\n")
    always_requesting = review_payload(
        supported=False,
        rejection_reason="Evidence gap: still need more context.",
        evidence_gaps=["Still need more context."],
        evidence_locations=[],
        context_requests=[
            {"kind": "window", "path": "app.js", "symbol": "", "start_line": 1, "end_line": 1}
        ],
    )
    client = QueueClient([always_requesting, always_requesting, always_requesting])

    review = PlaidNoxDeepHuntAgent(client).review(sample_repo, deep_candidate(), finding())

    assert review.supported is False
    assert len(client.responses.requests) == 3


def test_metadata_review_rejects_an_on_demand_context_request(sample_repo):
    candidate = deep_candidate()
    candidate.metadata["sensitive_evidence"] = True
    payload = review_payload(
        evidence_locations=[],
        context_requests=[
            {"kind": "window", "path": "app.js", "symbol": "", "start_line": 1, "end_line": 1}
        ],
    )

    with pytest.raises(AIResponseError, match="on-demand source or Security IR expansion"):
        PlaidNoxDeepHuntAgent(FakeClient(payload)).review(sample_repo, candidate, finding())


PATCH_TEXT = (
    "--- a/app.js\n"
    "+++ b/app.js\n"
    "@@ -1,5 +1,5 @@\n"
    " const express = require('express');\n"
    " const app = express();\n"
    " app.post('/reports', async (req, res) => {\n"
    "-  return html_to_pdf.generatePdf({ content: req.body.name });\n"
    "+  return html_to_pdf.generatePdf({ content: sanitize(req.body.name) });\n"
    " });\n"
)


def patch_proposal_payload(**overrides):
    payload = {
        "proposed": True,
        "patch": PATCH_TEXT,
        "summary": "Sanitize report content before passing it to the PDF renderer.",
        "files_changed": ["app.js"],
        "risk_notes": "Assumes a sanitize() helper is already available in this module.",
        "confidence": 0.8,
        "rejection_reason": "",
    }
    payload.update(overrides)
    return payload


def _write_reports_fixture(sample_repo):
    (sample_repo / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/reports', async (req, res) => {\n"
        "  return html_to_pdf.generatePdf({ content: req.body.name });\n"
        "});\n"
    )
    verified = finding()
    verified.evidence = Evidence(
        "app.js", 4, 4, "html_to_pdf.generatePdf({ content: req.body.name });", "POST /reports",
        "html_to_pdf.generatePdf", [],
    )
    verified.metadata["deep_hunt"] = review_payload(
        evidence_locations=[{"path": "app.js", "start_line": 4, "end_line": 4, "role": "origin"}]
    )
    return verified


def test_ai_proposes_a_patch_and_verifies_it_fixes_the_finding(sample_repo):
    verified = _write_reports_fixture(sample_repo)
    original_source = (sample_repo / "app.js").read_text()
    fixed_review = review_payload(
        supported=False,
        rejection_reason="Content is now sanitized before reaching the renderer.",
        evidence_gaps=[],
        evidence_locations=[],
    )
    client = SchemaClient(
        {
            "plaidnox_patch_proposal": patch_proposal_payload(),
            "plaidnox_security_review": fixed_review,
        }
    )
    agent = PlaidNoxDeepHuntAgent(client)

    proposal = agent.propose_patch(sample_repo, verified)
    assert proposal.proposed is True
    assert proposal.files_changed == ["app.js"]

    verification = agent.verify_patch(sample_repo, verified, proposal)
    assert verification.applied is True
    assert verification.verified is True
    assert verification.rescan_supported is False
    assert (sample_repo / "app.js").read_text() == original_source


def test_ai_patch_proposal_rejects_a_diff_whose_headers_do_not_match_files_changed(sample_repo):
    verified = _write_reports_fixture(sample_repo)
    client = FakeClient(patch_proposal_payload(files_changed=["other.js"]))

    with pytest.raises(AIResponseError, match="declared files did not match"):
        PlaidNoxDeepHuntAgent(client).propose_patch(sample_repo, verified)


def test_ai_patch_proposal_declines_without_a_reason_is_rejected(sample_repo):
    verified = _write_reports_fixture(sample_repo)
    client = FakeClient(
        patch_proposal_payload(proposed=False, patch="", files_changed=[], rejection_reason="")
    )

    with pytest.raises(AIResponseError, match="declined without an evidence-backed reason"):
        PlaidNoxDeepHuntAgent(client).propose_patch(sample_repo, verified)


def test_verify_patch_reports_an_unapplied_patch_without_touching_the_repository(sample_repo):
    verified = _write_reports_fixture(sample_repo)
    original_source = (sample_repo / "app.js").read_text()
    broken_patch = patch_proposal_payload(
        patch=(
            "--- a/app.js\n"
            "+++ b/app.js\n"
            "@@ -1,5 +1,5 @@\n"
            " this context line does not match the file\n"
            "-neither does this one\n"
            "+so the patch cannot apply\n"
        )
    )
    agent = PlaidNoxDeepHuntAgent(FakeClient(broken_patch))
    proposal = agent.propose_patch(sample_repo, verified)

    verification = agent.verify_patch(sample_repo, verified, proposal)
    assert verification.applied is False
    assert verification.verified is False
    assert (sample_repo / "app.js").read_text() == original_source


def test_verify_patch_skips_the_rescan_when_no_patch_was_proposed(sample_repo):
    verified = _write_reports_fixture(sample_repo)
    payload = patch_proposal_payload(
        proposed=False, patch="", files_changed=[], rejection_reason="Not confident enough to fix this safely."
    )
    agent = PlaidNoxDeepHuntAgent(FakeClient(payload))
    declined = agent.propose_patch(sample_repo, verified)

    verification = agent.verify_patch(sample_repo, verified, declined)
    assert verification.applied is False
    assert verification.verified is False


def test_env_loader_does_not_evaluate_shell_content(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("LITELLM_API_KEY=test-key\nDANGEROUS=$(touch should-not-run)\n")
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    load_env_file(env_file)
    assert __import__("os").environ["LITELLM_API_KEY"] == "test-key"
    assert not (tmp_path / "should-not-run").exists()


def test_env_loader_accepts_litellm_base_without_evaluating_values(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "LITELLM_API_BASE=http://localhost:4000" + chr(10) + "UNTRUSTED=$(touch should-not-run)" + chr(10)
    )
    monkeypatch.delenv("LITELLM_API_BASE", raising=False)
    load_env_file(env_file)
    assert __import__("os").environ["LITELLM_API_BASE"] == "http://localhost:4000"
    assert not (tmp_path / "should-not-run").exists()


def test_env_loader_accepts_ifrit_research_configuration(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "IFRIT_RESEARCH_PROVIDER=perplexity_sonar\n"
        "IFRIT_PERPLEXITY_API_KEY=test-perplexity-key\n"
        "IFRIT_RESEARCH_SONAR_MODEL=sonar\n"
    )
    for key in ("IFRIT_RESEARCH_PROVIDER", "IFRIT_PERPLEXITY_API_KEY", "IFRIT_RESEARCH_SONAR_MODEL"):
        monkeypatch.delenv(key, raising=False)

    load_env_file(env_file)

    environment = __import__("os").environ
    assert environment["IFRIT_RESEARCH_PROVIDER"] == "perplexity_sonar"
    assert environment["IFRIT_RESEARCH_SONAR_MODEL"] == "sonar"


def test_ai_builds_context_then_discovers_evidenced_candidates(sample_repo):
    (sample_repo / "app.js").write_text(
        """const express = require("express");
const app = express();
app.get("/users/:id", async (req, res) => {
  return User.findById(req.params.id);
});
"""
    )
    client = SchemaClient(
        {
            "plaidnox_recon_search_plan": {
                "strategy": "Derive route and request-input evidence from the observed Express imports.",
                "queries": [
                    {
                        "query_id": "express-entrypoints",
                        "pattern": "app\\.(get|post)|req\\.(params|body)",
                        "include_globs": ["*.js"],
                        "objective": "Locate repository-specific Express entry points and input reads.",
                        "coverage_targets": ["application entry points", "request inputs"],
                    }
                ],
                "coverage_notes": "The fixture has one application source file.",
            },
            "plaidnox_repository_context": {
                "architecture": "Express API serving a user lookup route.",
                "applications": [
                    {
                        "app_name": "fixture",
                        "app_root_path": ".",
                        "architecture": "Express route handler.",
                        "entry_points": ["app.js"],
                        "trust_boundaries": ["HTTP request"],
                        "data_stores": ["User model"],
                    }
                ],
            },
            "plaidnox_search_query_plan": {
                "strategy": "Find request-controlled object lookups.",
                "queries": [
                    {
                        "query_id": "user-lookup",
                        "task_ids": ["task-user-lookup"],
                        "pattern": "findById|req\\.params",
                        "include_globs": ["*.js"],
                        "objective": "Locate attacker-controlled identifiers and object lookup operations.",
                    }
                ],
                "coverage_notes": "The task is covered by source and sink searches.",
            },
            "plaidnox_vulnerability_discovery": {
                "candidates": [
                    {
                        "confirmed": True,
                        "title": "Potential missing ownership check",
                        "vulnerability_class": "missing object ownership enforcement",
                        "classification_references": [
                            {
                                "namespace": "CWE",
                                "identifier": "CWE-639",
                                "name": "Authorization Bypass Through User-Controlled Key",
                                "source_url": "https://cwe.mitre.org/data/definitions/639.html",
                            }
                        ],
                        "business_impact": "An authenticated actor may read another actor's object.",
                        "severity": "high",
                        "confidence": 0.82,
                        "category": "authorization",
                        "path": "app.js",
                        "start_line": 4,
                        "end_line": 4,
                        "message": "The route queries an object by request-supplied identifier without an ownership condition.",
                        "attack_path": "request parameter -> object lookup",
                        "remediation": "Scope the query to the authenticated subject or perform an explicit ownership check.",
                    }
                ],
                "coverage_complete": True,
                "next_focus": "",
            },
        }
    )
    agent = PlaidNoxDeepHuntAgent(client, model="test-model")
    context = agent.build_repository_context(sample_repo, "org/repo", "abc123", build_structural_graph(sample_repo))
    plan = HuntPlan(
        "plan-test",
        "Review the user lookup path.",
        [
            HuntTask(
                "task-user-lookup",
                "Review user lookup",
                "Trace the request identifier to the object lookup.",
                ["app.js"],
                ["GET /users/:id"],
                ["authorization"],
                ["source, controls, and object lookup"],
                [],
                [],
            )
        ],
    )
    candidates, failures = agent.discover_candidates(sample_repo, context, plan)

    assert context.to_dict()["applications"][0]["app_name"] == "fixture"
    assert failures == 0
    assert len(candidates) == 1
    assert candidates[0].vulnerability_class == "missing object ownership enforcement"
    assert candidates[0].metadata["classification_references"][0]["identifier"] == "CWE-639"
    assert candidates[0].metadata["ai_discovery"] is True
    assert client.responses.requests[0]["text"]["format"]["name"] == "plaidnox_recon_search_plan"
    assert client.responses.requests[1]["text"]["format"]["name"] == "plaidnox_repository_context"
    assert client.responses.requests[2]["text"]["format"]["name"] == "plaidnox_search_query_plan"
    assert client.responses.requests[3]["text"]["format"]["name"] == "plaidnox_vulnerability_discovery"
    discovery_payload = json.loads(client.responses.requests[3]["input"][1]["content"])
    compact_context = discovery_payload["repository_context"]
    assert "security_ir" not in compact_context
    assert "source_inventory" not in compact_context
    assert "source_tree" not in compact_context
    assert compact_context["focus_path"] == "app.js"
    discovery_audit = agent.model_input_audit()[3]
    assert discovery_audit["operation"] == "vulnerability_discovery"
    assert discovery_audit["repository_wide_context"] is False


def test_ai_can_request_a_bounded_call_flow_only_when_needed(tmp_path):
    source = tmp_path / "service.py"
    source.write_text(
        "def load_record(identifier):\n    return store.load(identifier)\n\n"
        "def handle_request(identifier):\n    return load_record(identifier)\n",
        encoding="utf-8",
    )
    graph = build_structural_graph(tmp_path)

    result = _resolve_context_request(
        tmp_path,
        graph,
        {"kind": "flow", "path": "service.py", "symbol": "load_record", "start_line": 1, "end_line": 2},
    )

    assert result["resolved"] is True
    assert result["edges"]
    assert len(result["edges"]) <= 80


def test_ai_attaches_context_fabric_before_reconnaissance(sample_repo, tmp_path):
    from plaidnox_sast.context_fabric import ContextFabricStore

    client = SchemaClient(
        {
            "plaidnox_recon_search_plan": {
                "strategy": "Inspect the observed JavaScript application.",
                "queries": [
                    {
                        "query_id": "fixture-entrypoints",
                        "pattern": "app\\.",
                        "include_globs": ["*.js"],
                        "objective": "Locate application registration points.",
                        "coverage_targets": ["fixture application"],
                    }
                ],
                "coverage_notes": "Fixture scope is bounded.",
            },
            "plaidnox_repository_context": {
                "architecture": "Express fixture.",
                "applications": [],
            }
        }
    )
    agent = PlaidNoxDeepHuntAgent(
        client,
        context_store=ContextFabricStore(tmp_path / "context.sqlite"),
    )

    context = agent.build_repository_context(
        sample_repo,
        "org/repo",
        "abc123",
        build_structural_graph(sample_repo, False),
    )

    assert context.context_fabric["context_id"].startswith("ctx-")
    assert context.context_fabric["reused"] is False
    request = json.loads(client.responses.requests[0]["input"][1]["content"])
    assert request["context_fabric"]["context_id"] == context.context_fabric["context_id"]


def test_ai_creates_open_ended_hunt_tasks_before_discovery(sample_repo):
    client = QueueClient(
        [
            {
                "strategy": "Inspect observed JavaScript registration and request access.",
                "queries": [
                    {
                        "query_id": "identity-entrypoints",
                        "pattern": "app\\.|req\\.",
                        "include_globs": ["*.js"],
                        "objective": "Locate identity entry points and inputs.",
                        "coverage_targets": ["identity application"],
                    }
                ],
                "coverage_notes": "Fixture scope is bounded.",
            },
            {
                "architecture": "Express identity service.",
                "applications": [],
            },
            {
                "strategy": "Map attacker-reachable flows and verify business invariants.",
                "tasks": [
                    {
                        "task_id": "account-boundary",
                        "title": "Account boundary review",
                        "objective": "Trace every account lookup from HTTP input through ownership enforcement.",
                        "focus_paths": ["app.js"],
                        "entry_points": ["POST /signin"],
                        "vulnerability_themes": ["cross-tenant state confusion"],
                        "evidence_requirements": ["source, controls, and security impact"],
                        "knowledge_queries": [],
                    }
                ],
            }
        ]
    )
    agent = PlaidNoxDeepHuntAgent(client, model="test-model")
    context = agent.build_repository_context(
        sample_repo,
        "org/repo",
        "abc123",
        build_structural_graph(sample_repo, False),
        "Customer identities are business critical.",
    )
    plan = agent.plan_tasks(context, "Authentication uses signed tokens.")

    assert plan.tasks[0].vulnerability_themes == ["cross-tenant state confusion"]
    assert context.business_context.startswith("Customer identities")
    assert "exhaustive attacker-first hunting" in client.responses.requests[2]["input"][0]["content"]


def test_ai_consolidates_only_model_grouped_findings():
    first = finding()
    second = finding()
    second.fingerprint = "second-fingerprint"
    second.evidence = Evidence("routes/report.js", 22, 22, "render(report)")
    client = SchemaClient(
        {
            "plaidnox_finding_consolidation": {
                "assignments": {
                    first.fingerprint: "pdf-rendering",
                    second.fingerprint: "pdf-rendering",
                }
            },
            "plaidnox_finding_group_narratives": {
                "groups": {
                    "pdf-rendering": {
                        "primary_fingerprint": first.fingerprint,
                        "title": "Untrusted report input reaches the PDF renderer",
                        "vulnerability_class": "CWE-918",
                        "severity": "high",
                        "confidence": 0.94,
                        "message": "Two call sites expose the same report-rendering trust-boundary failure.",
                        "business_impact": "An attacker can make the renderer access protected resources.",
                        "remediation": "Isolate rendering and reject remote resource references.",
                        "reasoning": "Both paths reach the same renderer without an intervening control.",
                    }
                }
            }
        }
    )

    consolidated = PlaidNoxDeepHuntAgent(client).consolidate_findings([first, second])

    assert len(consolidated) == 1
    assert consolidated[0].confidence == 0.94
    assert consolidated[0].metadata["consolidation"]["member_fingerprints"] == [
        "fingerprint",
        "second-fingerprint",
    ]
    assert [request["text"]["format"]["name"] for request in client.responses.requests] == [
        "plaidnox_finding_consolidation",
        "plaidnox_finding_group_narratives",
    ]
    required = client.responses.requests[0]["text"]["format"]["schema"]["properties"]["assignments"]["required"]
    assert required == [first.fingerprint, second.fingerprint]


def test_ai_rejects_consolidation_that_drops_a_finding():
    import pytest

    from plaidnox_sast.ai import AIResponseError

    first = finding()
    second = finding()
    second.fingerprint = "second-fingerprint"
    client = SchemaClient(
        {
            "plaidnox_finding_consolidation": {
                "assignments": {
                    first.fingerprint: "first",
                    second.fingerprint: "missing-group",
                }
            },
            "plaidnox_finding_group_narratives": {
                "groups": {
                    "first": {
                        "primary_fingerprint": first.fingerprint,
                        "title": first.title,
                        "vulnerability_class": first.vulnerability_class,
                        "severity": first.severity.value,
                        "confidence": first.confidence,
                        "message": first.message,
                        "business_impact": first.impact,
                        "remediation": first.remediation,
                        "reasoning": "The other finding was omitted.",
                    }
                }
            }
        }
    )

    with pytest.raises(AIResponseError, match="narratives did not cover"):
        PlaidNoxDeepHuntAgent(client).consolidate_findings([first, second])


def test_variant_sweep_uses_compact_verified_context(sample_repo):
    client = SchemaClient(
        {
            "plaidnox_search_query_plan": {
                "strategy": "Search for variants of the verified root cause.",
                "queries": [
                    {
                        "query_id": "route-variants",
                        "task_ids": ["task-test"],
                        "pattern": "app\\.(get|post)|req\\.",
                        "include_globs": ["*.js"],
                        "objective": "Find alternate request paths and input use.",
                    }
                ],
                "coverage_notes": "The route task is covered.",
            },
            "plaidnox_variant_sweep": {
                "candidates": [],
                "coverage_complete": True,
                "next_focus": "",
            }
        }
    )
    agent = PlaidNoxDeepHuntAgent(client)
    context = AIRepositoryContext("org/repo", "abc", "Fixture", [], [], ["app.js"], 0, 0)
    plan = HuntPlan(
        "plan-test",
        "Trace attacker-reachable paths.",
        [
            HuntTask(
                "task-test",
                "Review routes",
                "Trace external input.",
                ["app.js"],
                ["GET /"],
                ["open-ended review"],
                ["source and control evidence"],
                ["framework security behavior"],
                [{"knowledge_id": "large-context", "content": "unused" * 500}],
            )
        ],
    )

    variants, failures = agent.sweep_variants(sample_repo, context, plan, [(deep_candidate(), finding())])

    assert variants == []
    assert failures == 0
    search_request = json.loads(client.responses.requests[0]["input"][1]["content"])
    assert "content" not in search_request["hunt_plan"]["tasks"][0]["knowledge_context"][0]
    request = json.loads(client.responses.requests[1]["input"][1]["content"])
    assert set(request["verified_roots"][0]) == {
        "fingerprint",
        "title",
        "vulnerability_class",
        "severity",
        "path",
        "start_line",
        "end_line",
        "attack_path",
        "root_cause",
        "category",
    }
    assert "knowledge_context" not in request["hunt_plan"]["tasks"][0]


def test_variant_sweep_records_provider_failure_without_crashing(sample_repo):
    class FailingResponses:
        def create(self, **kwargs):
            raise RuntimeError("rate limited")

    class FailingClient:
        responses = FailingResponses()

    agent = PlaidNoxDeepHuntAgent(FailingClient())
    context = AIRepositoryContext("org/repo", "abc", "Fixture", [], [], ["app.js"], 0, 0)
    plan = HuntPlan(
        "plan-test",
        "Trace paths.",
        [HuntTask("task", "Review", "Trace", ["app.js"], [], [], [], [], [])],
    )

    variants, failures = agent.sweep_variants(sample_repo, context, plan, [(deep_candidate(), finding())])

    assert variants == []
    assert failures >= 1
