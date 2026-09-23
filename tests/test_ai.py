from __future__ import annotations

import json
import threading
from dataclasses import replace

import pytest

from plaidnox_sast.ai import (
    AIRepositoryContext,
    AIResponseError,
    HuntPlan,
    HuntTask,
    PlaidNoxDeepHuntAgent,
    _execute_recon_search_plan,
    _resolve_context_request,
    _search_segments,
    load_env_file,
)
from plaidnox_sast.graph import build_structural_graph
from plaidnox_sast.jev import JevClient, JevRetryRouter
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
            "gained_capability": "SERVER_SIDE_REQUEST",
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


def test_recon_skips_invalid_model_pattern_and_keeps_other_query_evidence(sample_repo) -> None:
    errors = []
    queries = [
        {
            "query_id": "invalid-lookbehind",
            "objective": "Locate evaluator calls.",
            "pattern": r"(?<!\.)eval\(",
            "include_globs": ["*.js"],
            "coverage_targets": ["runtime-evaluation"],
        },
        {
            "query_id": "request-input",
            "objective": "Locate request inputs.",
            "pattern": r"req\.body",
            "include_globs": ["*.js"],
            "coverage_targets": ["input-surface"],
        },
    ]

    evidence, hits = _execute_recon_search_plan(
        sample_repo,
        queries,
        [],
        None,
        error_sink=errors.append,
    )

    assert len(errors) == 1
    assert errors[0].query_id == "invalid-lookbehind"
    assert evidence[0]["query_failed"] is True
    assert evidence[0]["failure"]["pattern_hash"] == errors[0].pattern_hash
    assert evidence[1]["query_failed"] is False
    assert any(hit.query_id == "request-input" for hit in hits)


def test_search_plan_skips_invalid_pattern_and_falls_back_to_task_focus(sample_repo) -> None:
    plan = HuntPlan(
        "plan-test",
        "Review the focused source.",
        [
            HuntTask(
                "task-1",
                "Review request handling",
                "Trace attacker input.",
                ["app.js"],
                [],
                [],
                [],
                [],
                [],
            )
        ],
    )
    errors = []

    segments = _search_segments(
        sample_repo,
        [
            {
                "query_id": "invalid-lookbehind",
                "pattern": r"(?<!\.)eval\(",
                "include_globs": ["*.js"],
                "task_ids": ["task-1"],
            }
        ],
        plan,
        build_structural_graph(sample_repo),
        [],
        None,
        error_sink=errors.append,
    )

    assert len(errors) == 1
    assert segments
    assert {item["path"] for item in segments} == {"app.js"}
    assert all(item["task_ids"] == ["task-1"] for item in segments)


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
    client = QueueClient([always_requesting, always_requesting, always_requesting, always_requesting])

    review = PlaidNoxDeepHuntAgent(client).review(sample_repo, deep_candidate(), finding())

    assert review.supported is False
    # 3 normal rounds (max_rounds=2) plus 1 bounded retry-routed round once the
    # evidence gap is still open, since JevRetryRouter's local fallback escalates
    # the model tier when the candidate has never been routed to DEEP.
    assert len(client.responses.requests) == 4
    assert client.responses.requests[3]["model"] == "kimi-k3"


def test_ai_review_retry_route_does_not_add_a_second_extra_round(sample_repo):
    """The retry route is consulted at most once per hunt(): the bounded extra
    round itself never triggers another retry-route consultation."""
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
    client = QueueClient([always_requesting, always_requesting, always_requesting, always_requesting])

    review = PlaidNoxDeepHuntAgent(client).review(
        sample_repo, deep_candidate(), finding(), model_tier=ModelTier.DEEP
    )

    assert review.supported is False
    # Already DEEP, so the local retry fallback expands context for exactly one
    # more round instead of escalating further.
    assert len(client.responses.requests) == 4


class FakeHTTPResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_ai_review_retry_route_skips_the_extra_round_when_jev_marks_unresolved(sample_repo, monkeypatch):
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
    response = {
        "model": "jev-test",
        "answers": {"next_action": {"choice": "mark_unresolved", "confidence": 0.9}},
    }
    monkeypatch.setattr("plaidnox_sast.jev.urlopen", lambda request, timeout: FakeHTTPResponse(response))
    agent = PlaidNoxDeepHuntAgent(client)
    agent.configure_retry_route(JevRetryRouter(JevClient("test-key", endpoint="https://example.test")))

    review = agent.review(sample_repo, deep_candidate(), finding())

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
    assert "ai_remediation" not in candidates[0].metadata
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


def test_ai_uses_persisted_context_and_only_changed_scope_on_next_revision(tmp_path):
    from plaidnox_sast.context_fabric import ContextFabricStore

    (tmp_path / "account.js").write_text(
        "function loadAccount(id) { return database.find(id); }\n",
        encoding="utf-8",
    )
    changed = tmp_path / "format.js"
    changed.write_text("function format(value) { return String(value); }\n", encoding="utf-8")
    client = SchemaClient(
        {
            "plaidnox_recon_search_plan": {
                "strategy": "Inspect observed functions.",
                "queries": [
                    {
                        "query_id": "observed-functions",
                        "pattern": "function",
                        "include_globs": ["*.js"],
                        "objective": "Locate observed function definitions.",
                        "coverage_targets": ["changed scope"],
                    }
                ],
                "coverage_notes": "The supplied scope is bounded.",
            },
            "plaidnox_repository_context": {
                "architecture": "Two small JavaScript modules.",
                "applications": [],
            },
            "plaidnox_search_query_plan": {
                "strategy": "Inspect the changed function scope.",
                "queries": [
                    {
                        "query_id": "changed-functions",
                        "task_ids": ["task-changed"],
                        "pattern": "function",
                        "include_globs": ["*.js"],
                        "objective": "Inspect functions in the affected scope.",
                    }
                ],
                "coverage_notes": "The changed task is covered.",
            },
            "plaidnox_vulnerability_discovery": {
                "candidates": [],
                "coverage_complete": True,
                "next_focus": "",
            },
        }
    )
    agent = PlaidNoxDeepHuntAgent(
        client,
        context_store=ContextFabricStore(tmp_path / "context.sqlite"),
    )
    agent.build_repository_context(tmp_path, "org/repo", "revision-a", build_structural_graph(tmp_path))

    changed.write_text(
        "function format(value) { return String(value).trim(); }\n",
        encoding="utf-8",
    )
    context = agent.build_repository_context(
        tmp_path,
        "org/repo",
        "revision-b",
        build_structural_graph(tmp_path),
    )

    incremental_recon = json.loads(client.responses.requests[2]["input"][1]["content"])
    assert "source_tree" not in incremental_recon
    assert "source_inventory" not in incremental_recon
    assert "security_ir" not in incremental_recon
    assert incremental_recon["analysis_scope_tree"] == ["format.js"]
    assert incremental_recon["changed_source_inventory"][0]["path"] == "format.js"
    assert incremental_recon["previous_repository_context"]["architecture"]
    assert context.analysis_scope_paths == ["format.js"]
    assert context.context_fabric["context_reused_percent"] > 0
    assert agent.model_input_audit()[2]["repository_wide_context"] is False

    plan = HuntPlan(
        "plan-changed",
        "Review the affected scope.",
        [
            HuntTask(
                "task-changed",
                "Review changed code",
                "Inspect affected behavior.",
                ["format.js"],
                [],
                ["open-ended security review"],
                ["source and control evidence"],
                [],
                [],
            )
        ],
    )
    candidates, failures = agent.discover_candidates(tmp_path, context, plan)
    discovery_payloads = [
        json.loads(request["input"][1]["content"])
        for request in client.responses.requests
        if request["text"]["format"]["name"] == "plaidnox_vulnerability_discovery"
    ]

    assert candidates == []
    assert failures == 0
    assert [payload["source_segment"]["path"] for payload in discovery_payloads] == ["format.js"]


def test_ai_reuses_exact_persisted_repository_context_without_model_calls(tmp_path):
    from plaidnox_sast.context_fabric import ContextFabricStore

    (tmp_path / "service.py").write_text("def run():\n    return True\n", encoding="utf-8")
    client = SchemaClient(
        {
            "plaidnox_recon_search_plan": {
                "strategy": "Inspect observed functions.",
                "queries": [
                    {
                        "query_id": "observed-functions",
                        "pattern": "def ",
                        "include_globs": ["*.py"],
                        "objective": "Locate observed functions.",
                        "coverage_targets": ["service"],
                    }
                ],
                "coverage_notes": "The supplied scope is bounded.",
            },
            "plaidnox_repository_context": {
                "architecture": "Python service.",
                "applications": [],
            },
        }
    )
    agent = PlaidNoxDeepHuntAgent(
        client,
        context_store=ContextFabricStore(tmp_path / "context.sqlite"),
    )
    graph = build_structural_graph(tmp_path)
    first = agent.build_repository_context(tmp_path, "org/repo", "revision-a", graph)
    request_count = len(client.responses.requests)

    reused = agent.build_repository_context(tmp_path, "org/repo", "revision-a", graph)

    assert len(client.responses.requests) == request_count
    assert reused.architecture == first.architecture
    assert reused.context_fabric["reused"] is True


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


def capable_finding() -> Finding:
    capable = finding()
    capable.metadata["deep_hunt"] = {
        "gained_capability": "SERVER_SIDE_REQUEST",
        "attack_path": "request body -> report template -> PDF renderer",
    }
    return capable


def test_capability_chain_skips_findings_with_no_gained_capability(sample_repo):
    client = SchemaClient({})
    agent = PlaidNoxDeepHuntAgent(client)
    context = AIRepositoryContext("org/repo", "abc", "Fixture", [], [], ["app.js"], 0, 0)
    plan = HuntPlan("plan-test", "Trace paths.", [HuntTask("task", "Review", "Trace", ["app.js"], [], [], [], [], [])])

    pivots, failures = agent.chain_capability_pivots(sample_repo, context, plan, [(deep_candidate(), finding())])

    assert pivots == []
    assert failures == 0
    assert client.responses.requests == []


def test_capability_chain_searches_from_the_gained_capability(sample_repo):
    client = SchemaClient(
        {
            "plaidnox_search_query_plan": {
                "strategy": "Search for where this capability crosses a further boundary.",
                "queries": [
                    {
                        "query_id": "renderer-pivots",
                        "task_ids": ["task-test"],
                        "pattern": "renderer|fetch\\(",
                        "include_globs": ["*.js"],
                        "objective": "Find where the renderer's network reach is consumed elsewhere.",
                    }
                ],
                "coverage_notes": "The renderer task is covered.",
            },
            "plaidnox_capability_chain": {
                "candidates": [],
                "coverage_complete": True,
                "next_focus": "",
            },
        }
    )
    agent = PlaidNoxDeepHuntAgent(client)
    context = AIRepositoryContext("org/repo", "abc", "Fixture", [], [], ["app.js"], 0, 0)
    plan = HuntPlan(
        "plan-test",
        "Trace attacker-reachable paths.",
        [HuntTask("task-test", "Review renderer", "Trace renderer reach.", ["app.js"], ["GET /"], [], [], [], [])],
    )

    pivots, failures = agent.chain_capability_pivots(sample_repo, context, plan, [(deep_candidate(), capable_finding())])

    assert pivots == []
    assert failures == 0
    search_request = json.loads(client.responses.requests[0]["input"][1]["content"])
    assert search_request["verified_roots"][0]["capability"] == "SERVER_SIDE_REQUEST"
    chain_request = json.loads(client.responses.requests[-1]["input"][1]["content"])
    assert chain_request["verified_roots"][0]["capability"] == "SERVER_SIDE_REQUEST"


def test_capability_chain_caps_and_prioritizes_findings_when_over_budget(sample_repo):
    client = SchemaClient(
        {
            "plaidnox_search_query_plan": {
                "strategy": "Search for where this capability crosses a further boundary.",
                "queries": [
                    {
                        "query_id": "renderer-pivots",
                        "task_ids": ["task-test"],
                        "pattern": "renderer|fetch\\(",
                        "include_globs": ["*.js"],
                        "objective": "Find where the renderer's network reach is consumed elsewhere.",
                    }
                ],
                "coverage_notes": "The renderer task is covered.",
            },
            "plaidnox_capability_chain": {
                "candidates": [],
                "coverage_complete": True,
                "next_focus": "",
            },
        }
    )
    agent = PlaidNoxDeepHuntAgent(client)
    context = AIRepositoryContext("org/repo", "abc", "Fixture", [], [], ["app.js"], 0, 0)
    plan = HuntPlan(
        "plan-test",
        "Trace attacker-reachable paths.",
        [HuntTask("task-test", "Review renderer", "Trace renderer reach.", ["app.js"], ["GET /"], [], [], [], [])],
    )
    verified = [
        (deep_candidate(), replace(capable_finding(), fingerprint=f"standard-{index}", severity=Severity.MEDIUM))
        for index in range(4)
    ] + [
        (deep_candidate(), replace(capable_finding(), fingerprint=f"high-{index}", severity=Severity.CRITICAL))
        for index in range(3)
    ]

    pivots, failures = agent.chain_capability_pivots(sample_repo, context, plan, verified)

    assert pivots == []
    assert failures == 0
    chain_request = json.loads(client.responses.requests[-1]["input"][1]["content"])
    sent_fingerprints = [item["fingerprint"] for item in chain_request["verified_roots"]]
    assert len(sent_fingerprints) == 5
    assert {"high-0", "high-1", "high-2"} <= set(sent_fingerprints)
    assert sent_fingerprints == ["high-0", "high-1", "high-2", "standard-0", "standard-1"]


def test_capability_chain_records_provider_failure_without_crashing(sample_repo):
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

    pivots, failures = agent.chain_capability_pivots(sample_repo, context, plan, [(deep_candidate(), capable_finding())])

    assert pivots == []
    assert failures >= 1


def test_deep_hunt_review_requires_gained_capability_when_supported(sample_repo):
    payload = review_payload(gained_capability="")
    agent = PlaidNoxDeepHuntAgent(FakeClient(payload))

    with pytest.raises(AIResponseError, match="gained capability"):
        agent.hunt(sample_repo, deep_candidate(), finding())


def test_structured_response_uses_the_reasoning_effort_configured_for_the_operation(sample_repo):
    from plaidnox_sast.assets import load_json

    client = FakeClient(review_payload())
    agent = PlaidNoxDeepHuntAgent(client)

    agent.review(sample_repo, deep_candidate(), finding())

    expected = load_json("runtime/agent.json")["reasoning_effort_by_operation"]["security_review"]
    assert client.responses.kwargs["reasoning"]["effort"] == expected


def test_structured_response_falls_back_to_low_effort_for_an_unlisted_operation(sample_repo, monkeypatch):
    import plaidnox_sast.ai as ai_module
    from plaidnox_sast.assets import load_json as real_load_json

    client = FakeClient(review_payload())
    agent = PlaidNoxDeepHuntAgent(client)

    def patched_load_json(name):
        data = real_load_json(name)
        if name == "runtime/agent.json":
            data = dict(data)
            data["reasoning_effort_by_operation"] = {}
        return data

    monkeypatch.setattr(ai_module, "load_json", patched_load_json)

    agent.review(sample_repo, deep_candidate(), finding())

    assert client.responses.kwargs["reasoning"]["effort"] == "low"


def test_stronger_effort_escalates_above_the_configured_default():
    from plaidnox_sast.ai import _stronger_effort

    assert _stronger_effort("low", "high") == "high"
    assert _stronger_effort("medium", "high") == "high"


def test_stronger_effort_never_downgrades_the_configured_default():
    from plaidnox_sast.ai import _stronger_effort

    assert _stronger_effort("high", "low") == "high"
    assert _stronger_effort("medium", None) == "medium"


def test_hunt_effort_override_is_none_without_a_route():
    from plaidnox_sast.ai import _hunt_effort_override

    assert _hunt_effort_override(None) is None


def test_hunt_effort_override_escalates_for_a_high_complexity_route():
    from plaidnox_sast.ai import _hunt_effort_override
    from plaidnox_sast.models import Depth, RouteDecision

    route = RouteDecision(depth=Depth.DEEP, reason="test", analysis_complexity=5)
    assert _hunt_effort_override(route) == "high"


def test_hunt_effort_override_escalates_for_a_falsification_flagged_route():
    from plaidnox_sast.ai import _hunt_effort_override
    from plaidnox_sast.models import Depth, RouteDecision

    route = RouteDecision(depth=Depth.DEEP, reason="test", analysis_complexity=2, needs_deep_falsification="yes")
    assert _hunt_effort_override(route) == "high"


def test_hunt_effort_override_is_none_for_a_low_complexity_uncontested_route():
    from plaidnox_sast.ai import _hunt_effort_override
    from plaidnox_sast.models import Depth, RouteDecision

    route = RouteDecision(depth=Depth.STANDARD, reason="test", analysis_complexity=2, needs_deep_falsification="unlikely")
    assert _hunt_effort_override(route) is None


def test_structured_response_escalates_reasoning_effort_when_jev_route_demands_it(sample_repo, monkeypatch):
    import plaidnox_sast.ai as ai_module
    from plaidnox_sast.assets import load_json as real_load_json
    from plaidnox_sast.models import Depth, ModelTier, RouteDecision

    client = FakeClient(review_payload())
    agent = PlaidNoxDeepHuntAgent(client)

    def patched_load_json(name):
        data = real_load_json(name)
        if name == "runtime/agent.json":
            data = dict(data)
            effort = dict(data["reasoning_effort_by_operation"])
            effort["security_review"] = "medium"
            data["reasoning_effort_by_operation"] = effort
        return data

    monkeypatch.setattr(ai_module, "load_json", patched_load_json)
    route = RouteDecision(depth=Depth.DEEP, reason="test", model_tier=ModelTier.DEEP, analysis_complexity=5)

    agent.hunt(sample_repo, deep_candidate(), finding(), route=route)

    assert client.responses.kwargs["reasoning"]["effort"] == "high"


def test_context_expansion_max_requests_defaults_without_a_route():
    from plaidnox_sast.ai import _context_expansion_max_requests

    runtime = {
        "context_expansion_max_requests_per_round": 5,
        "context_expansion_signal_bonus_requests": 2,
        "context_expansion_max_requests_per_round_ceiling": 13,
    }
    assert _context_expansion_max_requests(runtime, None) == 5


def test_context_expansion_max_requests_grows_with_breadth_signals_and_is_capped():
    from plaidnox_sast.ai import _context_expansion_max_requests
    from plaidnox_sast.models import Depth, RouteDecision

    runtime = {
        "context_expansion_max_requests_per_round": 5,
        "context_expansion_signal_bonus_requests": 2,
        "context_expansion_max_requests_per_round_ceiling": 13,
    }
    two_signals = RouteDecision(
        depth=Depth.DEEP, reason="test", needs_cross_file="likely", needs_state_reconstruction="likely"
    )
    all_signals = RouteDecision(
        depth=Depth.DEEP,
        reason="test",
        needs_cross_file="likely",
        needs_state_reconstruction="likely",
        needs_external_semantics="yes",
        needs_environment_context="yes",
    )
    assert _context_expansion_max_requests(runtime, two_signals) == 9
    assert _context_expansion_max_requests(runtime, all_signals) == 13


def test_hunt_caps_context_expansion_requests_per_round_by_default(sample_repo):
    (sample_repo / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/reports', async (req, res) => {\n"
        "  return html_to_pdf.generatePdf({ content: req.body.name });\n"
        "});\n"
    )
    requests = [
        {"kind": "window", "path": "app.js", "symbol": "", "start_line": 1, "end_line": 1} for _ in range(7)
    ]
    first_round = review_payload(
        supported=False,
        rejection_reason="Evidence gap: still need more context.",
        evidence_gaps=["Still need more context."],
        evidence_locations=[],
        context_requests=requests,
    )
    client = QueueClient([first_round, review_payload()])

    PlaidNoxDeepHuntAgent(client).hunt(sample_repo, deep_candidate(), finding())

    second_request_payload = json.loads(client.responses.requests[1]["input"][1]["content"])
    assert len(second_request_payload["context_expansions"]) == 5


def test_hunt_expands_more_context_per_round_when_jev_route_flags_broad_evidence_need(sample_repo):
    from plaidnox_sast.models import Depth, ModelTier, RouteDecision

    (sample_repo / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/reports', async (req, res) => {\n"
        "  return html_to_pdf.generatePdf({ content: req.body.name });\n"
        "});\n"
    )
    requests = [
        {"kind": "window", "path": "app.js", "symbol": "", "start_line": 1, "end_line": 1} for _ in range(7)
    ]
    first_round = review_payload(
        supported=False,
        rejection_reason="Evidence gap: still need more context.",
        evidence_gaps=["Still need more context."],
        evidence_locations=[],
        context_requests=requests,
    )
    client = QueueClient([first_round, review_payload()])
    route = RouteDecision(
        depth=Depth.DEEP,
        reason="test",
        model_tier=ModelTier.DEEP,
        needs_cross_file="likely",
        needs_state_reconstruction="likely",
        needs_external_semantics="yes",
        needs_environment_context="yes",
    )

    PlaidNoxDeepHuntAgent(client).hunt(sample_repo, deep_candidate(), finding(), route=route)

    second_request_payload = json.loads(client.responses.requests[1]["input"][1]["content"])
    assert len(second_request_payload["context_expansions"]) == 7


def test_resolve_context_request_paginates_callers_and_reports_truncation():
    from plaidnox_sast.ai import _resolve_context_request
    from plaidnox_sast.graph import Call, StructuralGraph

    calls = [Call(caller=f"caller_{i}", callee="target", path="app.js", line=i) for i in range(25)]
    graph = StructuralGraph(calls=calls)

    first_page = _resolve_context_request(
        None, graph, {"kind": "callers", "symbol": "target", "path": "", "start_line": 1, "end_line": 1, "offset": 0}
    )

    assert first_page["resolved"] is True
    assert first_page["total"] == 25
    assert first_page["returned"] == 20
    assert first_page["truncated"] is True
    assert len(first_page["edges"]) == 20

    second_page = _resolve_context_request(
        None,
        graph,
        {"kind": "callers", "symbol": "target", "path": "", "start_line": 1, "end_line": 1, "offset": 20},
    )

    assert second_page["resolved"] is True
    assert second_page["returned"] == 5
    assert second_page["truncated"] is False
    assert len(second_page["edges"]) == 5


def test_resolve_context_request_route_reports_not_truncated_when_all_results_fit():
    from plaidnox_sast.ai import _resolve_context_request
    from plaidnox_sast.graph import StructuralGraph, Symbol

    routes = [Symbol(name="listReports", path="app.js", line=3)]
    graph = StructuralGraph(routes=routes)

    result = _resolve_context_request(
        None,
        graph,
        {"kind": "route", "symbol": "listReports", "path": "", "start_line": 1, "end_line": 1, "offset": 0},
    )

    assert result["resolved"] is True
    assert result["total"] == 1
    assert result["truncated"] is False


def _obligation_plan():
    return HuntPlan(
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
                coverage_obligations=["Confirm an ownership check guards the object lookup."],
            )
        ],
    )


def _obligation_context():
    return AIRepositoryContext("org/repo", "abc", "Fixture", [], [], ["app.js"], 0, 0)


def test_create_search_plan_requires_every_coverage_obligation_to_be_referenced():
    client = SchemaClient(
        {
            "plaidnox_search_query_plan": {
                "strategy": "Find request-controlled object lookups.",
                "queries": [
                    {
                        "query_id": "user-lookup",
                        "task_ids": ["task-user-lookup"],
                        "pattern": "findById|req\\.params",
                        "include_globs": ["*.js"],
                        "objective": "Locate attacker-controlled identifiers and object lookup operations.",
                        "direction": "forward",
                        "purpose": "origin",
                        "coverage_refs": [],
                    }
                ],
                "coverage_notes": "The task is covered by source and sink searches.",
            }
        }
    )
    agent = PlaidNoxDeepHuntAgent(client)

    with pytest.raises(AIResponseError, match="did not cover every coverage obligation"):
        agent._create_search_plan(_obligation_context(), _obligation_plan())


def test_create_search_plan_rejects_an_unknown_coverage_ref():
    client = SchemaClient(
        {
            "plaidnox_search_query_plan": {
                "strategy": "Find request-controlled object lookups.",
                "queries": [
                    {
                        "query_id": "user-lookup",
                        "task_ids": ["task-user-lookup"],
                        "pattern": "findById|req\\.params",
                        "include_globs": ["*.js"],
                        "objective": "Locate attacker-controlled identifiers and object lookup operations.",
                        "direction": "forward",
                        "purpose": "origin",
                        "coverage_refs": ["not-a-real-ref"],
                    }
                ],
                "coverage_notes": "The task is covered by source and sink searches.",
            }
        }
    )
    agent = PlaidNoxDeepHuntAgent(client)

    with pytest.raises(AIResponseError, match="unknown coverage obligation"):
        agent._create_search_plan(_obligation_context(), _obligation_plan())


def test_create_search_plan_succeeds_when_every_coverage_obligation_is_referenced():
    client = SchemaClient(
        {
            "plaidnox_search_query_plan": {
                "strategy": "Find request-controlled object lookups.",
                "queries": [
                    {
                        "query_id": "user-lookup",
                        "task_ids": ["task-user-lookup"],
                        "pattern": "findById|req\\.params",
                        "include_globs": ["*.js"],
                        "objective": "Locate attacker-controlled identifiers and object lookup operations.",
                        "direction": "forward",
                        "purpose": "origin",
                        "coverage_refs": ["task-user-lookup::obligation::0"],
                    }
                ],
                "coverage_notes": "The task is covered by source and sink searches.",
            }
        }
    )
    agent = PlaidNoxDeepHuntAgent(client)

    queries = agent._create_search_plan(_obligation_context(), _obligation_plan())

    assert len(queries) == 1
    assert queries[0]["coverage_refs"] == ["task-user-lookup::obligation::0"]


def test_balanced_area_sample_returns_everything_when_under_the_limit():
    from plaidnox_sast.ai import _balanced_area_sample
    from plaidnox_sast.graph import Symbol

    items = [Symbol(name="a", path="area_a/one.js", line=1), Symbol(name="b", path="area_b/one.js", line=1)]

    selected, truncated_areas = _balanced_area_sample(items, 5, lambda item: item.path)

    assert selected == items
    assert truncated_areas == []


def test_balanced_area_sample_round_robins_instead_of_starving_later_areas():
    from plaidnox_sast.ai import _balanced_area_sample
    from plaidnox_sast.graph import Symbol

    items = [
        Symbol(name="a1", path="area_a/one.js", line=1),
        Symbol(name="a2", path="area_a/two.js", line=1),
        Symbol(name="a3", path="area_a/three.js", line=1),
        Symbol(name="b1", path="area_b/one.js", line=1),
        Symbol(name="c1", path="area_c/one.js", line=1),
    ]

    selected, truncated_areas = _balanced_area_sample(items, 3, lambda item: item.path)

    selected_areas = {item.path.split("/")[0] for item in selected}
    assert selected_areas == {"area_a", "area_b", "area_c"}
    assert truncated_areas == ["area_a"]


def test_build_repository_context_reports_sampling_truncation_by_area(sample_repo, monkeypatch):
    import plaidnox_sast.ai as ai_module
    from plaidnox_sast.assets import load_json as real_load_json
    from plaidnox_sast.graph import Symbol

    def patched_load_json(name):
        data = real_load_json(name)
        if name == "runtime/agent.json":
            data = dict(data)
            data["repository_route_limit"] = 2
        return data

    monkeypatch.setattr(ai_module, "load_json", patched_load_json)

    client = SchemaClient(
        {
            "plaidnox_recon_search_plan": {
                "strategy": "Inspect the observed application.",
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
            },
        }
    )
    agent = PlaidNoxDeepHuntAgent(client)
    graph = build_structural_graph(sample_repo, False)
    graph.routes = [
        Symbol(name="a1", path="area_a/one.js", line=1),
        Symbol(name="a2", path="area_a/two.js", line=1),
        Symbol(name="b1", path="area_b/one.js", line=1),
    ]

    agent.build_repository_context(sample_repo, "org/repo", "abc123", graph)

    repository_context_request = next(
        request
        for request in client.responses.requests
        if request["text"]["format"]["name"] == "plaidnox_repository_context"
    )
    payload = json.loads(repository_context_request["input"][1]["content"])
    coverage = payload["repository_context_coverage"]["routes"]

    assert coverage["total"] == 3
    assert coverage["included"] == 2
    assert coverage["truncated"] is True
    assert coverage["areas_with_omitted_context"] == ["area_a"]


def test_candidate_from_ai_item_does_not_require_a_confirmed_field(sample_repo):
    from plaidnox_sast.ai import _candidate_from_ai_item

    (sample_repo / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/reports', async (req, res) => {\n"
        "  return html_to_pdf.generatePdf({ content: req.body.name });\n"
        "});\n"
    )
    item = {
        "title": "Unresolved SSRF hypothesis",
        "vulnerability_class": "CWE-918",
        "classification_references": [],
        "business_impact": "An attacker may reach internal services.",
        "severity": "high",
        "confidence": 0.4,
        "category": "ssrf",
        "path": "app.js",
        "start_line": 4,
        "end_line": 4,
        "message": "Request-controlled content reaches the PDF renderer.",
        "attack_path": "request body -> html_to_pdf.generatePdf",
    }
    segment = {"path": "app.js", "start_line": 1, "end_line": 5}

    candidate = _candidate_from_ai_item(sample_repo, item, segment)

    assert candidate is not None
    assert candidate.title == "Unresolved SSRF hypothesis"


def test_candidate_from_ai_item_does_not_populate_a_remediation_metadata_key(sample_repo):
    from plaidnox_sast.ai import _candidate_from_ai_item

    (sample_repo / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/reports', async (req, res) => {\n"
        "  return html_to_pdf.generatePdf({ content: req.body.name });\n"
        "});\n"
    )
    item = {
        "title": "Unresolved SSRF hypothesis",
        "vulnerability_class": "CWE-918",
        "classification_references": [],
        "business_impact": "An attacker may reach internal services.",
        "severity": "high",
        "confidence": 0.4,
        "category": "ssrf",
        "path": "app.js",
        "start_line": 4,
        "end_line": 4,
        "message": "Request-controlled content reaches the PDF renderer.",
        "attack_path": "request body -> html_to_pdf.generatePdf",
    }
    segment = {"path": "app.js", "start_line": 1, "end_line": 5}

    candidate = _candidate_from_ai_item(sample_repo, item, segment)

    assert candidate is not None
    assert "ai_remediation" not in candidate.metadata


def _empty_context_request(**overrides):
    request = {"kind": "", "path": "", "symbol": "", "start_line": 1, "end_line": 1, "offset": 0, "pattern": "", "query": ""}
    request.update(overrides)
    return request


def test_resolve_context_request_sibling_handlers_excludes_the_requested_route_and_paginates():
    from plaidnox_sast.ai import _resolve_context_request
    from plaidnox_sast.graph import StructuralGraph, Symbol

    routes = [Symbol(name="signin", path="app.js", line=1)] + [
        Symbol(name=f"handler_{i}", path="app.js", line=i + 2) for i in range(21)
    ]
    graph = StructuralGraph(routes=routes)

    result = _resolve_context_request(
        None, graph, _empty_context_request(kind="sibling_handlers", path="app.js", symbol="signin")
    )

    assert result["resolved"] is True
    assert result["total"] == 21
    assert result["returned"] == 20
    assert result["truncated"] is True
    assert all(route["name"] != "signin" for route in result["routes"])


def test_resolve_context_request_sibling_handlers_reports_unresolved_when_no_siblings_exist():
    from plaidnox_sast.ai import _resolve_context_request
    from plaidnox_sast.graph import StructuralGraph, Symbol

    graph = StructuralGraph(routes=[Symbol(name="signin", path="app.js", line=1)])

    result = _resolve_context_request(
        None, graph, _empty_context_request(kind="sibling_handlers", path="app.js", symbol="signin")
    )

    assert result["resolved"] is False


def test_resolve_context_request_search_finds_matches_in_the_repository(sample_repo):
    from plaidnox_sast.ai import _resolve_context_request

    result = _resolve_context_request(
        sample_repo, None, _empty_context_request(kind="search", pattern="jwt.decode")
    )

    assert result["resolved"] is True
    assert result["total"] >= 1
    assert result["matches"][0]["path"] == "app.js"
    assert result["truncated"] is False


def test_resolve_context_request_search_reports_unresolved_for_an_empty_pattern(sample_repo):
    from plaidnox_sast.ai import _resolve_context_request

    result = _resolve_context_request(sample_repo, None, _empty_context_request(kind="search", pattern=""))

    assert result["resolved"] is False


def test_resolve_context_request_search_reports_unresolved_when_nothing_matches(sample_repo):
    from plaidnox_sast.ai import _resolve_context_request

    result = _resolve_context_request(
        sample_repo, None, _empty_context_request(kind="search", pattern="this_pattern_does_not_exist_anywhere")
    )

    assert result["resolved"] is False


def test_resolve_context_request_knowledge_returns_stored_entries(tmp_path):
    from plaidnox_sast.ai import _resolve_context_request
    from plaidnox_sast.knowledge import KnowledgeEntry, KnowledgeStore

    store = KnowledgeStore(tmp_path / "knowledge.sqlite3")
    store.upsert(
        KnowledgeEntry(
            topic="JWT signature bypass",
            content="Verify the algorithm is allow-listed before trusting a decoded JWT payload.",
            vulnerability_class="CWE-347",
        )
    )

    result = _resolve_context_request(
        None,
        None,
        _empty_context_request(kind="knowledge", query="JWT signature bypass"),
        knowledge_store=store,
    )

    assert result["resolved"] is True
    assert result["entries"][0]["topic"] == "JWT signature bypass"


def test_resolve_context_request_knowledge_reports_unresolved_without_a_configured_store():
    from plaidnox_sast.ai import _resolve_context_request

    result = _resolve_context_request(
        None, None, _empty_context_request(kind="knowledge", query="JWT signature bypass"), knowledge_store=None
    )

    assert result["resolved"] is False


def test_resolve_context_request_knowledge_reports_unresolved_for_an_empty_query(tmp_path):
    from plaidnox_sast.ai import _resolve_context_request
    from plaidnox_sast.knowledge import KnowledgeStore

    store = KnowledgeStore(tmp_path / "knowledge.sqlite3")

    result = _resolve_context_request(
        None, None, _empty_context_request(kind="knowledge", query=""), knowledge_store=store
    )

    assert result["resolved"] is False


def _referenceable_context():
    return AIRepositoryContext(
        "org/repo",
        "abc",
        "Fixture",
        [],
        [{"path": "app.js", "language": "js", "lines": 10}],
        ["app.js"],
        0,
        0,
        sensitive_effects=[{"effect_id": "effect-1", "effect_type": "db_write", "location": "app.js:4"}],
        authentication_paths=[{"name": "signin-flow", "entry_points": ["POST /signin"], "identity_source": "jwt"}],
    )


def _referenceable_task(**overrides):
    fields = {
        "task_id": "task-1",
        "title": "Review signin",
        "objective": "Trace the signin flow.",
        "focus_paths": ["app.js"],
        "entry_points": ["POST /signin"],
        "vulnerability_themes": ["authentication"],
        "evidence_requirements": ["source and controls"],
        "knowledge_queries": [],
        "knowledge_context": [],
        "inventory_refs": [],
        "sensitive_effect_refs": [],
        "authentication_path_refs": [],
    }
    fields.update(overrides)
    return HuntTask(**fields)


def test_validate_hunt_plan_references_accepts_refs_present_in_the_repository_context():
    from plaidnox_sast.ai import _validate_hunt_plan_references

    task = _referenceable_task(
        inventory_refs=["app.js"],
        sensitive_effect_refs=["effect-1"],
        authentication_path_refs=["signin-flow"],
    )

    _validate_hunt_plan_references(_referenceable_context(), [task])


def test_validate_hunt_plan_references_resolves_directory_and_relative_refs_to_inventory_files():
    from plaidnox_sast.ai import _validate_hunt_plan_references

    context = _referenceable_context()
    context.source_inventory = [
        {"path": "app.js", "language": "js", "lines": 10},
        {"path": "views/read.ejs", "language": "ejs", "lines": 5},
        {"path": "views/flag.ejs", "language": "ejs", "lines": 5},
    ]
    task = _referenceable_task(inventory_refs=["views", "./app.js", "views/"])

    _validate_hunt_plan_references(context, [task])

    assert task.inventory_refs == ["views/flag.ejs", "views/read.ejs", "app.js"]


def test_validate_hunt_plan_references_rejects_a_directory_with_no_inventory_files():
    from plaidnox_sast.ai import _validate_hunt_plan_references

    task = _referenceable_task(inventory_refs=["views"])

    with pytest.raises(AIResponseError, match="inventory path not in the repository context"):
        _validate_hunt_plan_references(_referenceable_context(), [task])


def test_validate_hunt_plan_references_rejects_an_unknown_inventory_ref():
    from plaidnox_sast.ai import _validate_hunt_plan_references

    task = _referenceable_task(inventory_refs=["not-a-real-file.js"])

    with pytest.raises(AIResponseError, match="unknown inventory path|inventory path not in the repository context"):
        _validate_hunt_plan_references(_referenceable_context(), [task])


def test_validate_hunt_plan_references_rejects_an_unknown_sensitive_effect_ref():
    from plaidnox_sast.ai import _validate_hunt_plan_references

    task = _referenceable_task(sensitive_effect_refs=["not-a-real-effect"])

    with pytest.raises(AIResponseError, match="sensitive effect not in the repository context"):
        _validate_hunt_plan_references(_referenceable_context(), [task])


def test_validate_hunt_plan_references_rejects_an_unknown_authentication_path_ref():
    from plaidnox_sast.ai import _validate_hunt_plan_references

    task = _referenceable_task(authentication_path_refs=["not-a-real-path"])

    with pytest.raises(AIResponseError, match="authentication path not in the repository context"):
        _validate_hunt_plan_references(_referenceable_context(), [task])


def test_plan_tasks_rejects_a_hunt_plan_with_a_hallucinated_inventory_ref(sample_repo):
    context = AIRepositoryContext(
        "org/repo",
        "abc",
        "Fixture",
        [],
        [{"path": "app.js", "language": "js", "lines": 10}],
        ["app.js"],
        0,
        0,
    )
    client = SchemaClient(
        {
            "plaidnox_hunt_plan": {
                "strategy": "Trace the signin flow.",
                "tasks": [
                    {
                        "task_id": "task-1",
                        "title": "Review signin",
                        "objective": "Trace the signin flow.",
                        "focus_paths": ["app.js"],
                        "entry_points": ["POST /signin"],
                        "vulnerability_themes": ["authentication"],
                        "evidence_requirements": ["source and controls"],
                        "knowledge_queries": [],
                        "inventory_refs": ["does-not-exist.js"],
                    }
                ],
            }
        }
    )
    agent = PlaidNoxDeepHuntAgent(client)

    with pytest.raises(AIResponseError, match="inventory path not in the repository context"):
        agent.plan_tasks(context)


class ScriptedResponses:
    """Returns raw answer text per schema name, consuming a script in order."""

    def __init__(self, scripts):
        self.scripts = {name: list(texts) for name, texts in scripts.items()}
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        name = kwargs["text"]["format"]["name"]
        return type("Response", (), {"status": "completed", "output_text": self.scripts[name].pop(0)})()


def _recon_plan_text() -> str:
    return json.dumps(
        {
            "strategy": "Locate Express entry points.",
            "queries": [
                {
                    "query_id": "express-entrypoints",
                    "pattern": "app\\.get",
                    "include_globs": ["*.js"],
                    "objective": "Locate Express entry points.",
                    "coverage_targets": ["application entry points"],
                }
            ],
            "coverage_notes": "One source file.",
        }
    )


_REPOSITORY_CONTEXT = {
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
}


@pytest.mark.parametrize(
    "answer",
    [
        json.dumps([_REPOSITORY_CONTEXT]),
        json.dumps({"repository_context": _REPOSITORY_CONTEXT}),
        "Context below, see [app.js] and [\"routes\"]:\n" + json.dumps(_REPOSITORY_CONTEXT),
    ],
    ids=["array", "envelope", "prose-with-brackets"],
)
def test_repository_context_reshapes_a_wrapped_answer_without_retrying(sample_repo, answer):
    (sample_repo / "app.js").write_text('const app = require("express")();\napp.get("/u", (req, res) => {});\n')
    responses = ScriptedResponses(
        {"plaidnox_recon_search_plan": [_recon_plan_text()], "plaidnox_repository_context": [answer]}
    )
    agent = PlaidNoxDeepHuntAgent(type("Client", (), {"responses": responses})(), model="test-model")

    context = agent.build_repository_context(sample_repo, "org/repo", "abc123", build_structural_graph(sample_repo))

    assert context.architecture == _REPOSITORY_CONTEXT["architecture"]
    assert context.to_dict()["applications"][0]["app_name"] == "fixture"
    assert len(responses.requests) == 2


def test_repository_context_retries_once_when_the_answer_has_the_wrong_shape(sample_repo):
    (sample_repo / "app.js").write_text('const app = require("express")();\napp.get("/u", (req, res) => {});\n')
    responses = ScriptedResponses(
        {
            "plaidnox_recon_search_plan": [_recon_plan_text()],
            "plaidnox_repository_context": [json.dumps(["app.js", "routes"]), json.dumps(_REPOSITORY_CONTEXT)],
        }
    )
    events = []
    agent = PlaidNoxDeepHuntAgent(
        type("Client", (), {"responses": responses})(), model="test-model", event_sink=events.append
    )

    context = agent.build_repository_context(sample_repo, "org/repo", "abc123", build_structural_graph(sample_repo))

    assert context.architecture == _REPOSITORY_CONTEXT["architecture"]
    assert [item["event"] for item in events].count("structured_response_shape_mismatch") == 1


def test_repository_context_still_fails_typed_after_exhausting_shape_retries(sample_repo):
    (sample_repo / "app.js").write_text('const app = require("express")();\napp.get("/u", (req, res) => {});\n')
    responses = ScriptedResponses(
        {
            "plaidnox_recon_search_plan": [_recon_plan_text()],
            "plaidnox_repository_context": [json.dumps(["app.js"]), json.dumps(["still wrong"])],
        }
    )
    agent = PlaidNoxDeepHuntAgent(type("Client", (), {"responses": responses})(), model="test-model")

    with pytest.raises(AIResponseError, match="repository context did not match"):
        agent.build_repository_context(sample_repo, "org/repo", "abc123", build_structural_graph(sample_repo))
