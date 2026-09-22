from __future__ import annotations

import json
import threading

import pytest

from plaidnox_sast.ai import (
    AIResponseError,
    AIRepositoryContext,
    HuntPlan,
    HuntTask,
    PlaidNoxDeepHuntAgent,
    load_env_file,
)
from plaidnox_sast.graph import build_structural_graph
from plaidnox_sast.models import Candidate, Evidence, Finding, FindingState, Severity


def review_payload(**overrides):
    payload = {
            "supported": True,
            "confidence": 0.91,
            "title": "Server-side request through PDF renderer",
            "vulnerability_class": "CWE-918",
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
                        "cwe": "CWE-639",
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
    assert candidates[0].vulnerability_class == "CWE-639"
    assert candidates[0].metadata["ai_discovery"] is True
    assert client.responses.requests[0]["text"]["format"]["name"] == "plaidnox_recon_search_plan"
    assert client.responses.requests[1]["text"]["format"]["name"] == "plaidnox_repository_context"
    assert client.responses.requests[2]["text"]["format"]["name"] == "plaidnox_search_query_plan"
    assert client.responses.requests[3]["text"]["format"]["name"] == "plaidnox_vulnerability_discovery"


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
