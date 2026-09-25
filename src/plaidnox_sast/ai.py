from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Protocol

from .assets import load_json
from .cache_telemetry import LiteLLMCacheTelemetry
from .context_fabric import ContextFabric, PreparedContext
from .fingerprint import CandidateIndex
from .controls import ModelUsageBudget
from .graph_context import GraphContextBroker
from .graphify_adapter import CodeGraphSnapshot, GraphifyAdapterError
from .graph_planner import GraphInvestigationPlanner, GraphPlanningError
from .errors import AIStageError
from .investigations import Investigation
from .graph import (
    RipgrepDiscovery,
    RipgrepQueryError,
    SearchHit,
    StructuralGraph,
    build_structural_graph,
    readable_source_tree,
    source_file_is_admitted,
    source_files,
)
from .checkpoint import ScanCheckpoint, candidate_from_dict, candidate_to_dict, unit_key
from .routers import (
    FRONTIER_PRIORITY_WEIGHT,
    FrontierRouter,
    ModelExecutionDecision,
    ModelExecutionRouter,
    RetryRouter,
)
from .knowledge import (
    KnowledgeCoordinator,
    KnowledgeEntry,
    KnowledgeStore,
    PerplexityKnowledgeProvider,
)
from .llm import (
    LiteLLMConfigurationError,
    LiteLLMResponsesClient,
    StructuredResponse,
    parse_structured,
    response_json,
    response_text,
)
from .models import Candidate, Evidence, Finding, ModelTier, RouteDecision, Severity
from .prompts import render_operation
from .redaction import redact as _redact
from .redaction import redact_payload
from .worksets import security_worksets_from_graph, security_worksets_from_regions


_RATE_LIMIT_ERROR_NAMES = frozenset({"RateLimitError"})


class AIConfigurationError(AIStageError):
    pass


class AIResponseError(AIStageError):
    pass


class ResponsesClient(Protocol):
    class responses:  # type: ignore[valid-type]
        @staticmethod
        def create(**kwargs: Any) -> Any: ...


@dataclass(slots=True)
class DeepHuntResult:
    supported: bool
    confidence: float
    reasoning: str
    attack_path: str
    remediation_note: str
    title: str = ""
    vulnerability_class: str = ""
    severity: str = ""
    message: str = ""
    business_impact: str = ""
    classification_references: list[dict[str, str]] = field(default_factory=list)
    falsification_attempts: list[str] | None = None
    required_preconditions: list[str] | None = None
    evidence_gaps: list[str] | None = None
    security_invariant: str = ""
    gained_capability: str = ""
    rejection_reason: str = ""
    gate_results: list[dict[str, Any]] = field(default_factory=list)
    evidence_locations: list[dict[str, Any]] = field(default_factory=list)
    proof_plan: str = ""
    regression_test: str = ""
    context_requests: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PatchProposal:
    """An AI-proposed unified diff remediating one already-verified finding."""

    proposed: bool
    patch: str
    summary: str
    files_changed: list[str]
    risk_notes: str
    confidence: float
    rejection_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PatchVerification:
    """Result of applying a proposed patch to an ephemeral repository copy and rescanning it."""

    applied: bool
    verified: bool
    reason: str = ""
    rescan_supported: bool | None = None
    rescan_confidence: float | None = None
    unexpected_failure: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AIRepositoryContext:
    """First-scan context retained with the report and reused for AI discovery."""

    codebase: str
    revision: str
    architecture: str
    applications: list[dict[str, Any]]
    source_inventory: list[dict[str, Any]]
    source_tree: list[str]
    graph_symbols: int
    graph_routes: int
    security_ir: list[dict[str, Any]] = field(default_factory=list)
    business_context: str = ""
    context_fabric: dict[str, Any] = field(default_factory=dict)
    actors: list[dict[str, Any]] = field(default_factory=list)
    sensitive_assets: list[dict[str, Any]] = field(default_factory=list)
    input_surfaces: list[dict[str, Any]] = field(default_factory=list)
    trust_boundaries: list[dict[str, Any]] = field(default_factory=list)
    security_invariants: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    production_areas: list[dict[str, Any]] = field(default_factory=list)
    entry_points: list[dict[str, Any]] = field(default_factory=list)
    sensitive_effects: list[dict[str, Any]] = field(default_factory=list)
    authentication_paths: list[dict[str, Any]] = field(default_factory=list)
    authorization_decisions: list[dict[str, Any]] = field(default_factory=list)
    indirect_dispatch: list[dict[str, Any]] = field(default_factory=list)
    build_time_variants: list[dict[str, Any]] = field(default_factory=list)
    coverage_ledger: list[dict[str, Any]] = field(default_factory=list)
    analysis_scope_paths: list[str] = field(default_factory=list)
    annotation_grounding: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "codebase": self.codebase,
            "revision": self.revision,
            "architecture": self.architecture,
            "applications": self.applications,
            "source_inventory": self.source_inventory,
            "source_tree": self.source_tree,
            "graph_symbols": self.graph_symbols,
            "graph_routes": self.graph_routes,
            "security_ir": self.security_ir,
            "business_context": self.business_context,
            "context_fabric": self.context_fabric,
            "actors": self.actors,
            "sensitive_assets": self.sensitive_assets,
            "input_surfaces": self.input_surfaces,
            "trust_boundaries": self.trust_boundaries,
            "security_invariants": self.security_invariants,
            "coverage_gaps": self.coverage_gaps,
            "production_areas": self.production_areas,
            "entry_points": self.entry_points,
            "sensitive_effects": self.sensitive_effects,
            "authentication_paths": self.authentication_paths,
            "authorization_decisions": self.authorization_decisions,
            "indirect_dispatch": self.indirect_dispatch,
            "build_time_variants": self.build_time_variants,
            "coverage_ledger": self.coverage_ledger,
            "analysis_scope_paths": self.analysis_scope_paths,
            "annotation_grounding": self.annotation_grounding,
        }


@dataclass(slots=True)
class HuntTask:
    task_id: str
    title: str
    objective: str
    focus_paths: list[str]
    entry_points: list[str]
    vulnerability_themes: list[str]
    evidence_requirements: list[str]
    knowledge_queries: list[str]
    knowledge_context: list[dict[str, Any]]
    business_invariants: list[str] = field(default_factory=list)
    coverage_obligations: list[str] = field(default_factory=list)
    falsification_requirements: list[str] = field(default_factory=list)
    inventory_refs: list[str] = field(default_factory=list)
    sensitive_effect_refs: list[str] = field(default_factory=list)
    authentication_path_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HuntPlan:
    plan_id: str
    strategy: str
    tasks: list[HuntTask]

    def to_dict(self) -> dict[str, Any]:
        return {"plan_id": self.plan_id, "strategy": self.strategy, "tasks": [task.to_dict() for task in self.tasks]}


class PlaidNoxDeepHuntAgent:
    """PlaidNox-owned attacker-first deep-hunt agent.

    It is intentionally implemented against the Responses API and our strict
    evidence schema. The methodology is inspired by public attacker-first
    research, but this is a separate implementation with no vendored runtime
    or prompts.
    """

    def __init__(
        self,
        client: ResponsesClient,
        model: str | None = None,
        max_output_tokens: int | None = None,
        knowledge_coordinator: KnowledgeCoordinator | None = None,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
        cache_telemetry: LiteLLMCacheTelemetry | None = None,
        context_store: ContextFabric | None = None,
        frontier_router: FrontierRouter | None = None,
        retry_router: RetryRouter | None = None,
        model_execution_router: ModelExecutionRouter | None = None,
        model_budget: ModelUsageBudget | None = None,
    ) -> None:
        self.client = client
        model_runtime = load_json("runtime/models.json")
        self.model = model or str(model_runtime["agent_default_model"])
        self.model_by_tier: dict[str, str] = {
            str(tier): str(name)
            for tier, name in model_runtime["agent_fallback_model_by_tier"].items()
        }
        configured_output_limit = int(model_runtime["agent_default_max_output_tokens"])
        self.max_output_tokens = (
            int(max_output_tokens) if max_output_tokens is not None else configured_output_limit
        )
        self.knowledge_coordinator = knowledge_coordinator
        self.event_sink = event_sink
        self.cache_telemetry = cache_telemetry or LiteLLMCacheTelemetry()
        self.context_store = context_store
        self.frontier_router = frontier_router or FrontierRouter()
        self.retry_router = retry_router or RetryRouter()
        self.checkpoint: ScanCheckpoint | None = None
        # Compatibility hook for integrations predating canonical pre-verification merging.
        self.candidate_sink: Callable[[Candidate], None] | None = None
        self.model_execution_router = model_execution_router or ModelExecutionRouter()
        self.model_budget = model_budget or ModelUsageBudget()
        self.discovery_error_types: list[str] = []
        self.discovery_errors: list[str] = []
        self.security_graph: StructuralGraph | None = None
        self.source_excludes: list[str] = []
        self.max_file_bytes: int | None = None
        self._model_input_audit: list[dict[str, Any]] = []
        self._model_execution_routes: dict[str, ModelExecutionDecision] = {}
        self.search_query_errors: list[dict[str, Any]] = []
        self.knowledge_errors: list[dict[str, str]] = []
        self.discovery_metrics: dict[str, int | float] = {}
        self.discovery_unresolved_obligations = 0
        self.discovery_required_coverage_unresolved = 0
        self.rate_limit_waits = 0
        self._telemetry_lock = threading.Lock()

    @classmethod
    def from_environment(
        cls,
        model: str | None = None,
        max_output_tokens: int | None = None,
    ) -> PlaidNoxDeepHuntAgent:
        try:
            selected_model = model or str(load_json("runtime/models.json")["agent_default_model"])
            client = LiteLLMResponsesClient.from_environment(selected_model)
        except LiteLLMConfigurationError as exc:
            raise AIConfigurationError(str(exc)) from exc
        return cls(
            client,
            model=selected_model,
            max_output_tokens=max_output_tokens,
        )

    def set_event_sink(self, sink: Callable[[dict[str, Any]], None]) -> None:
        self.event_sink = sink

    def _emit(self, event: str, **details: Any) -> None:
        if self.event_sink is not None:
            self.event_sink({"event": event, **details})

    def configure_knowledge(self, coordinator: KnowledgeCoordinator) -> None:
        self.knowledge_coordinator = coordinator

    def configure_context_fabric(self, store: ContextFabric) -> None:
        self.context_store = store

    def configure_capability_frontier(self, router: FrontierRouter) -> None:
        self.frontier_router = router

    def configure_checkpoint(self, checkpoint: ScanCheckpoint | None) -> None:
        self.checkpoint = checkpoint

    def configure_retry_route(self, router: RetryRouter) -> None:
        self.retry_router = router

    def configure_model_execution_route(self, router: ModelExecutionRouter) -> None:
        self.model_execution_router = router
        self._model_execution_routes.clear()

    def configure_source_policy(self, exclude: list[str], max_file_bytes: int) -> None:
        self.source_excludes = list(exclude)
        self.max_file_bytes = max_file_bytes

    def configure_security_graph(self, graph: StructuralGraph) -> None:
        """Provide a snapshot-local Security IR for targeted context expansion."""

        self.security_graph = graph

    def _record_search_query_errors(
        self,
        phase: str,
        context: AIRepositoryContext | None,
        errors: list[RipgrepQueryError],
    ) -> None:
        for error in errors:
            record = {"phase": phase, **error.to_dict()}
            self.search_query_errors.append(record)
            gap = (
                f"{phase} query {error.query_id} could not execute; "
                f"query terms {error.pattern_hash[:12]} remain an unresolved coverage obligation"
            )
            if context is not None and gap not in context.coverage_gaps:
                context.coverage_gaps.append(gap)
            self._emit("ripgrep_query_failed", **record)

    def prompt_cache_metrics(self) -> dict[str, int | float]:
        return self.cache_telemetry.snapshot().to_metrics()

    def model_input_audit(self) -> list[dict[str, Any]]:
        """Return content-free hashes and sizes for each generative request."""

        return [dict(item) for item in self._model_input_audit]

    def reset_model_input_audit(self) -> None:
        """Start a new scan-scoped model-input audit."""

        self._model_input_audit.clear()
        self._model_execution_routes.clear()
        self.rate_limit_waits = 0

    def reset_search_query_errors(self) -> None:
        """Start a new scan-scoped AI search-query audit."""

        self.search_query_errors.clear()

    def reset_model_budget(self) -> None:
        self.model_budget.reset()

    def model_budget_metrics(self) -> dict[str, int | float]:
        return self.model_budget.metrics()

    def model_input_metrics(self) -> dict[str, int]:
        return {
            "model_input_calls": len(self._model_input_audit),
            "model_input_characters": sum(int(item["payload_characters"]) for item in self._model_input_audit),
            "model_source_context_characters": sum(
                int(item["source_context_characters"]) for item in self._model_input_audit
            ),
            "model_calls_with_repository_wide_context": sum(
                int(bool(item["repository_wide_context"])) for item in self._model_input_audit
            ),
            "rate_limit_waits": self.rate_limit_waits,
        }

    def web_knowledge_provider(self) -> PerplexityKnowledgeProvider:
        return PerplexityKnowledgeProvider.from_environment(self.model_budget)

    def hunt(
        self,
        root: Path,
        candidate: Candidate,
        finding: Finding,
        security_context: str = "",
        model_tier: ModelTier | None = None,
        route: RouteDecision | None = None,
    ) -> DeepHuntResult:
        self._emit(
            "candidate_verification_started",
            rule_id=candidate.rule_id,
            path=candidate.evidence.path,
            line=candidate.evidence.start_line,
        )
        metadata_only = bool(candidate.metadata.get("sensitive_evidence") or candidate.metadata.get("content_read") is False)
        runtime = load_json("runtime/agent.json")
        max_rounds = int(runtime["context_expansion_max_rounds"])
        max_requests = _context_expansion_max_requests(runtime, route)
        reasoning_effort_override = _hunt_effort_override(route)
        context_expansions: list[dict[str, Any]] = []
        confidence_history: list[float] = []
        review: DeepHuntResult | None = None
        for round_index in range(max_rounds + 1):
            review = self._run_hunt_round(
                root,
                candidate,
                finding,
                security_context,
                metadata_only,
                runtime,
                context_expansions,
                model_tier,
                reasoning_effort_override,
            )
            confidence_history.append(review.confidence)
            if metadata_only and review.context_requests:
                raise AIResponseError("Metadata-only review requested on-demand source or Security IR expansion")
            if round_index >= max_rounds or not review.context_requests:
                break
            self._emit(
                "candidate_context_expansion_requested",
                rule_id=candidate.rule_id,
                requests=len(review.context_requests),
                round=round_index + 1,
            )
            for request in review.context_requests[:max_requests]:
                context_expansions.append(
                    _resolve_context_request(
                        root,
                        self.security_graph,
                        request,
                        source_excludes=self.source_excludes,
                        max_file_bytes=self.max_file_bytes,
                        knowledge_store=self.knowledge_coordinator.store if self.knowledge_coordinator else None,
                    )
                )
        if not metadata_only and review.context_requests:
            review = self._apply_retry_route(
                root,
                candidate,
                finding,
                security_context,
                runtime,
                context_expansions,
                model_tier,
                reasoning_effort_override,
                review,
                confidence_history,
                max_requests,
            )
        self._emit(
            "candidate_verification_completed",
            rule_id=candidate.rule_id,
            path=candidate.evidence.path,
            supported=review.supported,
            confidence=review.confidence,
        )
        return review

    def _run_hunt_round(
        self,
        root: Path,
        candidate: Candidate,
        finding: Finding,
        security_context: str,
        metadata_only: bool,
        runtime: dict[str, Any],
        context_expansions: list[dict[str, Any]],
        model_tier: ModelTier | None,
        reasoning_effort_override: str | None,
    ) -> DeepHuntResult:
        code_window = "[contents intentionally unavailable]" if metadata_only else _source_window(
            root,
            candidate.evidence.path,
            candidate.evidence.start_line,
            candidate.evidence.end_line,
            exclude=self.source_excludes,
            max_file_bytes=self.max_file_bytes,
        )
        evidence = {
            "rule_id": candidate.rule_id,
            "title": candidate.title,
            "vulnerability_class": candidate.vulnerability_class,
            "message": candidate.message,
            "candidate_confidence": candidate.confidence,
            "finding_impact": finding.impact,
            "graph_path": candidate.evidence.graph_path,
            "discovery_evidence_basis": candidate.metadata.get("evidence_basis", {}),
            "candidate_evidence_packet": candidate.metadata.get("evidence_packet", {}),
            "security_ir_context": {} if metadata_only else _security_ir_context(
                self.security_graph,
                candidate.evidence.path,
                candidate.evidence.start_line,
            ),
            "source_window": code_window,
            "context_expansions": context_expansions,
            "protected_security_context": _redact(
                security_context[: int(runtime["security_context_characters"])]
            ),
            "metadata_only": metadata_only,
        }
        response = self._structured_response(
            "plaidnox_security_review",
            load_json("schemas/deep_hunt_review.json"),
            "metadata_exposure_review" if metadata_only else "security_review",
            evidence,
            model_tier=model_tier,
            reasoning_effort_override=reasoning_effort_override,
        )
        review = _deep_hunt_result_from_response(response)
        _validate_deep_hunt_result(
            root,
            candidate,
            review,
            metadata_only=metadata_only,
            evidence_paths=_evidence_paths(
                candidate, context_expansions, evidence["protected_security_context"]
            ),
        )
        return review

    def _apply_retry_route(
        self,
        root: Path,
        candidate: Candidate,
        finding: Finding,
        security_context: str,
        runtime: dict[str, Any],
        context_expansions: list[dict[str, Any]],
        model_tier: ModelTier | None,
        reasoning_effort_override: str | None,
        review: DeepHuntResult,
        confidence_history: list[float],
        max_requests: int,
    ) -> DeepHuntResult:
        """Decide, exactly once, whether a single bounded extra round is warranted after the
        normal context-expansion budget is exhausted and a genuine evidence gap remains."""
        decision = self.retry_router.decide(_retry_facts(review, model_tier, context_expansions, confidence_history))
        self._emit(
            "candidate_retry_routed",
            rule_id=candidate.rule_id,
            action=decision.action,
            reason=decision.reason,
        )
        if decision.action == "mark_unresolved":
            return review
        retry_model_tier = ModelTier.DEEP if decision.action == "escalate_model" else model_tier
        retry_effort_override = "high" if decision.action == "escalate_model" else reasoning_effort_override
        if decision.action == "expand_context":
            for request in review.context_requests[:max_requests]:
                context_expansions.append(
                    _resolve_context_request(
                        root,
                        self.security_graph,
                        request,
                        source_excludes=self.source_excludes,
                        max_file_bytes=self.max_file_bytes,
                        knowledge_store=self.knowledge_coordinator.store if self.knowledge_coordinator else None,
                    )
                )
        return self._run_hunt_round(
            root,
            candidate,
            finding,
            security_context,
            False,
            runtime,
            context_expansions,
            retry_model_tier,
            retry_effort_override,
        )

    # Compatibility with integrations built before the dedicated Deep Hunt name.
    def review(
        self,
        root: Path,
        candidate: Candidate,
        finding: Finding,
        security_context: str = "",
        model_tier: ModelTier | None = None,
        route: RouteDecision | None = None,
    ) -> AIReview:
        return self.hunt(root, candidate, finding, security_context, model_tier=model_tier, route=route)

    def propose_patch(
        self,
        root: Path,
        finding: Finding,
        model_tier: ModelTier | None = None,
    ) -> PatchProposal:
        """Propose the smallest safe unified diff remediating an already-verified finding."""
        self._emit("patch_proposal_started", fingerprint=finding.fingerprint, path=finding.evidence.path)
        deep_hunt = finding.metadata.get("deep_hunt", {})
        evidence_locations = list(deep_hunt.get("evidence_locations", [])) or [
            {
                "path": finding.evidence.path,
                "start_line": finding.evidence.start_line,
                "end_line": finding.evidence.end_line,
                "role": "origin",
            }
        ]
        sources = [
            {
                "path": str(location.get("path", finding.evidence.path)),
                "start_line": int(location.get("start_line", finding.evidence.start_line) or 1),
                "end_line": int(location.get("end_line", finding.evidence.start_line) or 1),
                "role": str(location.get("role", "")),
                "content": _source_window(
                    root,
                    str(location.get("path", finding.evidence.path)),
                    int(location.get("start_line", finding.evidence.start_line) or 1),
                    int(location.get("end_line", finding.evidence.start_line) or 1),
                    exclude=self.source_excludes,
                    max_file_bytes=self.max_file_bytes,
                ),
            }
            for location in evidence_locations
        ]
        payload = {
            "title": finding.title,
            "vulnerability_class": finding.vulnerability_class,
            "severity": finding.severity.value,
            "message": finding.message,
            "business_impact": finding.impact,
            "attack_path": str(deep_hunt.get("attack_path", "")),
            "security_invariant": str(deep_hunt.get("security_invariant", "")),
            "remediation_note": str(deep_hunt.get("remediation_note", finding.remediation)),
            "proof_plan": str(deep_hunt.get("proof_plan", "")),
            "regression_test": str(deep_hunt.get("regression_test", "")),
            "evidence_sources": sources,
        }
        response = self._structured_response(
            "plaidnox_patch_proposal",
            load_json("schemas/patch_proposal.json"),
            "patch_proposal",
            payload,
            model_tier=model_tier,
        )
        proposal = _patch_proposal_from_response(response)
        _validate_patch_proposal(root, proposal)
        self._emit(
            "patch_proposal_completed",
            fingerprint=finding.fingerprint,
            proposed=proposal.proposed,
            files_changed=len(proposal.files_changed),
        )
        return proposal

    def verify_patch(
        self,
        root: Path,
        finding: Finding,
        proposal: PatchProposal,
        security_context: str = "",
        model_tier: ModelTier | None = None,
    ) -> PatchVerification:
        """Apply a proposed patch to an ephemeral repository copy and rescan it; never writes to `root`."""
        if not proposal.proposed:
            return PatchVerification(applied=False, verified=False, reason="no patch was proposed")
        self._emit("patch_verification_started", fingerprint=finding.fingerprint)
        with tempfile.TemporaryDirectory(prefix="plaidnox-patch-") as workspace:
            tmp_root = Path(workspace) / "snapshot"
            shutil.copytree(root, tmp_root)
            result = subprocess.run(
                ["patch", "-p1", "--forward", "--batch", "--no-backup-if-mismatch"],
                cwd=tmp_root,
                input=proposal.patch,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                self._emit("patch_verification_apply_failed", fingerprint=finding.fingerprint)
                return PatchVerification(
                    applied=False,
                    verified=False,
                    reason=f"patch did not apply cleanly: {(result.stderr or result.stdout).strip()[:400]}",
                )
            try:
                patched_graph = build_structural_graph(
                    tmp_root, exclude=self.source_excludes, max_file_bytes=self.max_file_bytes
                )
            except OSError as exc:
                return PatchVerification(
                    applied=True, verified=False, reason=f"could not analyze the patched snapshot: {exc}"
                )
            candidate = Candidate(
                rule_id=finding.rule_id,
                title=finding.title,
                vulnerability_class=finding.vulnerability_class,
                severity=finding.severity,
                confidence=finding.confidence,
                message=finding.message,
                evidence=finding.evidence,
                metadata={},
            )
            previous_graph = self.security_graph
            self.security_graph = patched_graph
            try:
                rescan = self.hunt(tmp_root, candidate, finding, security_context, model_tier=model_tier)
            except Exception as exc:  # noqa: BLE001
                unexpected = not isinstance(exc, AIStageError)
                self._emit(
                    "patch_verification_rescan_failed",
                    fingerprint=finding.fingerprint,
                    error_type=type(exc).__name__,
                )
                return PatchVerification(
                    applied=True,
                    verified=False,
                    reason=f"rescan failed: {exc}"[:400],
                    unexpected_failure=unexpected,
                )
            finally:
                self.security_graph = previous_graph
        verified = not rescan.supported
        self._emit("patch_verification_completed", fingerprint=finding.fingerprint, verified=verified)
        return PatchVerification(
            applied=True,
            verified=verified,
            reason="" if verified else "the vulnerability still verified against the patched snapshot",
            rescan_supported=rescan.supported,
            rescan_confidence=rescan.confidence,
        )

    def build_repository_context(
        self,
        root: Path,
        codebase: str,
        revision: str,
        graph: StructuralGraph,
        business_context: str = "",
    ) -> AIRepositoryContext:
        """Create a structured architecture summary before vulnerability discovery."""
        self.security_graph = graph
        inventory = _source_inventory(root, self.source_excludes, self.max_file_bytes)
        source_tree = readable_source_tree(
            root,
            exclude=self.source_excludes,
            max_file_bytes=self.max_file_bytes,
        )
        self._emit("repository_context_started", codebase=codebase, source_files=len(inventory))
        runtime = load_json("runtime/agent.json")
        context_fabric: dict[str, Any] = {}
        preparation = None
        if self.context_store is not None:
            preparation = self.context_store.prepare_snapshot(
                codebase,
                revision,
                root,
                graph,
            )
            scope_paths = _analysis_scope_paths(preparation, source_tree)
            context_fabric = {
                "context_id": preparation.current.context_id,
                "revision": preparation.current.commit,
                "symbol_count": preparation.current.symbol_count,
                "base_context_id": preparation.previous.context_id if preparation.previous else "",
                "overlay_id": preparation.overlay.overlay_id if preparation.overlay else "",
                "changed_paths": preparation.changed_paths,
                "affected_symbols": preparation.overlay.affected_symbols if preparation.overlay else [],
                "analysis_scope_paths": scope_paths,
                "context_reused_percent": (
                    preparation.overlay.context_reused_percent
                    if preparation.overlay
                    else (100 if preparation.reused else 0)
                ),
                "reused": preparation.reused,
            }
            if preparation.reused and preparation.previous_repository_context is not None:
                context = _repository_context_from_saved(
                    preparation.previous_repository_context,
                    codebase,
                    revision,
                    inventory,
                    source_tree,
                    graph,
                    context_fabric,
                )
                self.context_store.save_repository_context(
                    preparation.current.context_id,
                    codebase,
                    context.to_dict(),
                )
                self._emit(
                    "repository_context_reused",
                    codebase=codebase,
                    context_id=preparation.current.context_id,
                )
                return context

        full_security_ir = _repository_security_ir(graph, runtime)
        incremental = bool(
            preparation is not None
            and preparation.overlay is not None
            and preparation.previous_repository_context is not None
        )
        scope_paths = set(context_fabric.get("analysis_scope_paths", source_tree))
        route_pool = [item for item in graph.routes if not incremental or item.path in scope_paths]
        symbol_pool = [item for item in graph.symbols if not incremental or item.path in scope_paths]
        file_pool = [item for item in graph.files if not incremental or item.path in scope_paths]
        sampled_routes, truncated_route_areas = _balanced_area_sample(
            route_pool, int(runtime["repository_route_limit"]), lambda item: item.path
        )
        sampled_symbols, truncated_symbol_areas = _balanced_area_sample(
            symbol_pool, int(runtime["repository_symbol_limit"]), lambda item: item.path
        )
        sampled_files, truncated_file_areas = _balanced_area_sample(
            file_pool, int(runtime["repository_ir_file_limit"]), lambda item: item.path
        )
        surface_inventory = _security_surface_inventory(
            root,
            graph,
            include_paths=scope_paths if incremental else None,
        )
        manifest_inventory = (
            [item for item in inventory if str(item["path"]) in scope_paths]
            if incremental
            else inventory
        )
        manifest_tree = [path for path in source_tree if path in scope_paths] if incremental else source_tree
        manifest_ir = (
            [item for item in full_security_ir if str(item["path"]) in scope_paths]
            if incremental
            else full_security_ir
        )
        manifest = {
            "codebase": codebase,
            "revision": revision,
            "routes": [
                {"name": item.name, "path": item.path, "line": item.line} for item in sampled_routes
            ],
            "symbols": [
                {"name": item.name, "path": item.path, "line": item.line} for item in sampled_symbols
            ],
            "security_ir": [
                {
                    "path": item.path,
                    "language": item.language,
                    "symbols": [
                        {
                            "name": symbol.name,
                            "qualified_name": symbol.qualified_name or symbol.name,
                            "line": symbol.line,
                            "end_line": symbol.end_line,
                            "kind": symbol.kind,
                        }
                        for symbol in item.symbols
                    ],
                    "imports": item.imports,
                    "calls": [
                        {"caller": call.caller, "callee": call.callee, "line": call.line}
                        for call in item.calls
                    ],
                }
                for item in sampled_files
            ],
            "business_context": _redact(
                business_context[: int(runtime["business_context_characters"])]
            ),
            "context_fabric": context_fabric,
            "repository_context_coverage": {
                "routes": {
                    "included": len(sampled_routes),
                    "total": len(graph.routes),
                    "truncated": len(sampled_routes) < len(graph.routes),
                    "areas_with_omitted_context": truncated_route_areas,
                },
                "symbols": {
                    "included": len(sampled_symbols),
                    "total": len(graph.symbols),
                    "truncated": len(sampled_symbols) < len(graph.symbols),
                    "areas_with_omitted_context": truncated_symbol_areas,
                },
                "security_ir_files": {
                    "included": len(sampled_files),
                    "total": len(graph.files),
                    "truncated": len(sampled_files) < len(graph.files),
                    "areas_with_omitted_context": truncated_file_areas,
                },
                "security_surfaces": {
                    key: value
                    for key, value in surface_inventory.items()
                    if key != "surfaces"
                },
            },
            "security_surface_inventory": surface_inventory,
        }
        if incremental and preparation is not None:
            manifest.pop("security_ir", None)
            manifest["changed_source_inventory"] = manifest_inventory
            manifest["analysis_scope_tree"] = manifest_tree
            manifest["security_ir_slice"] = manifest_ir
            manifest["previous_repository_context"] = _compact_repository_context_value(
                preparation.previous_repository_context or {},
                "",
            )
            manifest["incremental_context_packet"] = (
                preparation.packet.to_dict() if preparation.packet is not None else {}
            )
        else:
            manifest["source_inventory"] = manifest_inventory
            manifest["source_tree"] = manifest_tree
        recon_queries = self._create_recon_search_plan(manifest)
        recon_errors: list[RipgrepQueryError] = []
        recon_evidence, recon_hits = _execute_recon_search_plan(
            root,
            recon_queries,
            self.source_excludes,
            self.max_file_bytes,
            include_paths=scope_paths if incremental else None,
            error_sink=recon_errors.append,
        )
        graph.search_hits.extend(recon_hits)
        graph.rg_queries += len(recon_queries)
        manifest["recon_search_plan"] = [
            {
                "query_id": str(query["query_id"]),
                "objective": str(query["objective"]),
                "coverage_targets": [str(item) for item in query["coverage_targets"]],
            }
            for query in recon_queries
        ]
        manifest["recon_search_evidence"] = recon_evidence
        response = self._structured_response(
            "plaidnox_repository_context",
            load_json("schemas/repository_context.json"),
            "repository_context",
            manifest,
        )
        try:
            payload = response_json(response)
            architecture = str(payload["architecture"])
            applications = list(payload["applications"])
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError(f"AI repository context did not match the required schema: {_schema_failure(exc)}") from exc
        grounding_summary = _ground_repository_annotations(
            payload,
            root,
            graph,
            preparation.previous_repository_context
            if preparation is not None and preparation.overlay is not None
            else None,
        )
        context = AIRepositoryContext(
            codebase=codebase,
            revision=revision,
            architecture=architecture,
            applications=applications,
            source_inventory=inventory,
            source_tree=source_tree,
            graph_symbols=len(graph.symbols),
            graph_routes=len(graph.routes),
            security_ir=full_security_ir,
            business_context=_redact(
                business_context[: int(runtime["business_context_characters"])]
            ),
            context_fabric=context_fabric,
            actors=[dict(item) for item in payload.get("actors", [])],
            sensitive_assets=[dict(item) for item in payload.get("sensitive_assets", [])],
            input_surfaces=[dict(item) for item in payload.get("input_surfaces", [])],
            trust_boundaries=[dict(item) for item in payload.get("trust_boundaries", [])],
            security_invariants=[str(item) for item in payload.get("security_invariants", [])],
            coverage_gaps=[str(item) for item in payload.get("coverage_gaps", [])],
            production_areas=[dict(item) for item in payload.get("production_areas", [])],
            entry_points=[dict(item) for item in payload.get("entry_points", [])],
            sensitive_effects=[dict(item) for item in payload.get("sensitive_effects", [])],
            authentication_paths=[dict(item) for item in payload.get("authentication_paths", [])],
            authorization_decisions=[dict(item) for item in payload.get("authorization_decisions", [])],
            indirect_dispatch=[dict(item) for item in payload.get("indirect_dispatch", [])],
            build_time_variants=[dict(item) for item in payload.get("build_time_variants", [])],
            coverage_ledger=[dict(item) for item in payload.get("coverage_ledger", [])],
            analysis_scope_paths=sorted(scope_paths) if scope_paths else source_tree,
            annotation_grounding=grounding_summary,
        )
        self._record_search_query_errors("recon", context, recon_errors)
        if self.context_store is not None and preparation is not None:
            self.context_store.save_repository_context(
                preparation.current.context_id,
                codebase,
                context.to_dict(),
            )
        self._emit("repository_context_completed", codebase=codebase, applications=len(applications))
        return context

    def _create_recon_search_plan(self, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        response = self._structured_response(
            "plaidnox_recon_search_plan",
            load_json("schemas/recon_search_plan.json"),
            "recon_search_plan",
            manifest,
        )
        try:
            payload = response_json(response)
            queries = [dict(item) for item in payload["queries"]]
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError(f"AI reconnaissance search plan did not match the required schema: {_schema_failure(exc)}") from exc
        runtime = load_json("runtime/code_intelligence.json")
        if len(queries) > int(runtime["maximum_recon_queries"]):
            raise AIResponseError("AI reconnaissance search plan exceeded the configured query limit")
        query_ids = [str(query.get("query_id", "")) for query in queries]
        if len(set(query_ids)) != len(query_ids):
            raise AIResponseError("AI reconnaissance search plan returned duplicate query identifiers")
        self._emit("recon_search_plan_generated", queries=len(queries))
        return queries

    def plan_tasks(
        self,
        context: AIRepositoryContext,
        security_context: str = "",
    ) -> HuntPlan:
        if self.knowledge_coordinator is not None:
            cached = self.knowledge_coordinator.store.load_plan(context.codebase, context.revision)
            if cached is not None:
                tasks = [_hunt_task_from_value(value) for value in cached["tasks"]]
                self._emit("hunt_plan_reused", plan_id=cached["plan_id"], tasks=len(tasks))
                return HuntPlan(str(cached["plan_id"]), str(cached["strategy"]), tasks)

        runtime = load_json("runtime/agent.json")
        request = {
            "repository_context": _compact_repository_context(context, ""),
            "protected_security_context": _redact(
                security_context[: int(runtime["security_context_characters"])]
            ),
        }
        response = self._structured_response(
            "plaidnox_hunt_plan",
            load_json("schemas/hunt_plan.json"),
            "hunt_plan",
            request,
        )
        try:
            payload = response_json(response)
            task_values = list(payload["tasks"])
            strategy = str(payload["strategy"])
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError(f"AI hunt plan did not match the required schema: {_schema_failure(exc)}") from exc

        tasks: list[HuntTask] = []
        knowledge_failures = 0
        self._emit("hunt_plan_generated", codebase=context.codebase, tasks=len(task_values))
        for value in task_values:
            task = _hunt_task_from_value(value)
            if self.knowledge_coordinator is not None:
                self._emit(
                    "knowledge_resolution_started",
                    task_id=task.task_id,
                    queries=len(task.knowledge_queries),
                )
                for query in dict.fromkeys(
                    item.strip() for item in task.knowledge_queries if item.strip()
                ):
                    try:
                        _decision, entries = self.knowledge_coordinator.resolve(
                            context.codebase,
                            context.revision,
                            {"task_id": task.task_id, "title": task.title, "vulnerability_themes": task.vulnerability_themes},
                            query,
                            {},
                        )
                    except Exception as exc:  # noqa: BLE001
                        knowledge_failures += 1
                        error = {
                            "task_id": task.task_id,
                            "query_hash": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                            "error_type": type(exc).__name__,
                            "error": _redact(str(exc)[:240]),
                        }
                        self.knowledge_errors.append(error)
                        self._emit("knowledge_resolution_failed", **error)
                        continue
                    task.knowledge_context.extend(_knowledge_excerpts(entries, _decision.action))
                task.knowledge_context = list(
                    {item["knowledge_id"]: item for item in task.knowledge_context}.values()
                )
                self._emit(
                    "knowledge_resolution_completed",
                    task_id=task.task_id,
                    entries=len(task.knowledge_context),
                )
            tasks.append(task)

        if not tasks:
            raise AIResponseError("AI hunt plan contained no investigation tasks")
        _validate_hunt_plan_references(context, tasks)
        plan_id = ""
        if self.knowledge_coordinator is not None and knowledge_failures == 0:
            plan_id = self.knowledge_coordinator.store.save_plan(
                context.codebase,
                context.revision,
                strategy,
                [task.to_dict() for task in tasks],
            )
        self._emit(
            "hunt_plan_persisted" if plan_id else "hunt_plan_not_persisted",
            plan_id=plan_id,
            tasks=len(tasks),
            knowledge_failures=knowledge_failures,
        )
        return HuntPlan(plan_id=plan_id, strategy=strategy, tasks=tasks)

    def plan_graph_investigation(
        self,
        context: AIRepositoryContext,
        *,
        codebase_id: str,
        graph_snapshot: CodeGraphSnapshot,
        context_broker: GraphContextBroker,
        target_node_id: str | None = None,
        target_node_ids: Sequence[str] | None = None,
        surface_context: Sequence[Mapping[str, Any]] = (),
        stable_key: str | None = None,
    ) -> Investigation:
        """Plan one Graphify-grounded investigation without making a finding verdict."""

        def complete(payload: dict[str, Any]) -> Mapping[str, Any]:
            response = self._structured_response(
                "plaidnox_graph_investigation_plan",
                load_json("schemas/graph_investigation_plan.json"),
                "graph_investigation_planning",
                payload,
                max_output_tokens=int(
                    load_json("runtime/code_intelligence.json")["maximum_planner_output_tokens"]
                ),
                model_tier=ModelTier.FAST,
            )
            try:
                return dict(response_json(response))
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise AIResponseError(
                    f"AI Graphify investigation plan did not match the required schema: {_schema_failure(exc)}"
                ) from exc

        planner = GraphInvestigationPlanner(complete)
        try:
            selected_targets = tuple(target_node_ids or ())
            if not selected_targets and target_node_id:
                selected_targets = (target_node_id,)
            if not selected_targets:
                raise GraphPlanningError("at least one Graphify target node is required")
            investigation = planner.plan_targets(
                codebase_id=codebase_id,
                snapshot=graph_snapshot,
                broker=context_broker,
                target_node_ids=selected_targets,
                repository_context={
                    "architecture": context.architecture,
                    "applications": context.applications,
                    "business_context": context.business_context,
                    "actors": context.actors,
                    "sensitive_assets": context.sensitive_assets,
                    "trust_boundaries": context.trust_boundaries,
                    "security_invariants": context.security_invariants,
                },
                surface_context=surface_context,
                stable_key=stable_key,
            )
        except GraphPlanningError as exc:
            raise AIResponseError(str(exc)) from exc
        except GraphifyAdapterError as exc:
            raise AIResponseError(f"Graph context could not support investigation planning: {exc}") from exc
        self._emit(
            "graph_investigation_planned",
            investigation_id=investigation.investigation_id,
            target_node_id=selected_targets[0] if len(selected_targets) == 1 else None,
            target_node_ids=list(selected_targets),
            graph_snapshot_id=graph_snapshot.snapshot_id,
            source_windows=len(investigation.source_windows),
        )
        return investigation

    def discover_candidates(
        self,
        root: Path,
        context: AIRepositoryContext,
        plan: HuntPlan | None = None,
    ) -> tuple[list[Candidate], int]:
        """Use AI-planned ripgrep discovery and focused Security IR context."""
        candidates: list[Candidate] = []
        failures = 0
        self.discovery_error_types = []
        self.discovery_errors = []
        self.discovery_unexpected_failures = 0
        runtime = load_json("runtime/agent.json")
        queries = self._create_search_plan(context, plan)
        search_errors: list[RipgrepQueryError] = []
        region_stats: dict[str, int] = {}
        segments = _search_segments(
            root,
            queries,
            plan,
            self.security_graph,
            self.source_excludes,
            self.max_file_bytes,
            include_paths=set(context.analysis_scope_paths) or None,
            error_sink=search_errors.append,
            stats=region_stats,
        )
        self._emit("discovery_regions_planned", **region_stats)
        self._record_search_query_errors("candidate_discovery", context, search_errors)
        if not segments:
            raise AIResponseError("AI ripgrep plan produced no reviewable context")
        segments, workset_stats = _security_workset_review_units(segments)
        self._emit("discovery_worksets_attached", **workset_stats)

        # One index for the whole scan: the same bug reported from overlapping
        # segments or continuations must be hunted once.
        candidate_index = CandidateIndex()

        def analyze(segment: dict[str, Any]) -> tuple[list[Candidate], list[Exception]]:
            segment_candidates: list[Candidate] = []
            errors: list[Exception] = []
            # Identity is the bounded workset batch. Region-level source windows
            # and task/query IDs remain provenance, not work identity.
            checkpoint_key = unit_key(
                "discovery-workset-v1",
                {
                    "workset_id": segment["security_workset"]["workset_id"],
                    "evidence_hash": segment["security_workset"]["evidence_hash"],
                    "batch_index": segment["security_workset"]["batch_index"],
                },
            )
            if self.checkpoint is not None:
                saved = self.checkpoint.get("discovery", checkpoint_key)
                if saved is not None:
                    self._emit(
                        "checkpoint_reused",
                        stage="discovery",
                        path=segment["path"],
                        start_line=segment["start_line"],
                        workset_id=segment["security_workset"]["workset_id"],
                        batch_index=segment["security_workset"]["batch_index"],
                    )
                    return [candidate_from_dict(item) for item in saved["candidates"]], []
            self._emit(
                "discovery_workset_batch_started",
                path=segment["path"],
                start_line=segment["start_line"],
                workset_id=segment["security_workset"]["workset_id"],
                batch_index=segment["security_workset"]["batch_index"],
            )
            related_tasks = _tasks_for_segment(
                plan,
                str(segment["path"]),
                {str(item) for item in segment.get("task_ids", [])},
            )
            next_focus = ""
            for _continuation in range(int(runtime["discovery_max_continuations"]) + 1):
                request = {
                    "repository_context": _compact_repository_context(
                        context,
                        str(segment["path"]),
                    ),
                    "hunt_plan": {"strategy": plan.strategy, "tasks": related_tasks} if plan else None,
                    "source_segment": {
                        key: segment[key]
                        for key in ("path", "start_line", "end_line", "task_ids", "query_ids")
                        if key in segment
                    },
                    "source_windows": segment["allowed_source_windows"],
                    "security_workset": segment.get("security_workset", {}),
                    "continuation_focus": next_focus,
                }
                try:
                    response = self._structured_response(
                        "plaidnox_vulnerability_discovery",
                        load_json("schemas/vulnerability_discovery.json"),
                        "vulnerability_discovery",
                        request,
                    )
                    payload = response_json(response)
                    new_candidates = 0
                    for item in payload["candidates"]:
                        candidate = _candidate_from_ai_item(
                            root,
                            item,
                            segment,
                            allowed_source_windows=segment["allowed_source_windows"],
                        )
                        if candidate is None:
                            continue
                        if not candidate_index.admit(candidate):
                            continue
                        segment_candidates.append(candidate)
                        new_candidates += 1
                    if bool(payload["coverage_complete"]):
                        break
                    if not new_candidates and not segment_candidates:
                        # Nothing found on the first pass: a second pass over the same
                        # source is the duplicated call, so treat the region as covered.
                        self._emit("discovery_continuation_skipped", path=segment["path"], round=_continuation)
                        break
                    if _continuation > 0 and not new_candidates:
                        # A continuation that only repeats known candidates is not
                        # widening coverage; stop paying to resend the segment.
                        self._emit("discovery_continuation_exhausted", path=segment["path"], round=_continuation)
                        break
                    if str(payload["next_focus"]) == next_focus:
                        self._emit("discovery_continuation_exhausted", path=segment["path"], round=_continuation)
                        break
                    next_focus = str(payload["next_focus"])
                    if not next_focus:
                        raise AIResponseError("AI marked coverage incomplete without a continuation focus")
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
                    break
            if self.checkpoint is not None and not errors:
                self.checkpoint.put(
                    "discovery", checkpoint_key, {"candidates": [candidate_to_dict(item) for item in segment_candidates]}
                )
            sink = self.candidate_sink
            if sink is not None and not errors:
                for candidate in segment_candidates:
                    try:
                        sink(candidate)
                    except Exception:  # noqa: BLE001 - early triage is an optimisation only
                        break
            self._emit(
                "discovery_workset_batch_completed",
                path=segment["path"],
                start_line=segment["start_line"],
                workset_id=segment["security_workset"]["workset_id"],
                batch_index=segment["security_workset"]["batch_index"],
                candidates=len(segment_candidates),
                errors=len(errors),
            )
            return segment_candidates, errors

        with ThreadPoolExecutor(max_workers=int(runtime["discovery_max_workers"])) as executor:
            for segment_candidates, errors in executor.map(analyze, segments):
                candidates.extend(segment_candidates)
                failures += len(errors)
                self.discovery_error_types.extend(type(error).__name__ for error in errors)
                self.discovery_errors.extend(str(error)[:240] for error in errors)
                self.discovery_unexpected_failures += sum(
                    1 for error in errors if not isinstance(error, AIStageError)
                )
        return candidates, failures

    def sweep_variants(
        self,
        root: Path,
        context: AIRepositoryContext,
        plan: HuntPlan,
        verified: list[tuple[Candidate, Finding]],
    ) -> tuple[list[Candidate], int]:
        """Search the complete readable source set for variants of a verified root cause."""
        runtime = load_json("runtime/agent.json")
        variants: list[Candidate] = []
        failures = 0
        self.variant_unexpected_failures = 0
        if not verified:
            return [], 0

        self._emit("variant_sweep_started", verified_roots=len(verified))

        verified_payload = [
            {
                "fingerprint": finding.fingerprint,
                "title": finding.title,
                "vulnerability_class": finding.vulnerability_class,
                "severity": finding.severity.value,
                "path": finding.evidence.path,
                "start_line": finding.evidence.start_line,
                "end_line": finding.evidence.end_line,
                "attack_path": finding.metadata.get("deep_hunt", {}).get("attack_path", ""),
                "root_cause": finding.metadata.get("deep_hunt", {}).get("reasoning", ""),
                "category": candidate.metadata.get("category", "general"),
            }
            for candidate, finding in verified
        ]

        compact_plan = {
            "plan_id": plan.plan_id,
            "strategy": plan.strategy,
            "tasks": [
                {
                    "task_id": task.task_id,
                    "title": task.title,
                    "objective": task.objective,
                    "focus_paths": task.focus_paths,
                    "vulnerability_themes": task.vulnerability_themes,
                    "evidence_requirements": task.evidence_requirements,
                    "business_invariants": task.business_invariants,
                    "coverage_obligations": task.coverage_obligations,
                    "falsification_requirements": task.falsification_requirements,
                    "inventory_refs": task.inventory_refs,
                    "sensitive_effect_refs": task.sensitive_effect_refs,
                    "authentication_path_refs": task.authentication_path_refs,
                }
                for task in plan.tasks
            ],
        }

        def analyze(segment: dict[str, Any]) -> tuple[list[Candidate], int, int]:
            segment_variants: list[Candidate] = []
            segment_failures = 0
            segment_unexpected = 0
            self._emit("variant_segment_started", path=segment["path"], start_line=segment["start_line"])
            next_focus = ""
            for _continuation in range(int(runtime["discovery_max_continuations"]) + 1):
                request = {
                    "repository_context": _compact_repository_context(
                        context,
                        str(segment["path"]),
                    ),
                    "hunt_plan": compact_plan,
                    "verified_roots": verified_payload,
                    "source_segment": segment,
                    "continuation_focus": next_focus,
                }
                try:
                    response = self._structured_response(
                        "plaidnox_variant_sweep",
                        load_json("schemas/variant_sweep.json"),
                        "variant_sweep",
                        request,
                    )
                    payload = response_json(response)
                    for item in payload["candidates"]:
                        variant = _candidate_from_ai_item(root, item, segment)
                        if variant is not None:
                            variant.metadata["variant_of"] = [
                                finding.fingerprint for _candidate, finding in verified
                            ]
                            variant.metadata["engine"] = "plaidnox-root-cause-sweep"
                            segment_variants.append(variant)
                    if bool(payload["coverage_complete"]):
                        break
                    next_focus = str(payload["next_focus"])
                    if not next_focus:
                        raise AIResponseError("AI variant sweep was incomplete without a continuation focus")
                except Exception as exc:  # noqa: BLE001
                    segment_failures += 1
                    if not isinstance(exc, AIStageError):
                        segment_unexpected += 1
                    break
            self._emit(
                "variant_segment_completed",
                path=segment["path"],
                start_line=segment["start_line"],
                candidates=len(segment_variants),
                errors=segment_failures,
            )
            return segment_variants, segment_failures, segment_unexpected

        try:
            queries = self._create_search_plan(context, plan, verified_payload)
        except Exception as exc:  # noqa: BLE001
            self._emit("variant_search_plan_failed", error_type=type(exc).__name__)
            self.variant_unexpected_failures += int(not isinstance(exc, AIStageError))
            return [], 1
        search_errors: list[RipgrepQueryError] = []
        segments = _search_segments(
            root,
            queries,
            plan,
            self.security_graph,
            self.source_excludes,
            self.max_file_bytes,
            include_paths=set(context.analysis_scope_paths) or None,
            error_sink=search_errors.append,
        )
        self._record_search_query_errors("variant_sweep", context, search_errors)
        if not segments:
            raise AIResponseError("AI variant-search plan produced no reviewable context")
        with ThreadPoolExecutor(max_workers=int(runtime["sweep_max_workers"])) as executor:
            for segment_variants, segment_failures, segment_unexpected in executor.map(analyze, segments):
                variants.extend(segment_variants)
                failures += segment_failures
                self.variant_unexpected_failures += segment_unexpected
        self._emit("variant_sweep_completed", candidates=len(variants), errors=failures)
        return variants, failures

    def _frontier_priority(self, finding: Finding) -> str:
        facts = {
            "fingerprint": finding.fingerprint,
            "capability": finding.metadata.get("deep_hunt", {}).get("gained_capability", ""),
            "title": finding.title,
            "vulnerability_class": finding.vulnerability_class,
            "severity": finding.severity.value,
            "attack_path": finding.metadata.get("deep_hunt", {}).get("attack_path", ""),
        }
        return self.frontier_router.prioritize(facts).priority

    def chain_capability_pivots(
        self,
        root: Path,
        context: AIRepositoryContext,
        plan: HuntPlan,
        verified: list[tuple[Candidate, Finding]],
    ) -> tuple[list[Candidate], int]:
        """Search for a further security-boundary crossing enabled by each verified finding's gained capability.

        A confirmed finding's `gained_capability` (set by `hunt`'s verification gate 5) is not
        an endpoint -- it is new attacker-controlled reach. This stage asks whether that reach
        crosses another boundary elsewhere in the repository and, when it does, returns pivot
        candidates that re-enter the same discovery-then-verify pipeline as any other candidate,
        so a chained hypothesis is never asserted without its own independent Deep Hunt review.
        """
        runtime = load_json("runtime/agent.json")
        pivots: list[Candidate] = []
        failures = 0
        self.capability_chain_unexpected_failures = 0
        capable = [
            (candidate, finding)
            for candidate, finding in verified
            if str(finding.metadata.get("deep_hunt", {}).get("gained_capability", ""))
        ]
        if not capable:
            return [], 0

        max_frontier = int(runtime["capability_chain_max_frontier"])
        if len(capable) > max_frontier:
            ranked = [
                (self._frontier_priority(finding), candidate, finding)
                for candidate, finding in capable
            ]
            ranked.sort(key=lambda item: FRONTIER_PRIORITY_WEIGHT[item[0]], reverse=True)
            self._emit(
                "capability_chain_frontier_selected",
                candidates=len(capable),
                selected=max_frontier,
            )
            capable = [(candidate, finding) for _priority, candidate, finding in ranked[:max_frontier]]

        self._emit("capability_chain_started", verified_roots=len(capable))

        capability_payload = [
            {
                "fingerprint": finding.fingerprint,
                "capability": finding.metadata.get("deep_hunt", {}).get("gained_capability", ""),
                "title": finding.title,
                "vulnerability_class": finding.vulnerability_class,
                "severity": finding.severity.value,
                "path": finding.evidence.path,
                "start_line": finding.evidence.start_line,
                "end_line": finding.evidence.end_line,
                "attack_path": finding.metadata.get("deep_hunt", {}).get("attack_path", ""),
            }
            for candidate, finding in capable
        ]

        compact_plan = {
            "plan_id": plan.plan_id,
            "strategy": plan.strategy,
            "tasks": [
                {
                    "task_id": task.task_id,
                    "title": task.title,
                    "objective": task.objective,
                    "focus_paths": task.focus_paths,
                    "vulnerability_themes": task.vulnerability_themes,
                    "evidence_requirements": task.evidence_requirements,
                    "business_invariants": task.business_invariants,
                    "coverage_obligations": task.coverage_obligations,
                    "falsification_requirements": task.falsification_requirements,
                    "inventory_refs": task.inventory_refs,
                    "sensitive_effect_refs": task.sensitive_effect_refs,
                    "authentication_path_refs": task.authentication_path_refs,
                }
                for task in plan.tasks
            ],
        }

        def analyze(segment: dict[str, Any]) -> tuple[list[Candidate], int, int]:
            segment_pivots: list[Candidate] = []
            segment_failures = 0
            segment_unexpected = 0
            self._emit("capability_chain_segment_started", path=segment["path"], start_line=segment["start_line"])
            next_focus = ""
            for _continuation in range(int(runtime["discovery_max_continuations"]) + 1):
                request = {
                    "repository_context": context.to_dict(),
                    "hunt_plan": compact_plan,
                    "verified_roots": capability_payload,
                    "source_segment": segment,
                    "continuation_focus": next_focus,
                }
                try:
                    response = self._structured_response(
                        "plaidnox_capability_chain",
                        load_json("schemas/capability_chain.json"),
                        "capability_chain",
                        request,
                    )
                    payload = response_json(response)
                    for item in payload["candidates"]:
                        pivot = _candidate_from_ai_item(root, item, segment)
                        if pivot is not None:
                            pivot.metadata["capability_pivot_of"] = [
                                finding.fingerprint for _candidate, finding in capable
                            ]
                            pivot.metadata["engine"] = "plaidnox-capability-chain"
                            segment_pivots.append(pivot)
                    if bool(payload["coverage_complete"]):
                        break
                    next_focus = str(payload["next_focus"])
                    if not next_focus:
                        raise AIResponseError("AI capability chain was incomplete without a continuation focus")
                except Exception as exc:  # noqa: BLE001
                    segment_failures += 1
                    if not isinstance(exc, AIStageError):
                        segment_unexpected += 1
                    break
            self._emit(
                "capability_chain_segment_completed",
                path=segment["path"],
                start_line=segment["start_line"],
                candidates=len(segment_pivots),
                errors=segment_failures,
            )
            return segment_pivots, segment_failures, segment_unexpected

        try:
            queries = self._create_search_plan(context, plan, capability_payload)
        except Exception as exc:  # noqa: BLE001
            self._emit("capability_chain_search_plan_failed", error_type=type(exc).__name__)
            self.capability_chain_unexpected_failures += int(not isinstance(exc, AIStageError))
            return [], 1
        search_errors: list[RipgrepQueryError] = []
        segments = _search_segments(
            root,
            queries,
            plan,
            self.security_graph,
            self.source_excludes,
            self.max_file_bytes,
            error_sink=search_errors.append,
        )
        self._record_search_query_errors("capability_chain", context, search_errors)
        if not segments:
            raise AIResponseError("AI capability-chain search plan produced no reviewable context")
        with ThreadPoolExecutor(max_workers=int(runtime["sweep_max_workers"])) as executor:
            for segment_pivots, segment_failures, segment_unexpected in executor.map(analyze, segments):
                pivots.extend(segment_pivots)
                failures += segment_failures
                self.capability_chain_unexpected_failures += segment_unexpected
        self._emit("capability_chain_completed", candidates=len(pivots), errors=failures)
        return pivots, failures

    def _create_search_plan(
        self,
        context: AIRepositoryContext,
        plan: HuntPlan | None,
        verified_roots: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        if plan is None or not plan.tasks:
            raise AIResponseError("A hunt plan is required before ripgrep discovery")
        compact_tasks = [
            {
                "task_id": task.task_id,
                "title": task.title,
                "objective": task.objective,
                "focus_paths": task.focus_paths,
                "entry_points": task.entry_points,
                "vulnerability_themes": task.vulnerability_themes,
                "evidence_requirements": task.evidence_requirements,
                "knowledge_queries": task.knowledge_queries,
                "business_invariants": task.business_invariants,
                "coverage_obligations": task.coverage_obligations,
                "falsification_requirements": task.falsification_requirements,
                "inventory_refs": task.inventory_refs,
                "sensitive_effect_refs": task.sensitive_effect_refs,
                "authentication_path_refs": task.authentication_path_refs,
                "knowledge_context": [
                    {
                        key: item.get(key, "")
                        for key in (
                            "knowledge_id",
                            "topic",
                            "vulnerability_class",
                            "ecosystem",
                            "framework",
                            "source_url",
                        )
                    }
                    for item in task.knowledge_context
                ],
            }
            for task in plan.tasks
        ]
        obligation_index = [
            {"ref_id": f"{task.task_id}::obligation::{i}", "task_id": task.task_id, "text": obligation}
            for task in plan.tasks
            for i, obligation in enumerate(task.coverage_obligations)
        ]
        runtime = load_json("runtime/code_intelligence.json")
        query_budget = _query_budget(runtime, len(context.analysis_scope_paths), len(plan.tasks))
        request = {
            "repository_context": _compact_repository_context(context, ""),
            "hunt_plan": {"plan_id": plan.plan_id, "strategy": plan.strategy, "tasks": compact_tasks},
            "verified_roots": verified_roots or [],
            "coverage_obligation_refs": obligation_index,
            "query_budget": {
                "maximum_queries": query_budget,
                "guidance": "Share one query across tasks (task_ids may list several) instead of repeating it.",
            },
        }
        response = self._structured_response(
            "plaidnox_search_query_plan",
            load_json("schemas/search_query_plan.json"),
            "search_query_plan",
            request,
        )
        try:
            payload = response_json(response)
            queries = list(payload["queries"])
            task_ids = {task.task_id for task in plan.tasks}
            covered = {str(task_id) for query in queries for task_id in query["task_ids"]}
            covered_refs = {str(ref) for query in queries for ref in query.get("coverage_refs", [])}
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError(f"AI search plan did not match the required schema: {_schema_failure(exc)}") from exc
        missing = task_ids - covered
        if missing:
            raise AIResponseError("AI search plan did not cover every hunt task")
        all_obligation_refs = {item["ref_id"] for item in obligation_index}
        unknown_refs = covered_refs - all_obligation_refs
        if unknown_refs:
            raise AIResponseError("AI search plan referenced an unknown coverage obligation")
        missing_refs = all_obligation_refs - covered_refs
        if missing_refs:
            raise AIResponseError("AI search plan did not cover every coverage obligation")
        maximum = int(query_budget * float(runtime["query_budget_enforcement_factor"]))
        if len(queries) > maximum:
            raise AIResponseError("AI search plan exceeded the configured query limit")
        self._emit(
            "search_plan_generated",
            queries=len(queries),
            query_budget=query_budget,
            tasks=len(task_ids),
            variant_sweep=bool(verified_roots),
        )
        return queries

    def consolidate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Use an evidence-aware model verdict to merge only equivalent validated findings."""
        if not findings:
            return []
        self._emit("finding_consolidation_started", findings=len(findings))
        payload = {
            "findings": [
                {
                    "fingerprint": finding.fingerprint,
                    "title": finding.title,
                    "vulnerability_class": finding.vulnerability_class,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                    "message": finding.message,
                    "business_impact": finding.impact,
                    "remediation": finding.remediation,
                    "evidence": {
                        "path": finding.evidence.path,
                        "start_line": finding.evidence.start_line,
                        "end_line": finding.evidence.end_line,
                        "source_symbol": finding.evidence.source_symbol,
                        "sink_symbol": finding.evidence.sink_symbol,
                        "graph_path": finding.evidence.graph_path,
                    },
                    "deep_hunt": {
                        "reasoning": finding.metadata.get("deep_hunt", {}).get("reasoning", ""),
                        "attack_path": finding.metadata.get("deep_hunt", {}).get("attack_path", ""),
                        "required_preconditions": finding.metadata.get("deep_hunt", {}).get(
                            "required_preconditions", []
                        ),
                    },
                }
                for finding in findings
            ]
        }
        consolidation_schema = load_json("schemas/finding_consolidation.json")
        assignment_schema = consolidation_schema["properties"]["assignments"]
        assignment_schema["properties"] = {
            finding.fingerprint: {"type": "string", "minLength": 1, "maxLength": 120}
            for finding in findings
        }
        assignment_schema["required"] = [finding.fingerprint for finding in findings]
        response = self._structured_response(
            "plaidnox_finding_consolidation",
            consolidation_schema,
            "finding_consolidation",
            payload,
            max_output_tokens=int(load_json("runtime/agent.json")["consolidation_max_output_tokens"]),
        )
        try:
            consolidation = response_json(response)
            assignments = {str(key): str(value) for key, value in consolidation["assignments"].items()}
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError(f"AI finding consolidation did not match the required schema: {_schema_failure(exc)}") from exc

        by_fingerprint = {finding.fingerprint: finding for finding in findings}
        expected = set(by_fingerprint)
        if set(assignments) != expected:
            raise AIResponseError("AI finding consolidation assignments did not cover every fingerprint")
        members_by_group: dict[str, list[str]] = {}
        for fingerprint, group_key in assignments.items():
            members_by_group.setdefault(group_key, []).append(fingerprint)

        narrative_schema = load_json("schemas/finding_group_narratives.json")
        narrative_groups = narrative_schema["properties"]["groups"]
        narrative_groups["properties"] = {
            group_key: load_json("schemas/finding_group.json") for group_key in members_by_group
        }
        narrative_groups["required"] = list(members_by_group)
        narrative_response = self._structured_response(
            "plaidnox_finding_group_narratives",
            narrative_schema,
            "finding_group_narratives",
            {"assignments": assignments, **payload},
            max_output_tokens=int(load_json("runtime/agent.json")["consolidation_max_output_tokens"]),
        )
        try:
            groups = dict(response_json(narrative_response)["groups"])
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError(f"AI finding group narratives did not match the required schema: {_schema_failure(exc)}") from exc
        if set(groups) != set(members_by_group):
            raise AIResponseError("AI finding narratives did not cover every assigned group")
        consolidated: list[Finding] = []
        for group_key, group in groups.items():
            members = members_by_group[str(group_key)]
            primary_fingerprint = str(group["primary_fingerprint"])
            if primary_fingerprint not in members:
                raise AIResponseError("AI finding consolidation referenced an invalid fingerprint")
            primary = by_fingerprint[primary_fingerprint]
            alternatives = [
                {
                    "fingerprint": member,
                    "path": by_fingerprint[member].evidence.path,
                    "start_line": by_fingerprint[member].evidence.start_line,
                    "end_line": by_fingerprint[member].evidence.end_line,
                }
                for member in members
                if member != primary_fingerprint
            ]
            metadata = {
                **primary.metadata,
                "consolidation": {
                    "reasoning": str(group["reasoning"]),
                    "member_fingerprints": members,
                    "alternative_evidence": alternatives,
                },
            }
            consolidated.append(
                replace(
                    primary,
                    title=str(group["title"]),
                    vulnerability_class=str(group["vulnerability_class"]),
                    severity=Severity(str(group["severity"])),
                    confidence=float(group["confidence"]),
                    message=str(group["message"]),
                    impact=str(group["business_impact"]),
                    remediation=str(group["remediation"]),
                    metadata=metadata,
                )
            )
        self._emit("finding_consolidation_completed", findings=len(consolidated))
        return consolidated

    def _model_for_tier(self, model_tier: ModelTier | None) -> str:
        if model_tier is None:
            return self.model
        return self.model_by_tier.get(model_tier.value, self.model)

    def _create_with_rate_limit_wait(self, request_kwargs: dict[str, Any], agent_runtime: Mapping[str, Any]) -> Any:
        """Call the model, waiting only when a provider reports rate limiting.

        LiteLLM already owns bounded transport retries. Connection failures,
        timeouts, and provider errors must therefore escape to the durable
        checkpoint as pending work rather than being mislabeled as rate-limit
        waits and sleeping for several minutes.
        """
        max_waits = int(agent_runtime["rate_limit_max_waits"])
        base = float(agent_runtime["rate_limit_base_wait_seconds"])
        ceiling = float(agent_runtime["rate_limit_max_wait_seconds"])
        for waited in range(max_waits + 1):
            try:
                return self.client.responses.create(**request_kwargs)
            except Exception as exc:
                if waited == max_waits or type(exc).__name__ not in _RATE_LIMIT_ERROR_NAMES:
                    raise
                wait = min(ceiling, base * (2**waited))
                with self._telemetry_lock:
                    self.rate_limit_waits += 1
                self._emit(
                    "model_request_rate_limited",
                    operation=str(request_kwargs["model"]),
                    error_type=type(exc).__name__,
                    wait_seconds=wait,
                    wait_number=waited + 1,
                )
                time.sleep(wait)
        raise AssertionError("unreachable")

    def _structured_response(
        self,
        name: str,
        schema: dict[str, Any],
        prompt_operation: str,
        payload: dict[str, Any],
        max_output_tokens: int | None = None,
        model_tier: ModelTier | None = None,
        reasoning_effort_override: str | None = None,
    ) -> Any:
        safe_payload = redact_payload(payload)
        serialized_payload = json.dumps(safe_payload, sort_keys=True, ensure_ascii=False)
        runtime = load_json("runtime/code_intelligence.json")
        source_keys = {str(item) for item in runtime["audited_source_payload_keys"]}
        source_context_characters = _payload_characters_for_keys(safe_payload, source_keys)
        repository_wide_context = _contains_repository_wide_context(safe_payload)
        agent_runtime = load_json("runtime/agent.json")
        configured_effort = str(agent_runtime["reasoning_effort_by_operation"].get(prompt_operation, "low"))
        tier_efforts = agent_runtime.get("reasoning_effort_by_operation_by_tier", {}).get(
            prompt_operation, {}
        )
        requested_tier = model_tier.value if model_tier is not None else "standard"
        configured_effort = str(tier_efforts.get(requested_tier, configured_effort))
        effort = _stronger_effort(configured_effort, reasoning_effort_override)
        system_prompt, user_prompt = render_operation(prompt_operation, safe_payload, output_schema=schema)
        schema_hash = hashlib.sha256(
            json.dumps(schema, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        checkpoint_key = unit_key(
            "llm_response",
            name,
            prompt_operation,
            hashlib.sha256(system_prompt.encode("utf-8")).hexdigest(),
            hashlib.sha256(user_prompt.encode("utf-8")).hexdigest(),
            schema_hash,
        )
        checkpoint_work_identity = _checkpoint_work_identity(prompt_operation, safe_payload)
        if self.checkpoint is not None:
            saved = self.checkpoint.get_record("llm_response", checkpoint_key)
            if saved is not None:
                execution = dict(saved["execution"])
                structured_payload = saved["payload"]["structured_payload"]
                self._model_input_audit.append(
                    {
                        "operation": prompt_operation,
                        "model_tier": str(execution.get("model_tier", "checkpoint")),
                        "model": str(execution.get("model", "checkpoint")),
                        "payload_hash": hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest(),
                        "payload_characters": len(serialized_payload),
                        "source_context_characters": source_context_characters,
                        "repository_wide_context": repository_wide_context,
                        "checkpoint_reused": True,
                    }
                )
                self._emit(
                    "checkpoint_reused",
                    stage="llm_response",
                    operation=prompt_operation,
                )
                replay = SimpleNamespace(
                    status="completed",
                    output_text=json.dumps(structured_payload, ensure_ascii=False),
                    usage={},
                )
                return StructuredResponse(replay, structured_payload)
        model_execution = self._model_execution_route(
            prompt_operation,
            safe_payload,
            len(serialized_payload),
            source_context_characters,
            repository_wide_context,
            model_tier,
            effort,
        )
        routed_effort = str(tier_efforts.get(model_execution.model_tier.value, configured_effort))
        routed_effort = _stronger_effort(routed_effort, reasoning_effort_override)
        if routed_effort != effort:
            effort = routed_effort
            model_execution = self._model_execution_route(
                prompt_operation,
                safe_payload,
                len(serialized_payload),
                source_context_characters,
                repository_wide_context,
                model_execution.model_tier,
                effort,
            )
        self._model_input_audit.append(
            {
                "operation": prompt_operation,
                "model_tier": model_execution.model_tier.value,
                "model": model_execution.model_name,
                "payload_hash": hashlib.sha256(serialized_payload.encode("utf-8")).hexdigest(),
                "payload_characters": len(serialized_payload),
                "source_context_characters": source_context_characters,
                "repository_wide_context": repository_wide_context,
                "checkpoint_reused": False,
            }
        )
        request_policy = _model_request_policy(agent_runtime, prompt_operation)
        operation_output_limits = agent_runtime.get("model_output_token_limit_by_operation", {})
        tier_output_limits = agent_runtime.get(
            "model_output_token_limit_by_operation_by_tier", {}
        ).get(prompt_operation, {})
        effective_max_output_tokens = (
            int(max_output_tokens)
            if max_output_tokens is not None
            else int(
                tier_output_limits.get(
                    model_execution.model_tier.value,
                    operation_output_limits.get(prompt_operation, self.max_output_tokens),
                )
            )
        )
        request_kwargs: dict[str, Any] = {
            "model": model_execution.model_name,
            "reasoning": {"effort": effort},
            "input": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "text": {
                "verbosity": "low",
                "format": {"type": "json_schema", "name": name, "strict": True, "schema": schema},
            },
            "timeout": request_policy["timeout_seconds"],
            "max_retries": request_policy["max_retries"],
        }
        if model_execution.model_name.startswith("gpt-"):
            # Routes requests sharing this stable prefix to the same cache shard.
            request_kwargs["prompt_cache_key"] = (
                f"{agent_runtime['prompt_cache_key_prefix']}:{prompt_operation}"
            )
        # Every provider request carries a configured upper bound. Without it,
        # some gateways reserve the model's full context-window output budget
        # and reject an otherwise small request before generation begins.
        request_kwargs["max_output_tokens"] = effective_max_output_tokens
        checkpoint_context = {
            "schema_name": name,
            "schema": schema,
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
        }
        checkpoint_execution = {
            "operation": prompt_operation,
            "model": model_execution.model_name,
            "model_tier": model_execution.model_tier.value,
            "reasoning_effort": effort,
            "timeout_seconds": request_policy["timeout_seconds"],
            "max_retries": request_policy["max_retries"],
            "max_output_tokens": effective_max_output_tokens,
            "work_identity": checkpoint_work_identity,
        }
        if self.checkpoint is not None:
            self.checkpoint.begin("llm_response", checkpoint_key, checkpoint_context, checkpoint_execution)
        shape_retries = request_policy["structured_shape_retries"]
        truncation_policy = agent_runtime.get("output_truncation_retry_by_operation", {}).get(
            prompt_operation, {}
        )
        max_output_retries = int(truncation_policy.get("max_retries", 0))
        retry_limits = truncation_policy.get("retry_output_tokens_by_tier", {})
        output_retry_count = 0
        total_attempts = int(shape_retries) + max_output_retries + 1
        best: Any = None
        for attempt in range(total_attempts):
            reservation = self.model_budget.reserve(
                str(request_kwargs["model"]),
                len(system_prompt) + len(user_prompt),
                effective_max_output_tokens,
            )
            started_at = time.monotonic()
            self._emit(
                "model_request_started",
                operation=prompt_operation,
                model=str(request_kwargs["model"]),
                attempt=attempt + 1,
                timeout_seconds=request_policy["timeout_seconds"],
                max_retries=request_policy["max_retries"],
            )
            try:
                response = self._create_with_rate_limit_wait(request_kwargs, agent_runtime)
            except BaseException as exc:
                self.model_budget.cancel(reservation)
                if self.checkpoint is not None:
                    self.checkpoint.fail("llm_response", checkpoint_key, type(exc).__name__)
                self._emit(
                    "model_request_failed",
                    operation=prompt_operation,
                    model=str(request_kwargs["model"]),
                    attempt=attempt + 1,
                    duration_milliseconds=round((time.monotonic() - started_at) * 1000),
                    error_type=type(exc).__name__,
                )
                raise
            self._emit(
                "model_request_completed",
                operation=prompt_operation,
                model=str(request_kwargs["model"]),
                attempt=attempt + 1,
                duration_milliseconds=round((time.monotonic() - started_at) * 1000),
            )
            self.model_budget.complete(reservation, response)
            self.cache_telemetry.record_response(response)
            if getattr(response, "status", "completed") != "completed":
                detail = getattr(response, "incomplete_details", None)
                reason = getattr(detail, "reason", "unknown") if detail else "unknown"
                if self.checkpoint is not None:
                    self.checkpoint.fail("llm_response", checkpoint_key, f"incomplete:{reason}")
                retry_limit = int(retry_limits.get(model_execution.model_tier.value, 0))
                if (
                    reason == "max_output_tokens"
                    and output_retry_count < max_output_retries
                    and retry_limit > effective_max_output_tokens
                ):
                    output_retry_count += 1
                    effective_max_output_tokens = retry_limit
                    request_kwargs["max_output_tokens"] = retry_limit
                    checkpoint_execution["max_output_tokens"] = retry_limit
                    checkpoint_execution["output_retry"] = output_retry_count
                    if self.checkpoint is not None:
                        self.checkpoint.begin(
                            "llm_response",
                            checkpoint_key,
                            checkpoint_context,
                            checkpoint_execution,
                        )
                    self._emit(
                        "model_output_truncation_retry",
                        operation=prompt_operation,
                        model_tier=model_execution.model_tier.value,
                        retry=output_retry_count,
                        max_output_tokens=retry_limit,
                    )
                    continue
                raise AIResponseError(f"AI request was incomplete: {reason}")
            try:
                payload, matches = parse_structured(response_text(response), schema)
            except json.JSONDecodeError:
                payload, matches = None, False
            if matches:
                if self.checkpoint is not None:
                    self.checkpoint.complete(
                        "llm_response",
                        checkpoint_key,
                        {"structured_payload": payload},
                    )
                return StructuredResponse(response, payload)
            if payload is not None:
                best = payload
            self._emit(
                "structured_response_shape_mismatch",
                operation=prompt_operation,
                attempt=attempt + 1,
                decodable=payload is not None,
            )
        # Out of retries: hand callers the closest reshaped answer (or the raw
        # one when nothing decoded) so their own schema check raises the
        # stage-specific AIResponseError.
        if self.checkpoint is not None:
            self.checkpoint.fail("llm_response", checkpoint_key, "StructuredResponseShapeMismatch")
        return StructuredResponse(response, best) if best is not None else response

    def _model_execution_route(
        self,
        operation: str,
        payload: Mapping[str, Any],
        payload_characters: int,
        source_context_characters: int,
        repository_wide_context: bool,
        minimum_tier: ModelTier | None,
        reasoning_effort: str,
    ) -> ModelExecutionDecision:
        cache_key = f"{operation}:{minimum_tier.value if minimum_tier else 'any'}:{reasoning_effort}"
        cached = self._model_execution_routes.get(cache_key)
        if cached is not None:
            return cached
        decision = self.model_execution_router.classify(
            {
                "operation": operation,
                "minimum_tier": minimum_tier.value if minimum_tier is not None else "",
                "reasoning_effort": reasoning_effort,
                "payload_characters": payload_characters,
                "source_context_characters": source_context_characters,
                "repository_wide_context": repository_wide_context,
                "context_fields": sorted(str(key) for key in payload),
            }
        )
        self._model_execution_routes[cache_key] = decision
        self._emit(
            "model_execution_route_selected",
            operation=operation,
            model=decision.model_name,
            model_tier=decision.model_tier.value,
            confidence=decision.confidence,
            reason=decision.reason,
        )
        return decision


def _checkpoint_work_identity(operation: str, payload: Mapping[str, Any]) -> str:
    """Identify the semantic work item across prompt/schema revisions."""
    segment = payload.get("source_segment")
    if isinstance(segment, Mapping) and segment.get("region_id"):
        return unit_key(operation, "region", segment["region_id"])
    region = payload.get("discovery_region")
    if isinstance(region, Mapping) and region.get("region_id"):
        return unit_key(operation, "region", region["region_id"])
    packet = payload.get("candidate_evidence_packet")
    if isinstance(packet, Mapping) and packet.get("candidate_id"):
        return unit_key(operation, "candidate", packet["candidate_id"])
    stable_candidate = {
        key: payload.get(key)
        for key in ("rule_id", "path", "start_line", "end_line", "title", "candidate_id")
        if payload.get(key) is not None
    }
    return unit_key(operation, stable_candidate) if stable_candidate else ""


def _model_request_policy(runtime: Mapping[str, Any], operation: str) -> dict[str, int | float]:
    """Resolve externally configured transport and response-shape limits."""

    policies = runtime["model_request_policy_by_operation"]
    default = dict(policies["default"])
    default.update(policies.get(operation, {}))
    return {
        "timeout_seconds": float(default["timeout_seconds"]),
        "max_retries": int(default["max_retries"]),
        "structured_shape_retries": int(default["structured_shape_retries"]),
    }


# Kept for artifact and test compatibility with the first MVP. New code uses
# DeepHuntResult, which names the actual PlaidNox domain operation.
AIReview = DeepHuntResult


def load_env_file(path: Path) -> None:
    """Load only KEY=VALUE pairs without evaluating shell syntax."""

    allowed = {str(key) for key in load_json("runtime/environment.json")["allowed_env_file_keys"]}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in allowed and value:
            os.environ.setdefault(key, value.strip().strip("\"'"))


_EFFORT_ORDER = {"low": 0, "medium": 1, "high": 2}


def _stronger_effort(configured: str, override: str | None) -> str:
    """Let a route's evidence signals escalate reasoning effort above the static per-operation default, never below it."""
    if override is None or override not in _EFFORT_ORDER:
        return configured
    if configured not in _EFFORT_ORDER:
        return configured
    return override if _EFFORT_ORDER[override] > _EFFORT_ORDER[configured] else configured


def _hunt_effort_override(route: RouteDecision | None) -> str | None:
    if route is None:
        return None
    if route.analysis_complexity >= 4 or route.needs_deep_falsification in {"likely", "yes"}:
        return "high"
    return None


def _context_expansion_max_requests(runtime: dict[str, Any], route: RouteDecision | None) -> int:
    base = int(runtime["context_expansion_max_requests_per_round"])
    if route is None:
        return base
    breadth_signals = (
        route.needs_cross_file,
        route.needs_state_reconstruction,
        route.needs_external_semantics,
        route.needs_environment_context,
    )
    bonus_per_signal = int(runtime["context_expansion_signal_bonus_requests"])
    extra = sum(1 for signal in breadth_signals if signal in {"likely", "yes"}) * bonus_per_signal
    ceiling = int(runtime["context_expansion_max_requests_per_round_ceiling"])
    return min(base + extra, ceiling)


def _retry_facts(
    review: DeepHuntResult,
    model_tier: ModelTier | None,
    context_expansions: list[dict[str, Any]],
    confidence_history: list[float],
) -> dict[str, Any]:
    return {
        "model_tier": model_tier.value if model_tier is not None else "",
        "rounds_used": len(confidence_history),
        "context_requests_pending": len(review.context_requests),
        "resolved_requests": len(context_expansions),
        "unresolved_gates": [
            str(gate.get("gate", "")) for gate in review.gate_results if gate.get("verdict") == "unknown"
        ],
        "evidence_gaps": list(review.evidence_gaps or []),
        "confidence_history": confidence_history,
    }


def _source_window(
    root: Path,
    relative_path: str,
    start_line: int,
    end_line: int,
    *,
    exclude: list[str] | None = None,
    max_file_bytes: int | None = None,
) -> str:
    """Read a bounded source window only when the project source policy admits the file."""

    source_path = (root / relative_path).resolve()
    if root.resolve() not in source_path.parents:
        raise AIResponseError("finding path escapes the repository")
    if not source_file_is_admitted(
        root,
        source_path,
        exclude=exclude,
        max_file_bytes=max_file_bytes,
    ):
        raise AIResponseError("source path is not admitted by the project source policy")
    runtime = load_json("runtime/code_intelligence.json")
    lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, start_line - int(runtime["context_lines_before"]) - 1)
    end = min(len(lines), end_line + int(runtime["context_lines_after"]))
    numbered = [f"{index + 1}: {line}" for index, line in enumerate(lines[start:end], start)]
    return _redact("\n".join(numbered)[: int(runtime["source_window_max_characters"])])


def _security_ir_context(
    security_ir: StructuralGraph | None,
    path: str,
    line: int,
) -> dict[str, Any]:
    if security_ir is None:
        return {}
    file_ir = next((item for item in security_ir.files if item.path == path), None)
    return {
        "containing_symbol": security_ir.symbol_at(path, line),
        "symbols": [
            {
                "name": symbol.name,
                "qualified_name": symbol.qualified_name or symbol.name,
                "line": symbol.line,
                "end_line": symbol.end_line,
                "kind": symbol.kind,
            }
            for symbol in (file_ir.symbols if file_ir else [])
        ],
        "imports": list(file_ir.imports if file_ir else []),
        "calls": [
            {"caller": call.caller, "callee": call.callee, "line": call.line}
            for call in (file_ir.calls if file_ir else [])
        ],
        "references": [
            {
                "source": reference.source,
                "target": reference.target,
                "line": reference.line,
                "kind": reference.kind,
            }
            for reference in (file_ir.references if file_ir else [])
        ],
        "routes": [
            {"name": route.name, "line": route.line}
            for route in security_ir.routes
            if route.path == path
        ],
        "search_hits": [
            {"query_id": hit.query_id, "line": hit.line}
            for hit in security_ir.search_hits
            if hit.path == path
        ],
    }


def _deep_hunt_result_from_response(response: Any) -> DeepHuntResult:
    try:
        payload = response_json(response)
        review = DeepHuntResult(
            supported=bool(payload["supported"]),
            confidence=float(payload["confidence"]),
            reasoning=str(payload["reasoning"]),
            attack_path=str(payload["attack_path"]),
            remediation_note=str(payload["remediation_note"]),
            title=str(payload["title"]),
            vulnerability_class=str(payload["vulnerability_class"]),
            severity=str(payload["severity"]),
            message=str(payload["message"]),
            business_impact=str(payload["business_impact"]),
            classification_references=[
                {str(key): str(value) for key, value in item.items()}
                for item in payload["classification_references"]
            ],
            falsification_attempts=[str(item) for item in payload["falsification_attempts"]],
            required_preconditions=[str(item) for item in payload["required_preconditions"]],
            evidence_gaps=[str(item) for item in payload["evidence_gaps"]],
            security_invariant=str(payload["security_invariant"]),
            gained_capability=str(payload["gained_capability"]),
            rejection_reason=str(payload["rejection_reason"]),
            gate_results=[dict(item) for item in payload["gate_results"]],
            evidence_locations=[dict(item) for item in payload["evidence_locations"]],
            proof_plan=str(payload["proof_plan"]),
            regression_test=str(payload["regression_test"]),
            context_requests=[dict(item) for item in payload["context_requests"]],
        )
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AIResponseError(f"AI review did not match the required schema: {_schema_failure(exc)}") from exc
    if not 0 <= review.confidence <= 1:
        raise AIResponseError("AI review confidence must be between 0 and 1")
    return review


def _resolve_context_request(
    root: Path,
    security_graph: StructuralGraph | None,
    request: dict[str, Any],
    *,
    source_excludes: list[str] | None = None,
    max_file_bytes: int | None = None,
    knowledge_store: KnowledgeStore | None = None,
) -> dict[str, Any]:
    """Answer one AI-named Tree-sitter-backed context request from the already-built Security IR."""
    kind = str(request.get("kind", ""))
    path = str(request.get("path", ""))
    symbol = str(request.get("symbol", ""))
    start_line = int(request.get("start_line", 1) or 1)
    end_line = int(request.get("end_line", start_line) or start_line)
    offset = max(int(request.get("offset", 0) or 0), 0)
    pattern = str(request.get("pattern", ""))
    query = str(request.get("query", ""))
    page_size = int(load_json("runtime/agent.json")["context_request_edge_page_size"])

    if kind == "window":
        try:
            content = _source_window(
                root,
                path,
                start_line,
                end_line,
                exclude=source_excludes,
                max_file_bytes=max_file_bytes,
            )
        except (AIResponseError, OSError) as exc:
            return {"kind": kind, "path": path, "resolved": False, "reason": str(exc)}
        return {
            "kind": kind,
            "path": path,
            "start_line": start_line,
            "end_line": end_line,
            "resolved": True,
            "content": content,
        }

    if kind == "search":
        if not pattern:
            return {"kind": kind, "resolved": False, "reason": "search requests must include a non-empty literal"}
        try:
            hits = RipgrepDiscovery(root).search_literals(
                "context_search",
                [pattern],
                include_globs=[path] if path else [],
                exclude_globs=list(source_excludes or []),
            )
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
            return {"kind": kind, "resolved": False, "reason": str(exc)}
        eligible = {
            item.relative_to(root).as_posix()
            for item in source_files(root, exclude=source_excludes, max_file_bytes=max_file_bytes)
            if not _is_sensitive_path(item)
        }
        safe_hits = [{"path": hit.path, "line": hit.line} for hit in hits if hit.path in eligible]
        if not safe_hits:
            return {"kind": kind, "resolved": False, "reason": "no matches for the requested pattern"}
        page = safe_hits[offset : offset + page_size]
        return {
            "kind": kind,
            "resolved": True,
            "matches": page,
            "offset": offset,
            "returned": len(page),
            "total": len(safe_hits),
            "truncated": offset + len(page) < len(safe_hits),
        }

    if kind == "knowledge":
        if not query:
            return {"kind": kind, "resolved": False, "reason": "knowledge requests must include a non-empty query"}
        if knowledge_store is None:
            return {"kind": kind, "resolved": False, "reason": "no knowledge store is configured"}
        entries = knowledge_store.search(query)
        if not entries:
            return {"kind": kind, "resolved": False, "reason": "no stored knowledge matched the query"}
        return {
            "kind": kind,
            "resolved": True,
            "entries": [entry.to_dict() for entry in entries],
        }

    if security_graph is None:
        return {"kind": kind, "symbol": symbol, "resolved": False, "reason": "no Security IR is available"}

    if kind == "flow":
        flow = _bounded_call_flow(security_graph, symbol)
        if not flow["edges"]:
            return {
                "kind": kind,
                "symbol": symbol,
                "resolved": False,
                "reason": "no matching call-flow edges in the Security IR",
            }
        return {"kind": kind, "symbol": symbol, "resolved": True, **flow}

    if kind == "definition":
        match = next(
            (item for item in security_graph.symbols if symbol in {item.name, item.qualified_name}),
            None,
        )
        if match is None:
            return {"kind": kind, "symbol": symbol, "resolved": False, "reason": "symbol not found in the Security IR"}
        try:
            content = _source_window(
                root,
                match.path,
                match.line,
                match.end_line or match.line,
                exclude=source_excludes,
                max_file_bytes=max_file_bytes,
            )
        except (AIResponseError, OSError) as exc:
            return {"kind": kind, "symbol": symbol, "resolved": False, "reason": str(exc)}
        return {
            "kind": kind,
            "symbol": symbol,
            "path": match.path,
            "start_line": match.line,
            "end_line": match.end_line or match.line,
            "resolved": True,
            "content": content,
        }

    if kind in {"callers", "callees"}:
        all_edges = [
            {"caller": call.caller, "callee": call.callee, "path": call.path, "line": call.line}
            for call in security_graph.calls
            if (call.callee == symbol if kind == "callers" else call.caller == symbol)
        ]
        if not all_edges:
            return {"kind": kind, "symbol": symbol, "resolved": False, "reason": "no matching edges in the Security IR"}
        page = all_edges[offset : offset + page_size]
        return {
            "kind": kind,
            "symbol": symbol,
            "resolved": True,
            "edges": page,
            "offset": offset,
            "returned": len(page),
            "total": len(all_edges),
            "truncated": offset + len(page) < len(all_edges),
        }

    if kind == "imports":
        file_ir = next((item for item in security_graph.files if item.path == path), None)
        if file_ir is None:
            return {"kind": kind, "path": path, "resolved": False, "reason": "path not found in the Security IR"}
        return {"kind": kind, "path": path, "resolved": True, "imports": list(file_ir.imports)}

    if kind == "route":
        all_routes = [
            {"name": route.name, "path": route.path, "line": route.line}
            for route in security_graph.routes
            if symbol == route.name or path == route.path
        ]
        if not all_routes:
            return {"kind": kind, "symbol": symbol, "resolved": False, "reason": "no matching route in the Security IR"}
        page = all_routes[offset : offset + page_size]
        return {
            "kind": kind,
            "symbol": symbol,
            "resolved": True,
            "routes": page,
            "offset": offset,
            "returned": len(page),
            "total": len(all_routes),
            "truncated": offset + len(page) < len(all_routes),
        }

    if kind == "sibling_handlers":
        all_siblings = [
            {"name": route.name, "path": route.path, "line": route.line}
            for route in security_graph.routes
            if route.path == path and route.name != symbol
        ]
        if not all_siblings:
            return {"kind": kind, "path": path, "resolved": False, "reason": "no sibling routes in the same file"}
        page = all_siblings[offset : offset + page_size]
        return {
            "kind": kind,
            "path": path,
            "resolved": True,
            "routes": page,
            "offset": offset,
            "returned": len(page),
            "total": len(all_siblings),
            "truncated": offset + len(page) < len(all_siblings),
        }

    return {"kind": kind, "resolved": False, "reason": "unsupported context request kind"}


def _bounded_call_flow(graph: StructuralGraph, symbol: str) -> dict[str, Any]:
    """Return an AI-requested, bounded bidirectional call neighborhood."""

    runtime = load_json("runtime/code_intelligence.json")
    maximum_depth = int(runtime["maximum_flow_depth"])
    maximum_edges = int(runtime["maximum_flow_edges"])
    frontier = {symbol, symbol.rsplit(".", 1)[-1]}
    visited = set(frontier)
    selected: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str, int]] = set()
    for depth in range(maximum_depth):
        next_frontier: set[str] = set()
        for call in graph.calls:
            caller_aliases = {call.caller, call.caller.rsplit(".", 1)[-1]}
            callee_aliases = {call.callee, call.callee.rsplit(".", 1)[-1]}
            if not (frontier & caller_aliases or frontier & callee_aliases):
                continue
            edge_key = (call.caller, call.callee, call.path, call.line)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            selected.append(
                {
                    "caller": call.caller,
                    "callee": call.callee,
                    "path": call.path,
                    "line": call.line,
                    "depth": depth + 1,
                }
            )
            next_frontier.update(caller_aliases | callee_aliases)
            if len(selected) >= maximum_edges:
                break
        if len(selected) >= maximum_edges:
            break
        next_frontier -= visited
        if not next_frontier:
            break
        visited.update(next_frontier)
        frontier = next_frontier
    definitions = [
        {
            "name": item.name,
            "qualified_name": item.qualified_name or item.name,
            "path": item.path,
            "start_line": item.line,
            "end_line": item.end_line,
        }
        for item in graph.symbols
        if {item.name, item.qualified_name, item.name.rsplit(".", 1)[-1]} & visited
    ]
    return {"edges": selected, "definitions": definitions[:maximum_edges]}


def _validate_deep_hunt_result(
    root: Path,
    candidate: Candidate,
    review: DeepHuntResult,
    *,
    metadata_only: bool = False,
    evidence_paths: frozenset[str] | None = None,
) -> None:
    expected_gates = {
        "design_invariant",
        "reachability",
        "attacker_control",
        "effective_defense",
        "new_capability",
        "falsification",
        "reproduction",
        "remediation_invariant",
    }
    gates = {str(item.get("gate", "")): str(item.get("verdict", "")) for item in review.gate_results}
    if set(gates) != expected_gates or len(review.gate_results) != len(expected_gates):
        raise AIResponseError("AI review did not return exactly one verdict for every verification gate")
    if review.supported:
        if any(verdict != "pass" for verdict in gates.values()):
            raise AIResponseError("AI review supported a finding without passing every verification gate")
        if review.rejection_reason:
            raise AIResponseError("AI review returned a rejection reason for a supported finding")
        if not review.security_invariant or not review.proof_plan or not review.regression_test:
            raise AIResponseError("AI review omitted required proof or remediation evidence")
        if not review.gained_capability:
            raise AIResponseError("AI review supported a finding without naming the gained capability")
        if not metadata_only and not review.evidence_locations:
            raise AIResponseError("AI review supported a finding without machine-checkable evidence locations")
    elif not review.rejection_reason:
        raise AIResponseError("AI review rejected a candidate without an evidence-backed reason")

    if metadata_only:
        if review.evidence_locations:
            raise AIResponseError("Metadata-only review invented source-code evidence locations")
        return

    # Cross-file findings (change in one file, impact in another) legitimately
    # cite any file the verifier was shown -- not only the candidate's own.
    allowed = evidence_paths or frozenset({candidate.evidence.path})
    line_counts: dict[str, int] = {}
    for location in review.evidence_locations:
        start = int(location.get("start_line", 0))
        end = int(location.get("end_line", 0))
        path = str(location.get("path", ""))
        if path not in allowed:
            raise AIResponseError("AI review cited a location outside the supplied evidence file")
        if path not in line_counts:
            target = (root / path).resolve()
            if root.resolve() not in target.parents or not target.is_file():
                raise AIResponseError("AI review evidence path escapes the repository")
            line_counts[path] = len(target.read_text(encoding="utf-8", errors="replace").splitlines())
        if start < 1 or end < start or end > line_counts[path]:
            raise AIResponseError("AI review cited an invalid evidence line range")


_EVIDENCE_PATH = re.compile(r'"path":\s*"([^"\\]+)"')


def _evidence_paths(
    candidate: Candidate,
    context_expansions: list[dict[str, Any]],
    security_context: str,
) -> frozenset[str]:
    """Repository paths whose source the verifier was actually shown."""

    paths = {candidate.evidence.path}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "path" and isinstance(item, str):
                    paths.add(item)
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(candidate.metadata.get("evidence_packet", {}))
    walk(context_expansions)
    paths.update(_EVIDENCE_PATH.findall(security_context))
    return frozenset(paths)


def _patch_proposal_from_response(response: Any) -> PatchProposal:
    try:
        payload = response_json(response)
        proposal = PatchProposal(
            proposed=bool(payload["proposed"]),
            patch=str(payload["patch"]),
            summary=str(payload["summary"]),
            files_changed=[str(item) for item in payload["files_changed"]],
            risk_notes=str(payload["risk_notes"]),
            confidence=float(payload["confidence"]),
            rejection_reason=str(payload["rejection_reason"]),
        )
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AIResponseError(f"AI patch proposal did not match the required schema: {_schema_failure(exc)}") from exc
    return proposal


def _unified_diff_target_paths(patch_text: str) -> set[str]:
    paths = set()
    for line in patch_text.splitlines():
        if not line.startswith("+++ "):
            continue
        target = line[4:].strip().split("\t", 1)[0].removeprefix("b/")
        paths.add(target)
    return paths


def _validate_patch_proposal(root: Path, proposal: PatchProposal) -> None:
    if not proposal.proposed:
        if not proposal.rejection_reason:
            raise AIResponseError("AI patch proposal declined without an evidence-backed reason")
        return
    if not proposal.patch.strip() or not proposal.files_changed:
        raise AIResponseError("AI patch proposal was missing a diff or the files it changes")
    if _unified_diff_target_paths(proposal.patch) != set(proposal.files_changed):
        raise AIResponseError("AI patch proposal's declared files did not match the diff it produced")
    for relative_path in proposal.files_changed:
        target = (root / relative_path).resolve()
        if root.resolve() not in target.parents or not target.is_file():
            raise AIResponseError("AI patch proposal referenced a file outside the supplied repository")


_GENERATED_NAMES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "composer.lock",
     "poetry.lock", "pipfile.lock", "cargo.lock", "gemfile.lock", "go.sum", "uv.lock"}
)


def _is_generated_path(path: Path) -> bool:
    """Lockfiles and minified bundles carry no reviewable application logic."""
    name = path.name.lower()
    return name in _GENERATED_NAMES or name.endswith((".min.js", ".min.css", ".map"))


def _is_sensitive_path(path: Path) -> bool:
    name = path.name.lower()
    return name.startswith(".env") or any(term in name for term in ("credential", "secret", "id_rsa", "service-account"))


def _production_area(path: str) -> str:
    """First path segment, used as a coarse proxy for a distinct production area of the repository."""
    head = path.split("/", 1)[0]
    return head or "."


def _balanced_area_sample(
    items: list[Any],
    limit: int,
    path_of: Callable[[Any], str],
) -> tuple[list[Any], list[str]]:
    """Select up to `limit` items round-robin across production areas instead of a first-N slice.

    A plain `items[:limit]` slice starves every area but whichever sorts first in the
    underlying list. Interleaving by area keeps every part of the repository represented
    once the repository is larger than the configured limit.
    """
    if len(items) <= limit:
        return list(items), []
    buckets: dict[str, list[Any]] = {}
    for item in items:
        buckets.setdefault(_production_area(path_of(item)), []).append(item)
    areas = sorted(buckets)
    selected: list[Any] = []
    cursor = {area: 0 for area in areas}
    while len(selected) < limit:
        progressed = False
        for area in areas:
            if len(selected) >= limit:
                break
            index = cursor[area]
            bucket = buckets[area]
            if index < len(bucket):
                selected.append(bucket[index])
                cursor[area] = index + 1
                progressed = True
        if not progressed:
            break
    included_ids = {id(item) for item in selected}
    truncated_areas = sorted(
        area for area, bucket in buckets.items() if any(id(item) not in included_ids for item in bucket)
    )
    return selected, truncated_areas


def _security_surface_inventory(
    root: Path,
    graph: StructuralGraph,
    *,
    include_paths: set[str] | None = None,
) -> dict[str, Any]:
    """Build a bounded, syntax-only workset index for repository reconnaissance."""
    config = load_json("runtime/security_worksets.json")
    all_worksets = security_worksets_from_graph(root, graph)
    worksets = all_worksets
    if include_paths is not None:
        worksets = [
            item
            for item in all_worksets
            if any(
                location.path in include_paths
                for security_slice in item.slices
                for location in security_slice.locations
            )
        ]
    limit = int(config["maximum_repository_context_surfaces"])
    location_limit = int(config["maximum_repository_context_locations_per_surface"])
    excerpt_limit = int(config["maximum_repository_context_primary_excerpt_characters"])
    if min(limit, location_limit, excerpt_limit) < 1:
        raise ValueError("repository security-surface limits must be positive")

    counts: dict[str, int] = {}
    for workset in worksets:
        counts[workset.surface_type] = counts.get(workset.surface_type, 0) + 1
    selected, omitted_areas = _balanced_area_sample(
        worksets,
        limit,
        lambda item: item.surface_id.split("::", 1)[0],
    )
    surfaces: list[dict[str, Any]] = []
    for workset in selected:
        all_locations = []
        seen_locations: set[tuple[str, int, int, str]] = set()
        primary_excerpt = ""
        primary_excerpt_truncated = False
        related_symbols: set[str] = set()
        for security_slice in workset.slices:
            for location in security_slice.locations:
                key = (
                    location.path,
                    location.start_line,
                    location.end_line,
                    location.symbol_id,
                )
                if key not in seen_locations:
                    seen_locations.add(key)
                    all_locations.append(location)
                if location.symbol_id == workset.surface_id and not primary_excerpt:
                    primary_excerpt = location.excerpt[:excerpt_limit]
                    primary_excerpt_truncated = len(location.excerpt) > excerpt_limit
            for fact in security_slice.facts:
                if fact.get("kind") in {
                    "route_registration_symbol_reference",
                    "top_level_call_symbol_reference",
                }:
                    symbol_id_value = str(fact.get("symbol_id", ""))
                    if symbol_id_value:
                        related_symbols.add(symbol_id_value)
        surfaces.append(
            {
                "surface_type": workset.surface_type,
                "surface_id": workset.surface_id,
                "complete": workset.complete,
                "primary_excerpt": primary_excerpt,
                "primary_excerpt_truncated": primary_excerpt_truncated,
                "source_locations": [
                    {
                        "path": item.path,
                        "start_line": item.start_line,
                        "end_line": item.end_line,
                        "symbol_id": item.symbol_id,
                    }
                    for item in all_locations[:location_limit]
                ],
                "omitted_location_count": max(0, len(all_locations) - location_limit),
                "related_symbol_ids": sorted(related_symbols),
                "unresolved_edge_ids": list(workset.unresolved_edge_ids),
                "relationship_limitations": list(
                    workset.metadata.get("relationship_limitations", [])
                ),
            }
        )
    return {
        "source": "tree_sitter_syntax_worksets",
        "scope": "incremental_analysis_paths" if include_paths is not None else "repository",
        "total": len(worksets),
        "included": len(selected),
        "truncated": len(selected) < len(worksets),
        "omitted_surface_count": max(0, len(worksets) - len(selected)),
        "outside_scope_surface_count": max(0, len(all_worksets) - len(worksets)),
        "omitted_areas": omitted_areas,
        "counts_by_surface_type": dict(sorted(counts.items())),
        "surfaces": surfaces,
        "interpretation_limits": [
            "syntax observations do not prove callable roles, trust, reachability, data flow, or side effects",
            "omitted surfaces remain unreviewed by this bounded inventory",
        ],
    }


def _source_inventory(
    root: Path,
    exclude: list[str] | None = None,
    max_file_bytes: int | None = None,
) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for path in source_files(root, exclude=exclude, max_file_bytes=max_file_bytes):
        if _is_sensitive_path(path):
            continue
        try:
            line_count = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            continue
        inventory.append(
            {
                "path": path.relative_to(root).as_posix(),
                "language": path.suffix.lower().lstrip(".") or "text",
                "lines": line_count,
            }
        )
    return inventory


def _execute_recon_search_plan(
    root: Path,
    queries: list[dict[str, Any]],
    exclude: list[str] | None,
    max_file_bytes: int | None,
    include_paths: set[str] | None = None,
    error_sink: Callable[[RipgrepQueryError], None] | None = None,
) -> tuple[list[dict[str, Any]], list[SearchHit]]:
    """Execute only model-produced recon searches and return bounded evidence."""

    runtime = load_json("runtime/code_intelligence.json")
    eligible = {
        path.relative_to(root).as_posix()
        for path in source_files(root, exclude=exclude, max_file_bytes=max_file_bytes)
        if not _is_sensitive_path(path)
        and not _is_generated_path(path)
        and (include_paths is None or path.relative_to(root).as_posix() in include_paths)
    }
    discovery = RipgrepDiscovery(root, exclude=exclude or [], max_file_bytes=max_file_bytes)
    evidence: list[dict[str, Any]] = []
    all_hits: list[SearchHit] = []
    total_characters = 0
    evidence_limit = int(runtime["maximum_recon_evidence_characters"])
    hit_limit = int(runtime["maximum_recon_hits_per_query"])
    before = int(runtime["recon_context_lines_before"])
    after = int(runtime["recon_context_lines_after"])
    executor_cap = int(runtime["maximum_hits_per_query"])

    for query in queries:
        try:
            hits = discovery.search_literals(
                str(query["query_id"]),
                [str(item) for item in query["search_terms"]],
                include_globs=[str(item) for item in query.get("include_globs", [])],
                exclude_globs=[str(item) for item in (exclude or [])],
            )
        except RipgrepQueryError as exc:
            if error_sink is not None:
                error_sink(exc)
            evidence.append(
                {
                    "query_id": str(query["query_id"]),
                    "objective": str(query["objective"]),
                    "coverage_targets": [str(item) for item in query["coverage_targets"]],
                    "matches_returned": 0,
                    "results_truncated": False,
                    "query_failed": True,
                    "failure": exc.to_dict(),
                    "evidence": [],
                }
            )
            continue
        safe_hits = [hit for hit in hits if hit.path in eligible]
        all_hits.extend(safe_hits)
        query_evidence: list[dict[str, Any]] = []
        for hit in safe_hits[:hit_limit]:
            target = root / hit.path
            try:
                lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            start = max(0, hit.line - before - 1)
            end = min(len(lines), hit.line + after)
            snippet = _redact("\n".join(f"{number + 1}: {lines[number]}" for number in range(start, end)))
            if total_characters + len(snippet) > evidence_limit:
                break
            total_characters += len(snippet)
            query_evidence.append(
                {
                    "path": hit.path,
                    "line": hit.line,
                    "start_line": start + 1,
                    "end_line": end,
                    "content": snippet,
                }
            )
        evidence.append(
            {
                "query_id": str(query["query_id"]),
                "objective": str(query["objective"]),
                "coverage_targets": [str(item) for item in query["coverage_targets"]],
                "matches_returned": len(safe_hits),
                "results_truncated": len(safe_hits) >= executor_cap or len(safe_hits) > len(query_evidence),
                "query_failed": False,
                "evidence": query_evidence,
            }
        )
    return evidence, all_hits


def _source_segments(
    root: Path,
    max_characters: int = 1600,
    include_paths: set[str] | None = None,
    exclude: list[str] | None = None,
    max_file_bytes: int | None = None,
) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    for path in source_files(root, exclude=exclude, max_file_bytes=max_file_bytes):
        if _is_sensitive_path(path) or _is_generated_path(path):
            continue
        relative = path.relative_to(root).as_posix()
        if include_paths is not None and relative not in include_paths:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        start = 0
        while start < len(lines):
            end = start
            size = 0
            while end < len(lines):
                line_size = len(lines[end]) + 1
                if end > start and size + line_size > max_characters:
                    break
                size += line_size
                end += 1
            content = _redact("\n".join(lines[start:end]))
            segments.append({"path": relative, "start_line": start + 1, "end_line": end, "content": content})
            start = end
    return segments


def _search_segments(
    root: Path,
    queries: list[dict[str, Any]],
    plan: HuntPlan | None,
    graph: StructuralGraph | None,
    exclude: list[str] | None,
    max_file_bytes: int | None,
    include_paths: set[str] | None = None,
    error_sink: Callable[[RipgrepQueryError], None] | None = None,
    stats: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Run AI-created rg queries and expand hits with Tree-sitter Security IR.

    Hits become overlapping windows; windows that overlap or sit close together
    are merged into one region so the same code is reviewed once for every task.
    """

    if plan is None:
        return []
    eligible = {
        path.relative_to(root).as_posix()
        for path in source_files(root, exclude=exclude, max_file_bytes=max_file_bytes)
        if not _is_sensitive_path(path)
        and (include_paths is None or path.relative_to(root).as_posix() in include_paths)
    }
    rg = RipgrepDiscovery(root, exclude=exclude or [], max_file_bytes=max_file_bytes)
    hits_with_tasks: list[tuple[SearchHit, set[str]]] = []
    tasks_with_hits: set[str] = set()
    canonical: dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
    for query in queries:
        identity = (
            tuple(sorted({str(item).strip().lower() for item in query["search_terms"]})),
            tuple(sorted({str(item) for item in query["include_globs"]})),
        )
        merged = canonical.setdefault(identity, {**query, "task_ids": []})
        merged["task_ids"] = sorted({*map(str, merged["task_ids"]), *map(str, query["task_ids"])})
    if stats is not None:
        stats["queries_raw"] = len(queries)
        stats["queries_unique"] = len(canonical)
    for query in canonical.values():
        task_ids = {str(item) for item in query["task_ids"]}
        try:
            hits = rg.search_literals(
                str(query["query_id"]),
                [str(item) for item in query["search_terms"]],
                include_globs=[str(item) for item in query["include_globs"]],
                exclude_globs=exclude or [],
            )
        except RipgrepQueryError as exc:
            if error_sink is not None:
                error_sink(exc)
            continue
        for hit in hits:
            if hit.path in eligible:
                hits_with_tasks.append((hit, task_ids))
                tasks_with_hits.update(task_ids)

    runtime = load_json("runtime/code_intelligence.json")
    runtime_agent = load_json("runtime/agent.json")
    before = int(runtime["context_lines_before"])
    after = int(runtime["context_lines_after"])
    segments_by_key: dict[tuple[str, int, int], dict[str, Any]] = {}
    for hit, task_ids in hits_with_tasks:
        target = root / hit.path
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        enclosing = _enclosing_symbol(graph, hit.path, hit.line)
        start_line = max(1, (enclosing.line if enclosing else hit.line) - before)
        structural_end = enclosing.end_line if enclosing and enclosing.end_line >= enclosing.line else hit.line
        end_line = min(len(lines), structural_end + after)
        key = (hit.path, start_line, end_line)
        segment = segments_by_key.setdefault(
            key,
            {
                "path": hit.path,
                "start_line": start_line,
                "end_line": end_line,
                "content": _redact("\n".join(lines[start_line - 1 : end_line])),
                "content_hash": _indexed_file_hash(graph, hit.path),
                "query_ids": [],
                "task_ids": [],
                "anchor_type": (
                    "http_route"
                    if enclosing is not None and enclosing.kind == "route"
                    else "code_symbol" if enclosing is not None else "source_region"
                ),
                "anchor_id": (
                    (enclosing.qualified_name or enclosing.name)
                    if enclosing is not None
                    else f"{start_line}:{end_line}"
                ),
                "security_ir_slice": _related_ir(graph, hit.path, enclosing.name if enclosing else ""),
            },
        )
        segment["query_ids"] = sorted(set(segment["query_ids"]) | {hit.query_id})
        segment["task_ids"] = sorted(set(segment["task_ids"]) | task_ids)

    missing_task_ids = {task.task_id for task in plan.tasks} - tasks_with_hits
    focus_paths: dict[str, set[str]] = {}
    for task in plan.tasks:
        if task.task_id not in missing_task_ids:
            continue
        for focus in task.focus_paths:
            for path in eligible:
                if path == focus or path.startswith(focus.rstrip("/") + "/") or fnmatch.fnmatch(path, focus):
                    focus_paths.setdefault(path, set()).add(task.task_id)
    if stats is not None:
        stats["windows_raw"] = len(segments_by_key)
    regions = _merge_regions(root, list(segments_by_key.values()), graph, runtime_agent)
    fallback_segments = _source_segments(
        root,
        int(runtime_agent["source_segment_characters"]),
        include_paths=set(focus_paths),
        exclude=exclude,
        max_file_bytes=max_file_bytes,
    )
    fallback_added = 0
    for segment in fallback_segments:
        segment["query_ids"] = []
        segment["task_ids"] = sorted(focus_paths[str(segment["path"])])
        segment["content_hash"] = _indexed_file_hash(graph, str(segment["path"]))
        segment["anchor_type"] = "source_region"
        segment["anchor_id"] = f"{segment['start_line']}:{segment['end_line']}"
        covering = _covering_region(regions, segment, float(runtime_agent["region_overlap_ratio"]))
        if covering is not None:
            # Already reviewed as part of another region: only record the extra obligation.
            covering["task_ids"] = sorted({*covering["task_ids"], *segment["task_ids"]})
            continue
        segment["security_ir_slice"] = _related_ir(graph, str(segment["path"]), "")
        regions.append(segment)
        fallback_added += 1
    if stats is not None:
        stats["regions"] = len(regions)
        stats["fallback_regions"] = fallback_added
    return sorted(regions, key=lambda item: (str(item["path"]), int(item["start_line"])))


def _indexed_file_hash(graph: StructuralGraph | None, path: str) -> str:
    if graph is None:
        return ""
    file_ir = next((item for item in graph.files if item.path == path), None)
    return file_ir.content_hash if file_ir is not None else ""


def _security_workset_review_units(
    segments: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Group region evidence under canonical worksets and bounded review batches.

    Workset batches become the discovery units. Each keeps every underlying
    region as an exact source window for candidate grounding; source excerpts
    are sent once, through the serialized workset slices.
    """

    worksets = security_worksets_from_regions(segments)
    by_location: dict[tuple[str, int, int, str], dict[str, Any]] = {}
    for segment in segments:
        path = str(segment.get("path", ""))
        start = int(segment.get("start_line", 1))
        end = int(segment.get("end_line", start))
        anchor_type = str(segment.get("anchor_type", "line_range"))
        anchor_id = str(segment.get("anchor_id", "")).strip() or f"{start}:{end}"
        surface_id = f"{path}::{anchor_id}"
        if anchor_type == "line_range":
            surface_id = f"{surface_id}::{start}-{end}"
        key = (
            path,
            start,
            end,
            surface_id,
        )
        by_location[key] = segment

    review_units: list[dict[str, Any]] = []
    all_windows: set[tuple[str, int, int]] = set()
    for workset in worksets:
        source_segments: dict[tuple[str, int, int, str], dict[str, Any]] = {}
        for evidence_slice in workset.slices:
            for location in evidence_slice.locations:
                key = (
                    location.path,
                    location.start_line,
                    location.end_line,
                    location.symbol_id,
                )
                source_segment = by_location.get(key)
                if source_segment is None:
                    raise AIResponseError(
                        "a workset evidence slice could not be linked to its source region"
                    )
                source_segments[key] = source_segment
        batches = workset.batches()
        slice_by_id = {item.slice_id: item for item in workset.slices}
        for batch in batches:
            batch_segments: dict[tuple[str, int, int, str], dict[str, Any]] = {}
            source_windows: list[dict[str, Any]] = []
            for batch_slice in batch["slices"]:
                source_slice = slice_by_id.get(str(batch_slice["slice_id"]))
                if source_slice is None:
                    raise AIResponseError("a workset batch referenced an unknown evidence slice")
                for location in source_slice.locations:
                    key = (
                        location.path,
                        location.start_line,
                        location.end_line,
                        location.symbol_id,
                    )
                    batch_segments[key] = source_segments[key]
                    source_windows.append(
                        {
                            "path": location.path,
                            "start_line": location.start_line,
                            "end_line": location.end_line,
                        }
                    )
                    all_windows.add(key)
            members = list(batch_segments.values())
            if not members:
                raise AIResponseError("a workset batch contained no source windows")
            representative = min(
                members,
                key=lambda item: (str(item["path"]), int(item["start_line"])),
            )
            review_units.append(
                {
                    "path": str(representative["path"]),
                    "start_line": int(representative["start_line"]),
                    "end_line": int(representative["end_line"]),
                    "task_ids": sorted(
                        {str(task_id) for item in members for task_id in item.get("task_ids", [])}
                    ),
                    "query_ids": sorted(
                        {str(query_id) for item in members for query_id in item.get("query_ids", [])}
                    ),
                    "allowed_source_windows": source_windows,
                    "_source_region_keys": [
                        {
                            "path": path,
                            "start_line": start,
                            "end_line": end,
                            "surface_id": surface_id,
                        }
                        for path, start, end, surface_id in sorted(batch_segments)
                    ],
                    "security_workset": {
                        **batch,
                        "surface_type": workset.surface_type,
                        "surface_id": workset.surface_id,
                        "slice_count": batch["all_slices_count"],
                        "evidence_source": "region_security_ir_adapter",
                        "semantic_relationships_validated": False,
                    },
                }
            )
    return review_units, {
        "regions": len(segments),
        "regions_with_worksets": len(all_windows),
        "unique_worksets": len(worksets),
        "review_batches": len(review_units),
        "incomplete_worksets": sum(not item.complete for item in worksets),
    }


def _covering_region(regions: list[dict[str, Any]], segment: dict[str, Any], ratio: float) -> dict[str, Any] | None:
    length = max(1, int(segment["end_line"]) - int(segment["start_line"]) + 1)
    for region in regions:
        if region["path"] != segment["path"]:
            continue
        overlap = min(int(region["end_line"]), int(segment["end_line"])) - max(
            int(region["start_line"]), int(segment["start_line"])
        ) + 1
        if overlap / length >= ratio:
            return region
    return None


def _merge_regions(
    root: Path,
    windows: list[dict[str, Any]],
    graph: StructuralGraph | None,
    runtime_agent: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Merge same-file windows that overlap by the configured ratio or sit within the gap."""
    ratio = float(runtime_agent["region_overlap_ratio"])
    gap = int(runtime_agent["region_max_gap_lines"])
    limit = int(runtime_agent["region_max_characters"])
    by_path: dict[str, list[dict[str, Any]]] = {}
    for window in windows:
        by_path.setdefault(str(window["path"]), []).append(window)
    merged_all: list[dict[str, Any]] = []
    for path, items in by_path.items():
        items.sort(key=lambda item: (int(item["start_line"]), int(item["end_line"])))
        current: dict[str, Any] | None = None
        for item in items:
            if current is not None:
                overlap = min(int(current["end_line"]), int(item["end_line"])) - int(item["start_line"]) + 1
                length = max(1, int(item["end_line"]) - int(item["start_line"]) + 1)
                close = int(item["start_line"]) - int(current["end_line"]) <= gap
                span_chars = len(str(current["content"])) + len(str(item["content"]))
                if (overlap / length >= ratio or close) and span_chars <= limit:
                    if (
                        current.get("anchor_type") != item.get("anchor_type")
                        or current.get("anchor_id") != item.get("anchor_id")
                    ):
                        current["anchor_type"] = "source_region"
                    current["end_line"] = max(int(current["end_line"]), int(item["end_line"]))
                    current["query_ids"] = sorted({*current["query_ids"], *item["query_ids"]})
                    current["task_ids"] = sorted({*current["task_ids"], *item["task_ids"]})
                    current["merged_windows"] = int(current.get("merged_windows", 1)) + 1
                    continue
                merged_all.append(current)
            current = dict(item)
        if current is not None:
            merged_all.append(current)
    for region in merged_all:
        if region.get("anchor_type") == "source_region":
            region["anchor_id"] = f"{region['start_line']}:{region['end_line']}"
        if int(region.get("merged_windows", 1)) > 1:
            try:
                lines = (root / str(region["path"])).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            region["content"] = _redact("\n".join(lines[int(region["start_line"]) - 1 : int(region["end_line"])]))
            region["security_ir_slice"] = _related_ir(graph, str(region["path"]), "")
        region.pop("merged_windows", None)
    return merged_all


def _enclosing_symbol(graph: StructuralGraph | None, path: str, line: int):
    if graph is None:
        return None
    matches = [
        symbol
        for symbol in [*graph.symbols, *graph.routes]
        if symbol.path == path and symbol.line <= line and (symbol.end_line <= 0 or line <= symbol.end_line)
    ]
    return min(matches, key=lambda item: max(1, item.end_line - item.line)) if matches else None


def _related_ir(graph: StructuralGraph | None, path: str, symbol_name: str) -> dict[str, Any]:
    if graph is None:
        return {"symbols": [], "calls": [], "references": [], "imports": []}
    files = [item for item in graph.files if item.path == path]
    imports = [value for item in files for value in item.imports]
    calls = [
        {"caller": call.caller, "callee": call.callee, "line": call.line}
        for call in graph.calls
        if call.path == path and (not symbol_name or call.caller == symbol_name)
    ]
    symbols = [
        {
            "name": symbol.name,
            "qualified_name": symbol.qualified_name or symbol.name,
            "line": symbol.line,
            "end_line": symbol.end_line,
            "kind": symbol.kind,
        }
        for symbol in graph.symbols
        if symbol.path == path
    ]
    references = [
        {
            "source": item.source,
            "target": item.target,
            "line": item.line,
            "kind": item.kind,
        }
        for item in graph.references
        if item.path == path and (not symbol_name or item.source == symbol_name)
    ]
    return {"symbols": symbols, "calls": calls, "references": references, "imports": imports}


def _repository_security_ir(
    graph: StructuralGraph,
    runtime: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {
            "path": item.path,
            "language": item.language,
            "symbols": [
                {
                    "name": symbol.name,
                    "qualified_name": symbol.qualified_name or symbol.name,
                    "line": symbol.line,
                    "end_line": symbol.end_line,
                    "kind": symbol.kind,
                }
                for symbol in item.symbols
            ],
            "imports": item.imports,
            "calls": [
                {"caller": call.caller, "callee": call.callee, "line": call.line}
                for call in item.calls
            ],
            "references": [
                {
                    "source": reference.source,
                    "target": reference.target,
                    "line": reference.line,
                    "kind": reference.kind,
                }
                for reference in item.references
            ],
        }
        for item in graph.files[: int(runtime["repository_ir_file_limit"])]
    ]


def _analysis_scope_paths(
    preparation: PreparedContext,
    source_tree: list[str],
) -> list[str]:
    if preparation.reused:
        return list(source_tree)
    if preparation.packet is None:
        return list(source_tree)
    available = set(source_tree)
    paths = set(preparation.changed_paths)
    paths.update(str(item.get("path", "")) for item in preparation.packet.code_slices)
    return sorted(path for path in paths if path in available)


def _schema_failure(exc: BaseException) -> str:
    """Name why a model answer was rejected without echoing the answer itself."""

    if isinstance(exc, json.JSONDecodeError):
        return f"JSONDecodeError: {exc.msg} at char {exc.pos} of {len(exc.doc)}"
    return f"{type(exc).__name__}: {str(exc)[:160]}"


_GROUNDED_ANNOTATION_COLLECTIONS = (
    "input_surfaces",
    "trust_boundaries",
    "sensitive_effects",
    "entry_points",
    "authentication_paths",
    "authorization_decisions",
)


def _annotation_record_identity(collection: str, record: Mapping[str, Any]) -> tuple[str, ...]:
    """Return a stable-enough identity for carrying evidence across an overlay."""

    stable_id = record.get("entry_id") or record.get("effect_id")
    if stable_id:
        return (collection, str(stable_id))
    anchor = record.get("location") or record.get("decision_location") or ""
    return (collection, str(record.get("name", "")), str(anchor))


def _ground_repository_annotations(
    payload: dict[str, Any],
    root: Path,
    graph: StructuralGraph,
    previous_context: Mapping[str, Any] | None = None,
) -> dict[str, int]:
    """Ground model-reported context locations against this immutable source graph.

    This validates only source identity and location. It deliberately does not
    establish that the associated architectural or security claim is true.
    """

    root = root.resolve()
    indexed_files = {item.path: item for item in graph.files}
    prior_by_collection: dict[str, dict[tuple[str, ...], list[dict[str, Any]]]] = {}
    if previous_context is not None:
        for collection in _GROUNDED_ANNOTATION_COLLECTIONS:
            records = previous_context.get(collection, [])
            by_identity: dict[tuple[str, ...], list[dict[str, Any]]] = {}
            if isinstance(records, list):
                for record in records:
                    if not isinstance(record, Mapping):
                        continue
                    locations = record.get("evidence_locations", [])
                    if isinstance(locations, list) and locations:
                        by_identity[_annotation_record_identity(collection, record)] = [
                            dict(location) for location in locations if isinstance(location, Mapping)
                        ]
            prior_by_collection[collection] = by_identity

    summary = {
        "records_total": 0,
        "records_with_verified_locations": 0,
        "records_with_partial_locations": 0,
        "records_without_verified_locations": 0,
        "locations_verified": 0,
        "locations_unverified": 0,
        "locations_carried_forward": 0,
        "semantic_claims_validated": 0,
    }

    for collection in _GROUNDED_ANNOTATION_COLLECTIONS:
        records = payload.get(collection, [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            summary["records_total"] += 1
            locations = record.get("evidence_locations")
            if not isinstance(locations, list) or not locations:
                prior = prior_by_collection.get(collection, {}).get(
                    _annotation_record_identity(collection, record), []
                )
                prior = [
                    location
                    for location in prior
                    if _verify_annotation_location(root, indexed_files, location)[0]
                    == "verified_source_location"
                ]
                if prior:
                    locations = [dict(location, provenance="carried_forward") for location in prior]
                    record["evidence_locations"] = locations
                    summary["locations_carried_forward"] += len(locations)
                else:
                    locations = []

            valid_count = 0
            attempted_count = 0
            for location in locations:
                if not isinstance(location, dict):
                    continue
                attempted_count += 1
                status, source_hash = _verify_annotation_location(root, indexed_files, location)
                location["grounding_status"] = status
                if source_hash:
                    location["source_content_hash"] = source_hash
                    valid_count += 1
                    summary["locations_verified"] += 1
                else:
                    location.pop("source_content_hash", None)
                    summary["locations_unverified"] += 1

            if valid_count == attempted_count and valid_count:
                state = "verified"
                summary["records_with_verified_locations"] += 1
            elif valid_count:
                state = "partial"
                summary["records_with_partial_locations"] += 1
            else:
                state = "unverified" if attempted_count else "none"
                summary["records_without_verified_locations"] += 1
            record["annotation_provenance"] = {
                "origin": "repository_context_model",
                "location_grounding": state,
                "semantic_claim_validation": "not_performed",
            }

    return summary


def _verify_annotation_location(
    root: Path,
    indexed_files: Mapping[str, Any],
    location: dict[str, Any],
) -> tuple[str, str | None]:
    """Validate a location and optional quote against the indexed file version."""

    raw_path = location.get("path")
    if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
        return "invalid_path", None
    relative = Path(raw_path)
    if relative.is_absolute() or ".." in relative.parts:
        return "path_outside_snapshot", None
    normalized = relative.as_posix()
    file_ir = indexed_files.get(normalized)
    if file_ir is None:
        return "path_not_indexed", None
    source_path = (root / relative).resolve()
    if source_path != root and root not in source_path.parents:
        return "path_outside_snapshot", None
    try:
        content = source_path.read_bytes()
    except OSError:
        return "source_unreadable", None
    source_hash = hashlib.sha256(content).hexdigest()
    if source_hash != file_ir.content_hash:
        return "source_version_mismatch", None
    try:
        start_line = int(location["start_line"])
        end_line = int(location["end_line"])
    except (KeyError, TypeError, ValueError):
        return "invalid_line_range", None
    lines = content.decode("utf-8", errors="replace").splitlines()
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        return "invalid_line_range", None
    quote = location.get("quote")
    if quote:
        expected = " ".join(str(quote).split())
        actual = " ".join(" ".join(lines[start_line - 1 : end_line]).split())
        if expected not in actual:
            return "quote_mismatch", None
    return "verified_source_location", source_hash


def _repository_context_from_saved(
    saved: dict[str, object],
    codebase: str,
    revision: str,
    inventory: list[dict[str, Any]],
    source_tree: list[str],
    graph: StructuralGraph,
    context_fabric: dict[str, Any],
) -> AIRepositoryContext:
    def dictionaries(key: str) -> list[dict[str, Any]]:
        values = saved.get(key, [])
        return [dict(item) for item in values if isinstance(item, dict)] if isinstance(values, list) else []

    def strings(key: str) -> list[str]:
        values = saved.get(key, [])
        return [str(item) for item in values] if isinstance(values, list) else []

    return AIRepositoryContext(
        codebase=codebase,
        revision=revision,
        architecture=str(saved.get("architecture", "")),
        applications=dictionaries("applications"),
        source_inventory=inventory,
        source_tree=source_tree,
        graph_symbols=len(graph.symbols),
        graph_routes=len(graph.routes),
        security_ir=_repository_security_ir(graph, load_json("runtime/agent.json")),
        business_context=str(saved.get("business_context", "")),
        context_fabric=context_fabric,
        actors=dictionaries("actors"),
        sensitive_assets=dictionaries("sensitive_assets"),
        input_surfaces=dictionaries("input_surfaces"),
        trust_boundaries=dictionaries("trust_boundaries"),
        security_invariants=strings("security_invariants"),
        coverage_gaps=strings("coverage_gaps"),
        production_areas=dictionaries("production_areas"),
        entry_points=dictionaries("entry_points"),
        sensitive_effects=dictionaries("sensitive_effects"),
        authentication_paths=dictionaries("authentication_paths"),
        authorization_decisions=dictionaries("authorization_decisions"),
        indirect_dispatch=dictionaries("indirect_dispatch"),
        build_time_variants=dictionaries("build_time_variants"),
        coverage_ledger=dictionaries("coverage_ledger"),
        analysis_scope_paths=[],
        annotation_grounding=(
            dict(saved["annotation_grounding"])
            if isinstance(saved.get("annotation_grounding"), dict)
            else {}
        ),
    )


def _compact_repository_context(
    context: AIRepositoryContext,
    focus_path: str,
) -> dict[str, Any]:
    """Build the bounded non-source context reused by per-segment model calls."""

    return _compact_repository_context_value(context.to_dict(), focus_path)


def _compact_repository_context_value(
    source: dict[str, object],
    focus_path: str,
) -> dict[str, Any]:
    runtime = load_json("runtime/code_intelligence.json")
    maximum = int(runtime["maximum_compact_context_items_per_section"])
    omitted = {str(item) for item in runtime["compact_context_omitted_fields"]}
    compact: dict[str, Any] = {
        key: source.get(key)
        for key in runtime["compact_repository_context_scalar_fields"]
        if key in source
    }
    for key in runtime["compact_repository_context_collection_fields"]:
        values = source.get(key, [])
        if not isinstance(values, list):
            continue
        # Original order keeps the context byte-identical across segments so
        # the provider prompt cache can reuse it; focus only re-ranks when
        # the section is too large to include whole.
        ordered = list(enumerate(values))
        if focus_path and len(ordered) > maximum:
            ordered.sort(
                key=lambda item: (
                    0 if focus_path in json.dumps(item[1], ensure_ascii=False) else 1,
                    item[0],
                )
            )
        compact[str(key)] = [
            _without_fields(value, omitted)
            for _index, value in ordered[:maximum]
        ]
    return compact


def _without_fields(value: Any, omitted: set[str]) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _without_fields(item, omitted)
            for key, item in value.items()
            if str(key) not in omitted
        }
    if isinstance(value, list):
        return [_without_fields(item, omitted) for item in value]
    return value


def _payload_characters_for_keys(value: Any, keys: set[str], active: bool = False) -> int:
    if isinstance(value, dict):
        return sum(
            _payload_characters_for_keys(item, keys, active or str(key) in keys)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return sum(_payload_characters_for_keys(item, keys, active) for item in value)
    return len(value) if active and isinstance(value, str) else 0


def _contains_repository_wide_context(value: Any) -> bool:
    broad_keys = {
        str(item)
        for item in load_json("runtime/code_intelligence.json")["repository_wide_context_keys"]
    }
    if isinstance(value, dict):
        return any(
            (str(key) in broad_keys and bool(item)) or _contains_repository_wide_context(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_repository_wide_context(item) for item in value)
    return False


def _query_budget(runtime: Mapping[str, Any], file_count: int, task_count: int) -> int:
    """Search queries the planner may use: tight for small repositories, per-task otherwise."""
    per_task = int(runtime["maximum_dynamic_queries_per_task"])
    total = per_task * task_count
    if 0 < file_count <= int(runtime["small_repository_file_limit"]):
        total = min(
            int(runtime["small_repository_queries_per_task"]) * task_count,
            int(runtime["small_repository_total_queries"]),
        )
    return max(1, total)


def _candidate_from_ai_item(
    root: Path,
    item: dict[str, Any],
    segment: dict[str, Any],
    *,
    allowed_source_windows: list[dict[str, Any]] | None = None,
) -> Candidate | None:
    """Build a Candidate from a discovery/sweep/chain hypothesis.

    Every item surfaced at this stage is an unverified hypothesis, never a verdict: this
    stage identifies open-vocabulary vulnerability classes and gained capabilities, but
    only PlaidNox Deep Hunt independently reviews and can mark a candidate confirmed.
    """
    start = int(item["start_line"])
    end = int(item["end_line"])
    candidate_path = str(item.get("path", ""))
    windows = [segment, *(allowed_source_windows or [])]
    grounded = any(
        candidate_path == str(window.get("path", ""))
        and start >= int(window.get("start_line", 1))
        and end >= start
        and end <= int(window.get("end_line", 0))
        for window in windows
    )
    if not grounded:
        return None
    target = (root / candidate_path).resolve()
    if root.resolve() not in target.parents or not target.is_file():
        return None
    source_lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    if end > len(source_lines):
        return None
    severity = Severity(str(item["severity"]))
    category = re.sub(r"[^a-z0-9_-]", "-", str(item["category"]).lower()).strip("-") or "unclassified"
    title = str(item["title"]).strip()
    if not title:
        return None
    root_cause = {key: str(value) for key, value in dict(item.get("root_cause") or {}).items()}
    snippet = _redact("\n".join(source_lines[start - 1 : end])[:2000])
    return Candidate(
        rule_id=f"plaidnox.ai.{category}",
        title=title,
        vulnerability_class=str(item["vulnerability_class"]),
        severity=severity,
        confidence=float(item["confidence"]),
        message=str(item["message"]),
        evidence=Evidence(
            path=candidate_path,
            start_line=start,
            end_line=end,
            snippet=snippet,
            source_symbol=str(item["path"]),
            sink_symbol=category,
            graph_path=[str(item["path"]), str(item["attack_path"])],
        ),
        metadata={
            "category": category,
            "engine": "plaidnox-litellm-discovery",
            "ai_discovery": True,
            "ai_business_impact": str(item["business_impact"]),
            "classification_references": [dict(reference) for reference in item["classification_references"]],
            "evidence_basis": dict(item.get("evidence_basis", {})),
            "root_cause": root_cause,
            "root_equivalence": {
                key: str(value)
                for key, value in dict(item.get("root_equivalence") or {}).items()
            },
            "attacker_influence": str(item.get("attacker_influence", "")),
            "security_control": str(item.get("security_control", "")),
            "broken_invariant": str(item.get("broken_invariant", "")),
            "sensitive_effect": str(item.get("sensitive_effect", "")),
            "gained_capability": str(item.get("gained_capability", "")),
            "required_context": [str(value) for value in item.get("required_context", [])],
            "candidate_id": str(item.get("candidate_id", "")),
        },
    )


def _tasks_for_segment(
    plan: HuntPlan | None,
    path: str,
    task_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    if plan is None:
        return []
    if task_ids:
        selected = [task.to_dict() for task in plan.tasks if task.task_id in task_ids]
        if selected:
            return selected
    related: list[dict[str, Any]] = []
    for task in plan.tasks:
        if not task.focus_paths or any(
            path == focus or path.startswith(focus.rstrip("/") + "/") for focus in task.focus_paths
        ):
            related.append(task.to_dict())
    return related or [task.to_dict() for task in plan.tasks]


def _hunt_task_from_value(value: dict[str, Any]) -> HuntTask:
    return HuntTask(
        task_id=str(value["task_id"]),
        title=str(value["title"]),
        objective=str(value["objective"]),
        focus_paths=[str(item) for item in value["focus_paths"]],
        entry_points=[str(item) for item in value["entry_points"]],
        vulnerability_themes=[str(item) for item in value["vulnerability_themes"]],
        evidence_requirements=[str(item) for item in value["evidence_requirements"]],
        knowledge_queries=[str(item) for item in value["knowledge_queries"]],
        knowledge_context=[dict(item) for item in value.get("knowledge_context", [])],
        business_invariants=[str(item) for item in value.get("business_invariants", [])],
        coverage_obligations=[str(item) for item in value.get("coverage_obligations", [])],
        falsification_requirements=[str(item) for item in value.get("falsification_requirements", [])],
        inventory_refs=[str(item) for item in value.get("inventory_refs", [])],
        sensitive_effect_refs=[str(item) for item in value.get("sensitive_effect_refs", [])],
        authentication_path_refs=[str(item) for item in value.get("authentication_path_refs", [])],
    )


def _validate_hunt_plan_references(context: AIRepositoryContext, tasks: list[HuntTask]) -> None:
    """Fail closed if a task's *_refs field names an ID absent from the repository context it was built from."""
    valid_inventory_paths = {str(item.get("path", "")) for item in context.source_inventory}
    valid_effect_ids = {str(item.get("effect_id", "")) for item in context.sensitive_effects}
    valid_authentication_paths = {str(item.get("name", "")) for item in context.authentication_paths}
    for task in tasks:
        resolved_refs: list[str] = []
        for ref in task.inventory_refs:
            paths = _resolve_inventory_ref(ref, valid_inventory_paths)
            if not paths:
                raise AIResponseError(
                    f"AI hunt plan task {task.task_id!r} referenced an inventory path not in the repository context: {ref!r}"
                )
            resolved_refs.extend(path for path in paths if path not in resolved_refs)
        task.inventory_refs = resolved_refs
        for ref in task.sensitive_effect_refs:
            if ref not in valid_effect_ids:
                raise AIResponseError(
                    f"AI hunt plan task {task.task_id!r} referenced a sensitive effect not in the repository context: {ref!r}"
                )
        for ref in task.authentication_path_refs:
            if ref not in valid_authentication_paths:
                raise AIResponseError(
                    f"AI hunt plan task {task.task_id!r} referenced an authentication path not in the repository context: {ref!r}"
                )


def _resolve_inventory_ref(ref: str, valid_paths: set[str]) -> list[str]:
    """Map a planner reference to inventory files; a directory names the files under it.

    Planners routinely cite ``views`` or ``./app.js`` for files that do exist.
    Rejecting those discarded the entire hunt plan, so the scan analysed
    nothing. A path matching no inventory file still resolves to nothing and
    fails closed.
    """

    normalized = ref.strip().removeprefix("./").rstrip("/")
    if normalized in valid_paths:
        return [normalized]
    if not normalized:
        return []
    return sorted(path for path in valid_paths if path.startswith(f"{normalized}/"))


def _knowledge_excerpts(entries: list[KnowledgeEntry], decision: str) -> list[dict[str, Any]]:
    excerpt_limit = int(load_json("runtime/agent.json")["knowledge_excerpt_characters"])
    return [
        {
            "knowledge_id": entry.knowledge_id,
            "topic": entry.topic,
            "content": entry.content[:excerpt_limit],
            "vulnerability_class": entry.vulnerability_class,
            "ecosystem": entry.ecosystem,
            "framework": entry.framework,
            "source_url": entry.source_url,
            "source_updated_at": entry.source_updated_at,
            "provenance": entry.provenance,
            "confidence": entry.confidence,
            "retrieval_decision": decision,
        }
        for entry in entries
    ]
