from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol

from .assets import load_json
from .cache_telemetry import LiteLLMCacheTelemetry
from .context_fabric import ContextFabric
from .errors import AIStageError
from .graph import (
    RipgrepDiscovery,
    SearchHit,
    StructuralGraph,
    build_structural_graph,
    readable_source_tree,
    source_files,
)
from .knowledge import KnowledgeCoordinator, KnowledgeEntry, LiteLLMKnowledgeProvider
from .llm import LiteLLMConfigurationError, LiteLLMResponsesClient
from .models import Candidate, Evidence, Finding, ModelTier, Severity
from .prompts import render_operation
from .redaction import redact as _redact
from .redaction import redact_payload


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
    ) -> None:
        self.client = client
        model_runtime = load_json("runtime/models.json")
        self.model = model or str(model_runtime["agent_default_model"])
        self.model_by_tier: dict[str, str] = {
            str(tier): str(name) for tier, name in model_runtime.get("agent_model_by_tier", {}).items()
        }
        self.max_output_tokens = max_output_tokens or int(model_runtime["agent_default_max_output_tokens"])
        self.knowledge_coordinator = knowledge_coordinator
        self.event_sink = event_sink
        self.cache_telemetry = cache_telemetry or LiteLLMCacheTelemetry()
        self.context_store = context_store
        self.discovery_error_types: list[str] = []
        self.discovery_errors: list[str] = []
        self.security_graph: StructuralGraph | None = None
        self.source_excludes: list[str] = []
        self.max_file_bytes: int | None = None

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

    def configure_source_policy(self, exclude: list[str], max_file_bytes: int) -> None:
        self.source_excludes = list(exclude)
        self.max_file_bytes = max_file_bytes

    def prompt_cache_metrics(self) -> dict[str, int | float]:
        return self.cache_telemetry.snapshot().to_metrics()

    def web_knowledge_provider(self) -> LiteLLMKnowledgeProvider:
        return LiteLLMKnowledgeProvider.from_environment(self.cache_telemetry)

    def hunt(
        self,
        root: Path,
        candidate: Candidate,
        finding: Finding,
        security_context: str = "",
        model_tier: ModelTier | None = None,
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
        max_requests = int(runtime["context_expansion_max_requests_per_round"])
        context_expansions: list[dict[str, Any]] = []
        review: DeepHuntResult | None = None
        for round_index in range(max_rounds + 1):
            code_window = "[contents intentionally unavailable]" if metadata_only else _source_window(
                root, candidate.evidence.path, candidate.evidence.start_line, candidate.evidence.end_line
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
            )
            review = _deep_hunt_result_from_response(response)
            _validate_deep_hunt_result(root, candidate, review, metadata_only=metadata_only)
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
                context_expansions.append(_resolve_context_request(root, self.security_graph, request))
        self._emit(
            "candidate_verification_completed",
            rule_id=candidate.rule_id,
            path=candidate.evidence.path,
            supported=review.supported,
            confidence=review.confidence,
        )
        return review

    # Compatibility with integrations built before the dedicated Deep Hunt name.
    def review(
        self,
        root: Path,
        candidate: Candidate,
        finding: Finding,
        security_context: str = "",
        model_tier: ModelTier | None = None,
    ) -> AIReview:
        return self.hunt(root, candidate, finding, security_context, model_tier=model_tier)

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
            except Exception as exc:
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
        if self.context_store is not None:
            base = self.context_store.create_base(codebase, revision, root, graph)
            context_fabric = {
                "context_id": base.context_id,
                "revision": base.commit,
                "symbol_count": base.symbol_count,
                "reused": base.reused,
            }
        manifest = {
            "codebase": codebase,
            "revision": revision,
            "source_inventory": inventory,
            "source_tree": source_tree,
            "routes": [
                {"name": item.name, "path": item.path, "line": item.line}
                for item in graph.routes[: int(runtime["repository_route_limit"])]
            ],
            "symbols": [
                {"name": item.name, "path": item.path, "line": item.line}
                for item in graph.symbols[: int(runtime["repository_symbol_limit"])]
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
                for item in graph.files[: int(runtime["repository_ir_file_limit"])]
            ],
            "business_context": _redact(
                business_context[: int(runtime["business_context_characters"])]
            ),
            "context_fabric": context_fabric,
        }
        recon_queries = self._create_recon_search_plan(manifest)
        recon_evidence, recon_hits = _execute_recon_search_plan(
            root,
            recon_queries,
            self.source_excludes,
            self.max_file_bytes,
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
            payload = json.loads(response.output_text)
            architecture = str(payload["architecture"])
            applications = list(payload["applications"])
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError("AI repository context did not match the required schema") from exc
        context = AIRepositoryContext(
            codebase=codebase,
            revision=revision,
            architecture=architecture,
            applications=applications,
            source_inventory=inventory,
            source_tree=source_tree,
            graph_symbols=len(graph.symbols),
            graph_routes=len(graph.routes),
            security_ir=manifest["security_ir"],
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
            payload = json.loads(response.output_text)
            queries = [dict(item) for item in payload["queries"]]
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError("AI reconnaissance search plan did not match the required schema") from exc
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
            "repository_context": context.to_dict(),
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
            payload = json.loads(response.output_text)
            task_values = list(payload["tasks"])
            strategy = str(payload["strategy"])
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError("AI hunt plan did not match the required schema") from exc

        tasks: list[HuntTask] = []
        self._emit("hunt_plan_generated", codebase=context.codebase, tasks=len(task_values))
        for value in task_values:
            task = _hunt_task_from_value(value)
            if self.knowledge_coordinator is not None:
                self._emit(
                    "knowledge_resolution_started",
                    task_id=task.task_id,
                    queries=len(task.knowledge_queries),
                )
                for _query, decision, entries in self.knowledge_coordinator.resolve_many(
                    context.codebase,
                    context.revision,
                    task.to_dict(),
                    task.knowledge_queries,
                    context.to_dict(),
                ):
                    task.knowledge_context.extend(_knowledge_excerpts(entries, decision.action))
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
        plan_id = ""
        if self.knowledge_coordinator is not None:
            plan_id = self.knowledge_coordinator.store.save_plan(
                context.codebase,
                context.revision,
                strategy,
                [task.to_dict() for task in tasks],
            )
        self._emit("hunt_plan_persisted", plan_id=plan_id, tasks=len(tasks))
        return HuntPlan(plan_id=plan_id, strategy=strategy, tasks=tasks)

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
        segments = _search_segments(
            root,
            queries,
            plan,
            self.security_graph,
            self.source_excludes,
            self.max_file_bytes,
        )
        if not segments:
            raise AIResponseError("AI ripgrep plan produced no reviewable context")

        def analyze(segment: dict[str, Any]) -> tuple[list[Candidate], list[Exception]]:
            segment_candidates: list[Candidate] = []
            errors: list[Exception] = []
            self._emit("source_segment_started", path=segment["path"], start_line=segment["start_line"])
            related_tasks = _tasks_for_segment(
                plan,
                str(segment["path"]),
                {str(item) for item in segment.get("task_ids", [])},
            )
            next_focus = ""
            for _continuation in range(int(runtime["discovery_max_continuations"]) + 1):
                request = {
                    "repository_context": context.to_dict(),
                    "hunt_plan": {"strategy": plan.strategy, "tasks": related_tasks} if plan else None,
                    "source_segment": segment,
                    "continuation_focus": next_focus,
                }
                try:
                    response = self._structured_response(
                        "plaidnox_vulnerability_discovery",
                        load_json("schemas/vulnerability_discovery.json"),
                        "vulnerability_discovery",
                        request,
                    )
                    payload = json.loads(response.output_text)
                    for item in payload["candidates"]:
                        candidate = _candidate_from_ai_item(root, item, segment)
                        if candidate is not None:
                            segment_candidates.append(candidate)
                    if bool(payload["coverage_complete"]):
                        break
                    next_focus = str(payload["next_focus"])
                    if not next_focus:
                        raise AIResponseError("AI marked coverage incomplete without a continuation focus")
                except Exception as exc:
                    errors.append(exc)
                    break
            self._emit(
                "source_segment_completed",
                path=segment["path"],
                start_line=segment["start_line"],
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
                    "repository_context": context.to_dict(),
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
                    payload = json.loads(response.output_text)
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
                except Exception as exc:
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
        except Exception as exc:
            self._emit("variant_search_plan_failed", error_type=type(exc).__name__)
            self.variant_unexpected_failures += int(not isinstance(exc, AIStageError))
            return [], 1
        segments = _search_segments(
            root,
            queries,
            plan,
            self.security_graph,
            self.source_excludes,
            self.max_file_bytes,
        )
        if not segments:
            raise AIResponseError("AI variant-search plan produced no reviewable context")
        with ThreadPoolExecutor(max_workers=int(runtime["sweep_max_workers"])) as executor:
            for segment_variants, segment_failures, segment_unexpected in executor.map(analyze, segments):
                variants.extend(segment_variants)
                failures += segment_failures
                self.variant_unexpected_failures += segment_unexpected
        self._emit("variant_sweep_completed", candidates=len(variants), errors=failures)
        return variants, failures

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
        request = {
            "repository_context": context.to_dict(),
            "hunt_plan": {"plan_id": plan.plan_id, "strategy": plan.strategy, "tasks": compact_tasks},
            "verified_roots": verified_roots or [],
        }
        response = self._structured_response(
            "plaidnox_search_query_plan",
            load_json("schemas/search_query_plan.json"),
            "search_query_plan",
            request,
        )
        try:
            payload = json.loads(response.output_text)
            queries = list(payload["queries"])
            task_ids = {task.task_id for task in plan.tasks}
            covered = {str(task_id) for query in queries for task_id in query["task_ids"]}
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError("AI search plan did not match the required schema") from exc
        missing = task_ids - covered
        if missing:
            raise AIResponseError("AI search plan did not cover every hunt task")
        runtime = load_json("runtime/code_intelligence.json")
        maximum = int(runtime["maximum_dynamic_queries_per_task"]) * len(plan.tasks)
        if len(queries) > maximum:
            raise AIResponseError("AI search plan exceeded the configured query limit")
        self._emit(
            "search_plan_generated",
            queries=len(queries),
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
            consolidation = json.loads(response.output_text)
            assignments = {str(key): str(value) for key, value in consolidation["assignments"].items()}
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError("AI finding consolidation did not match the required schema") from exc

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
            groups = dict(json.loads(narrative_response.output_text)["groups"])
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise AIResponseError("AI finding group narratives did not match the required schema") from exc
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

    def _structured_response(
        self,
        name: str,
        schema: dict[str, Any],
        prompt_operation: str,
        payload: dict[str, Any],
        max_output_tokens: int | None = None,
        model_tier: ModelTier | None = None,
    ) -> Any:
        system_prompt, user_prompt = render_operation(prompt_operation, redact_payload(payload))
        response = self.client.responses.create(
            model=self._model_for_tier(model_tier),
            reasoning={"effort": "low"},
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            text={
                "verbosity": "low",
                "format": {"type": "json_schema", "name": name, "strict": True, "schema": schema},
            },
            max_output_tokens=max_output_tokens or self.max_output_tokens,
        )
        self.cache_telemetry.record_response(response)
        if getattr(response, "status", "completed") != "completed":
            detail = getattr(response, "incomplete_details", None)
            reason = getattr(detail, "reason", "unknown") if detail else "unknown"
            raise AIResponseError(f"AI request was incomplete: {reason}")
        return response


# Kept for artifact and test compatibility with the first MVP. New code uses
# DeepHuntResult, which names the actual PlaidNox domain operation.
AIReview = DeepHuntResult


def load_env_file(path: Path) -> None:
    """Load only KEY=VALUE pairs without evaluating shell syntax."""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {
            "JEV_API_KEY",
            "LITELLM_API_KEY",
            "LITELLM_API_BASE",
            "IFRIT_RESEARCH_PROVIDER",
            "IFRIT_PERPLEXITY_API_KEY",
            "IFRIT_RESEARCH_SONAR_MODEL",
        } and value:
            os.environ.setdefault(key, value.strip().strip("\"'"))


def _source_window(root: Path, relative_path: str, start_line: int, end_line: int) -> str:
    source_path = (root / relative_path).resolve()
    if root.resolve() not in source_path.parents:
        raise AIResponseError("finding path escapes the repository")
    lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, start_line - 41)
    end = min(len(lines), end_line + 40)
    numbered = [f"{index + 1}: {line}" for index, line in enumerate(lines[start:end], start)]
    return _redact("\n".join(numbered)[:12000])


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
        payload = json.loads(response.output_text)
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
            rejection_reason=str(payload["rejection_reason"]),
            gate_results=[dict(item) for item in payload["gate_results"]],
            evidence_locations=[dict(item) for item in payload["evidence_locations"]],
            proof_plan=str(payload["proof_plan"]),
            regression_test=str(payload["regression_test"]),
            context_requests=[dict(item) for item in payload["context_requests"]],
        )
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AIResponseError("AI review did not match the required schema") from exc
    if not 0 <= review.confidence <= 1:
        raise AIResponseError("AI review confidence must be between 0 and 1")
    return review


def _resolve_context_request(
    root: Path,
    security_graph: StructuralGraph | None,
    request: dict[str, Any],
) -> dict[str, Any]:
    """Answer one AI-named Tree-sitter-backed context request from the already-built Security IR."""
    kind = str(request.get("kind", ""))
    path = str(request.get("path", ""))
    symbol = str(request.get("symbol", ""))
    start_line = int(request.get("start_line", 1) or 1)
    end_line = int(request.get("end_line", start_line) or start_line)

    if kind == "window":
        try:
            content = _source_window(root, path, start_line, end_line)
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

    if security_graph is None:
        return {"kind": kind, "symbol": symbol, "resolved": False, "reason": "no Security IR is available"}

    if kind == "definition":
        match = next(
            (item for item in security_graph.symbols if symbol in {item.name, item.qualified_name}),
            None,
        )
        if match is None:
            return {"kind": kind, "symbol": symbol, "resolved": False, "reason": "symbol not found in the Security IR"}
        try:
            content = _source_window(root, match.path, match.line, match.end_line or match.line)
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
        edges = [
            {"caller": call.caller, "callee": call.callee, "path": call.path, "line": call.line}
            for call in security_graph.calls
            if (call.callee == symbol if kind == "callers" else call.caller == symbol)
        ][:5]
        if not edges:
            return {"kind": kind, "symbol": symbol, "resolved": False, "reason": "no matching edges in the Security IR"}
        return {"kind": kind, "symbol": symbol, "resolved": True, "edges": edges}

    if kind == "imports":
        file_ir = next((item for item in security_graph.files if item.path == path), None)
        if file_ir is None:
            return {"kind": kind, "path": path, "resolved": False, "reason": "path not found in the Security IR"}
        return {"kind": kind, "path": path, "resolved": True, "imports": list(file_ir.imports)}

    if kind == "route":
        routes = [
            {"name": route.name, "path": route.path, "line": route.line}
            for route in security_graph.routes
            if symbol == route.name or path == route.path
        ][:5]
        if not routes:
            return {"kind": kind, "symbol": symbol, "resolved": False, "reason": "no matching route in the Security IR"}
        return {"kind": kind, "symbol": symbol, "resolved": True, "routes": routes}

    return {"kind": kind, "resolved": False, "reason": "unsupported context request kind"}


def _validate_deep_hunt_result(
    root: Path,
    candidate: Candidate,
    review: DeepHuntResult,
    *,
    metadata_only: bool = False,
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
        if not metadata_only and not review.evidence_locations:
            raise AIResponseError("AI review supported a finding without machine-checkable evidence locations")
    elif not review.rejection_reason:
        raise AIResponseError("AI review rejected a candidate without an evidence-backed reason")

    if metadata_only:
        if review.evidence_locations:
            raise AIResponseError("Metadata-only review invented source-code evidence locations")
        return

    target = (root / candidate.evidence.path).resolve()
    if root.resolve() not in target.parents or not target.is_file():
        raise AIResponseError("AI review evidence path escapes the repository")
    line_count = len(target.read_text(encoding="utf-8", errors="replace").splitlines())
    for location in review.evidence_locations:
        start = int(location.get("start_line", 0))
        end = int(location.get("end_line", 0))
        if str(location.get("path", "")) != candidate.evidence.path:
            raise AIResponseError("AI review cited a location outside the supplied evidence file")
        if start < 1 or end < start or end > line_count:
            raise AIResponseError("AI review cited an invalid evidence line range")


def _patch_proposal_from_response(response: Any) -> PatchProposal:
    try:
        payload = json.loads(response.output_text)
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
        raise AIResponseError("AI patch proposal did not match the required schema") from exc
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


def _is_sensitive_path(path: Path) -> bool:
    name = path.name.lower()
    return name.startswith(".env") or any(term in name for term in ("credential", "secret", "id_rsa", "service-account"))


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
) -> tuple[list[dict[str, Any]], list[SearchHit]]:
    """Execute only model-produced recon searches and return bounded evidence."""

    runtime = load_json("runtime/code_intelligence.json")
    eligible = {
        path.relative_to(root).as_posix()
        for path in source_files(root, exclude=exclude, max_file_bytes=max_file_bytes)
        if not _is_sensitive_path(path)
    }
    discovery = RipgrepDiscovery(root)
    evidence: list[dict[str, Any]] = []
    all_hits: list[SearchHit] = []
    total_characters = 0
    evidence_limit = int(runtime["maximum_recon_evidence_characters"])
    hit_limit = int(runtime["maximum_recon_hits_per_query"])
    before = int(runtime["recon_context_lines_before"])
    after = int(runtime["recon_context_lines_after"])
    executor_cap = int(runtime["maximum_hits_per_query"])

    for query in queries:
        hits = discovery.search(
            str(query["query_id"]),
            str(query["pattern"]),
            include_globs=[str(item) for item in query.get("include_globs", [])],
            exclude_globs=[str(item) for item in (exclude or [])],
        )
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
        if _is_sensitive_path(path):
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
) -> list[dict[str, Any]]:
    """Run AI-created rg queries and expand hits with Tree-sitter Security IR."""

    if plan is None:
        return []
    eligible = {
        path.relative_to(root).as_posix()
        for path in source_files(root, exclude=exclude, max_file_bytes=max_file_bytes)
        if not _is_sensitive_path(path)
    }
    rg = RipgrepDiscovery(root)
    hits_with_tasks: list[tuple[SearchHit, set[str]]] = []
    tasks_with_hits: set[str] = set()
    for query in queries:
        task_ids = {str(item) for item in query["task_ids"]}
        hits = rg.search(
            str(query["query_id"]),
            str(query["pattern"]),
            include_globs=[str(item) for item in query["include_globs"]],
            exclude_globs=exclude or [],
        )
        for hit in hits:
            if hit.path in eligible:
                hits_with_tasks.append((hit, task_ids))
                tasks_with_hits.update(task_ids)

    runtime = load_json("runtime/code_intelligence.json")
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
                "query_ids": [],
                "task_ids": [],
                "security_ir": _related_ir(graph, hit.path, enclosing.name if enclosing else ""),
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
    fallback_segments = _source_segments(
        root,
        int(load_json("runtime/agent.json")["source_segment_characters"]),
        include_paths=set(focus_paths),
        exclude=exclude,
        max_file_bytes=max_file_bytes,
    )
    for segment in fallback_segments:
        segment["query_ids"] = []
        segment["task_ids"] = sorted(focus_paths[str(segment["path"])])
        segment["security_ir"] = _related_ir(graph, str(segment["path"]), "")
        key = (str(segment["path"]), int(segment["start_line"]), int(segment["end_line"]))
        segments_by_key.setdefault(key, segment)
    return sorted(segments_by_key.values(), key=lambda item: (str(item["path"]), int(item["start_line"])))


def _enclosing_symbol(graph: StructuralGraph | None, path: str, line: int):
    if graph is None:
        return None
    matches = [
        symbol
        for symbol in graph.symbols
        if symbol.path == path and symbol.line <= line and (symbol.end_line <= 0 or line <= symbol.end_line)
    ]
    return min(matches, key=lambda item: max(1, item.end_line - item.line)) if matches else None


def _related_ir(graph: StructuralGraph | None, path: str, symbol_name: str) -> dict[str, Any]:
    if graph is None:
        return {"symbols": [], "calls": [], "imports": []}
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
    return {"symbols": symbols, "calls": calls, "imports": imports}


def _candidate_from_ai_item(root: Path, item: dict[str, Any], segment: dict[str, Any]) -> Candidate | None:
    if not item.get("confirmed") or str(item.get("path", "")) != segment["path"]:
        return None
    start = int(item["start_line"])
    end = int(item["end_line"])
    if start < int(segment["start_line"]) or end < start or end > int(segment["end_line"]):
        return None
    target = (root / str(item["path"])).resolve()
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
    snippet = _redact("\n".join(source_lines[start - 1 : end])[:2000])
    return Candidate(
        rule_id=f"plaidnox.ai.{category}",
        title=title,
        vulnerability_class=str(item["vulnerability_class"]),
        severity=severity,
        confidence=float(item["confidence"]),
        message=str(item["message"]),
        evidence=Evidence(
            path=str(item["path"]),
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
            "ai_remediation": str(item["remediation"]),
            "ai_business_impact": str(item["business_impact"]),
            "classification_references": [dict(reference) for reference in item["classification_references"]],
            "evidence_basis": dict(item.get("evidence_basis", {})),
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
