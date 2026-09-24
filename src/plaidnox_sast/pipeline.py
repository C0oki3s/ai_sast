from __future__ import annotations

import hashlib
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from .ai import AIConfigurationError, PlaidNoxDeepHuntAgent
from .assets import load_json
from .config import load_local_project_config
from .errors import AIStageError
from .checkpoint import ScanCheckpoint, candidate_from_dict, candidate_to_dict, finding_from_dict, unit_key
from .fingerprint import CandidateIndex, candidate_evidence_packet, candidate_fingerprint, deduplicate
from .graph import build_structural_graph
from .routers import CandidateRouter
from .models import (
    Depth,
    Finding,
    FindingState,
    ModelTier,
    PolicyDecision,
    PolicyResult,
    ScanMode,
    ScanResult,
    Severity,
)
from .persistence import (
    SECURITY_IR_CONTEXT_VERSION,
    FindingDependencyInput,
    FindingEvidenceInput,
    SymbolInput,
    security_ir_inputs,
    snapshot_tree_hash,
    stable_id,
    unit_of_work,
)
from .policy import PolicyEngine
from .saist import DatadogSAISTDetector
from .validation import FindingValidator, priority_score

_SECURITY_IR_CONTEXT_VERSION = SECURITY_IR_CONTEXT_VERSION
_stable_id = stable_id


def _symbol_at_location(symbols_by_path: dict[str, list], path: str, line: int):
    """The Security IR symbol whose line range contains a finding's evidence location."""

    for symbol in symbols_by_path.get(path, []):
        if symbol.start_line <= line <= symbol.end_line:
            return symbol
    return None

def _finding_dependencies(
    finding: Finding,
    symbols: list[SymbolInput],
) -> list[FindingDependencyInput]:
    """Link a verified finding to every evidenced Security IR symbol."""

    locations: list[tuple[str, int, int]] = [
        (finding.evidence.path, finding.evidence.start_line, finding.evidence.end_line)
    ]
    for item in finding.metadata.get("evidence_locations", []):
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).replace("\\", "/")
        if not path:
            continue
        try:
            start = int(item.get("start_line") or item.get("line") or 1)
            end = int(item.get("end_line") or start)
        except (TypeError, ValueError):
            continue
        locations.append((path, start, max(start, end)))

    dependencies: dict[str, FindingDependencyInput] = {}
    for symbol in symbols:
        if any(
            symbol.path == path and symbol.start_line <= end and symbol.end_line >= start
            for path, start, end in locations
        ):
            dependencies[symbol.stable_key] = FindingDependencyInput(
                "symbol",
                symbol.stable_key,
                symbol.content_hash,
            )
    return list(dependencies.values())


def _resumable(checkpoint: ScanCheckpoint | None, stage: str, key: str, run):
    """Replay a completed sweep from the checkpoint; persist it only if it fully succeeded."""

    if checkpoint is not None:
        saved = checkpoint.get(stage, key)
        if saved is not None:
            return [candidate_from_dict(item) for item in saved["candidates"]], 0
    candidates, failures = run()
    if checkpoint is not None and failures == 0:
        checkpoint.put(stage, key, {"candidates": [candidate_to_dict(item) for item in candidates]})
    return candidates, failures


class SastPipeline:
    def __init__(
        self,
        saist_detector: DatadogSAISTDetector | None = None,
        session_factory: sessionmaker[Session] | None = None,
        tenant_id: str = "default",
        checkpoint_path: Path | None = None,
    ) -> None:
        self.checkpoint_path = checkpoint_path
        self.saist_detector = saist_detector
        self.session_factory = session_factory
        self.tenant_id = tenant_id

    def scan_snapshot(
        self,
        root: Path,
        codebase: str,
        revision: str | None = None,
        deep_hunt_agent: PlaidNoxDeepHuntAgent | None = None,
        propose_patches: bool = False,
    ) -> ScanResult:
        """Run the complete deep-hunt workflow against an immutable source snapshot."""

        root = root.resolve()
        if deep_hunt_agent is None:
            raise AIConfigurationError("PlaidNox Deep Hunt is required for every operational scan")
        config = load_local_project_config(root)
        graph = build_structural_graph(root, exclude=config.exclude, max_file_bytes=config.max_file_bytes)
        tree_hash = snapshot_tree_hash(graph)
        revision = revision or f"snapshot-{tree_hash}"
        context_scope = json.dumps(
            {
                "business_context": config.business_context,
                "exclude": sorted(config.exclude),
                "max_file_bytes": config.max_file_bytes,
                "security_context": config.security_context,
                "source_ref": config.source_ref,
                "version": config.version,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        context_scope_hash = hashlib.sha256(context_scope.encode("utf-8")).hexdigest()
        checkpoint: ScanCheckpoint | None = None
        if self.checkpoint_path is not None:
            checkpoint = ScanCheckpoint(
                self.checkpoint_path,
                (
                    f"{codebase}|{revision}|{tree_hash}|{context_scope_hash}|"
                    f"{load_json('prompts/manifest.json')['version']}"
                ),
            )
            configure_checkpoint = getattr(deep_hunt_agent, "configure_checkpoint", None)
            if callable(configure_checkpoint):
                configure_checkpoint(checkpoint)
        configure_source_policy = getattr(deep_hunt_agent, "configure_source_policy", None)
        if callable(configure_source_policy):
            configure_source_policy(config.exclude, config.max_file_bytes)
        reset_model_input_audit = getattr(deep_hunt_agent, "reset_model_input_audit", None)
        if callable(reset_model_input_audit):
            reset_model_input_audit()
        reset_model_budget = getattr(deep_hunt_agent, "reset_model_budget", None)
        if callable(reset_model_budget):
            reset_model_budget()
        reset_search_query_errors = getattr(deep_hunt_agent, "reset_search_query_errors", None)
        if callable(reset_search_query_errors):
            reset_search_query_errors()

        codebase_id = ""
        scan_id = ""
        persistence_enabled = self.session_factory is not None
        persistence_indexed = False
        persistence_error_type = ""
        persistence_error = ""
        persistence_findings_flagged_for_revalidation = 0
        symbols_by_path: dict[str, list] = {}
        if self.session_factory is not None:
            try:
                codebase_id = _stable_id("codebase", self.tenant_id, codebase)
                snapshot_id = _stable_id("snapshot", self.tenant_id, codebase, revision)
                scan_id = _stable_id("scan", codebase_id, snapshot_id)
                workflow_version = str(load_json("prompts/manifest.json")["version"])
                source_files, symbol_inputs, edge_inputs = security_ir_inputs(root, graph)
                persisted_ir = (source_files, symbol_inputs, edge_inputs)
                for symbol in symbol_inputs:
                    symbols_by_path.setdefault(symbol.path, []).append(symbol)
                reverse_dependency_hops = int(
                    load_json("runtime/code_intelligence.json")["maximum_reverse_dependency_depth"]
                )
                with unit_of_work(self.session_factory, self.tenant_id) as repository:
                    repository.add_codebase(codebase_id, external_key=codebase, display_name=codebase)
                    repository.add_snapshot(
                        snapshot_id, codebase_id, revision, tree_hash, _SECURITY_IR_CONTEXT_VERSION
                    )
                    repository.start_scan(scan_id, codebase_id, snapshot_id, mode="deep", workflow_version=workflow_version)
                    repository.save_security_ir(snapshot_id, source_files, symbol_inputs, edge_inputs)
                    # A callee's content changing must revalidate its callers and any
                    # finding that depended on either -- otherwise a fixed or newly
                    # broken callee would leave stale findings looking still current.
                    stale_finding_ids = repository.findings_requiring_revalidation(
                        codebase_id, snapshot_id, reverse_dependency_hops
                    )
                    persistence_findings_flagged_for_revalidation = repository.flag_findings_for_revalidation(
                        stale_finding_ids
                    )
                persistence_indexed = True
            except Exception as exc:  # noqa: BLE001
                # Infra persistence is tolerated like any other optional stage: a
                # database outage must not fail an otherwise-successful in-memory scan.
                persistence_error_type = type(exc).__name__
                persistence_error = str(exc)[:240]

        repository_context: dict[str, object] = {}
        context = None
        plan = None
        ai_discovery_candidates = []
        ai_context_failures = 0
        ai_planning_failures = 0
        ai_discovery_failures = 0
        ai_discovery_error_types: list[str] = []
        ai_discovery_errors: list[str] = []
        ai_discovery_unexpected_failures = 0
        ai_discovery_unresolved_obligations = 0
        ai_required_coverage_unresolved = 0
        ai_discovery_contract_failures = 0
        ai_context_error_type = ""
        ai_context_error = ""
        ai_context_unexpected_failures = 0
        context_builder = getattr(deep_hunt_agent, "build_repository_context", None)
        planner = getattr(deep_hunt_agent, "plan_tasks", None)
        discovery = getattr(deep_hunt_agent, "discover_candidates", None)
        sweeper = getattr(deep_hunt_agent, "sweep_variants", None)
        consolidator = getattr(deep_hunt_agent, "consolidate_findings", None)
        if not all(callable(item) for item in (context_builder, planner, discovery, sweeper, consolidator)):
            raise AIConfigurationError(
                "PlaidNox Deep Hunt agent must provide context, planning, discovery, variant sweeping, and consolidation"
            )
        router = CandidateRouter()
        validator = FindingValidator()
        worker_count = int(load_json("runtime/agent.json")["discovery_max_workers"])
        deep_budget_max = int(load_json("runtime/agent.json")["deep_hunt_budget_max"])

        def verify(candidate_route):
            candidate, route = candidate_route
            finding = validator.validate(codebase, root, candidate, route)
            if finding is None:
                return candidate, None, 0, 0, 0, 1, "", "", False
            review_key = candidate_fingerprint(codebase, candidate)
            saved = checkpoint.get("review", review_key) if checkpoint is not None else None
            if saved is not None:
                if saved["outcome"] == "unsupported":
                    return candidate, None, 1, 0, 0, 1, "", "", False
                return candidate, finding_from_dict(saved["finding"]), 1, 1, 0, 0, "", "", False
            try:
                hunt = getattr(deep_hunt_agent, "hunt", None)
                if not callable(hunt):
                    hunt = deep_hunt_agent.review
                review = hunt(root, candidate, finding, config.security_context, model_tier=route.model_tier, route=route)
                if not review.supported:
                    if checkpoint is not None:
                        checkpoint.put("review", review_key, {"outcome": "unsupported"})
                    return candidate, None, 1, 0, 0, 1, "", "", False
                finding.metadata["deep_hunt"] = review.to_dict()
                finding.title = review.title or finding.title
                finding.vulnerability_class = review.vulnerability_class or finding.vulnerability_class
                finding.metadata["classification_references"] = review.classification_references
                finding.severity = Severity(review.severity) if review.severity else finding.severity
                finding.message = review.message or finding.message
                finding.impact = review.business_impact or finding.impact
                finding.remediation = review.remediation_note or finding.remediation
                finding.confidence = review.confidence
                finding.priority_score = priority_score(
                    finding.severity,
                    finding.confidence,
                    str(finding.metadata.get("route_depth", "standard")),
                )
                finding.state = FindingState.VALIDATED
                finding.validator = "plaidnox-deep-hunt"
                if checkpoint is not None:
                    checkpoint.put("review", review_key, {"outcome": "supported", "finding": finding.to_dict()})
                return candidate, finding, 1, 1, 0, 0, "", "", False
            except Exception as exc:  # noqa: BLE001
                unexpected = not isinstance(exc, AIStageError)
                return candidate, None, 0, 0, 1, 1, type(exc).__name__, str(exc)[:240], unexpected

        try:
            context = context_builder(root, codebase, revision, graph, config.business_context)
            repository_context = context.to_dict()
            plan = planner(context, config.security_context)
            repository_context["hunt_plan"] = plan.to_dict()
            ai_discovery_candidates, ai_discovery_failures = discovery(root, context, plan)
            ai_discovery_error_types = list(getattr(deep_hunt_agent, "discovery_error_types", []))
            ai_discovery_errors = list(getattr(deep_hunt_agent, "discovery_errors", []))
            ai_discovery_unexpected_failures = int(getattr(deep_hunt_agent, "discovery_unexpected_failures", 0))
            ai_discovery_unresolved_obligations = int(
                getattr(deep_hunt_agent, "discovery_unresolved_obligations", 0)
            )
            ai_required_coverage_unresolved = int(
                getattr(deep_hunt_agent, "discovery_required_coverage_unresolved", 0)
            )
            ai_discovery_contract_failures = int(
                getattr(deep_hunt_agent, "discovery_contract_failures", 0)
            )
        except Exception as exc:  # noqa: BLE001
            ai_context_failures += 1
            ai_context_error_type = type(exc).__name__
            ai_context_error = str(exc)[:240]
            if not isinstance(exc, AIStageError):
                # Not a recognized AI/tool-chain failure: tolerated for scan
                # resilience the same as any other stage error, but flagged
                # distinctly so it is not mistaken for ordinary AI flakiness.
                ai_context_unexpected_failures += 1
            repository_context = {"error": ai_context_error_type, "message": ai_context_error}
            if callable(planner):
                ai_planning_failures += 1

        saist_candidates = self.saist_detector.scan(root, graph) if self.saist_detector else []
        candidates, duplicate_count = deduplicate(
            codebase,
            saist_candidates + ai_discovery_candidates,
        )
        for candidate in candidates:
            candidate.metadata["evidence_packet"] = candidate_evidence_packet(candidate).to_dict()

        findings = []
        rejected_count = 0
        ai_reviewed = 0
        ai_supported = 0
        ai_failures = 0
        ai_variant_candidates = 0
        ai_variant_failures = 0
        ai_variant_rounds = 0
        ai_variant_unexpected_failures = 0
        ai_capability_chain_candidates = 0
        ai_capability_chain_failures = 0
        ai_capability_chain_unexpected_failures = 0
        ai_capability_chain_rounds = 0
        deep_budget_demotions = 0
        ai_review_error_types: list[str] = []
        ai_review_errors: list[str] = []
        ai_review_unexpected_failures = 0
        work_queue = list(candidates)
        # Variants and pivots are checked against the same-issue index, so a bug
        # already reviewed under another name is not hunted again.
        seen_candidates = CandidateIndex(nearby_lines=0)
        for candidate in candidates:
            seen_candidates.admit(candidate)
        deep_budget_used = 0

        while work_queue:
            for candidate in work_queue:
                candidate.metadata["evidence_packet"] = candidate_evidence_packet(candidate).to_dict()
            round_routes = [(candidate, router.classify(candidate)) for candidate in work_queue]
            deep_entries = [entry for entry in round_routes if entry[1].model_tier == ModelTier.DEEP]
            remaining_budget = max(0, deep_budget_max - deep_budget_used)
            if len(deep_entries) > remaining_budget:
                # Ranking is deterministic composition over each candidate's already-decided
                # route -- every candidate is still dispositioned via Deep Hunt, only the
                # model tier for the lowest-priority overflow is capped.
                ranked = sorted(
                    deep_entries,
                    key=lambda entry: priority_score(entry[0].severity, entry[0].confidence, entry[1].depth.value),
                    reverse=True,
                )
                demoted_ids = {id(candidate) for candidate, _ in ranked[remaining_budget:]}
                deep_budget_demotions += len(demoted_ids)
                round_routes = [
                    (
                        candidate,
                        replace(
                            route,
                            depth=Depth.STANDARD,
                            model_tier=ModelTier.STANDARD,
                            reason=f"{route.reason}; demoted by scan deep-hunt budget",
                        )
                        if id(candidate) in demoted_ids
                        else route,
                    )
                    for candidate, route in round_routes
                ]
                deep_budget_used += remaining_budget
            else:
                deep_budget_used += len(deep_entries)

            verified_round = []
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                results = executor.map(verify, round_routes)
                for (
                    candidate,
                    finding,
                    reviewed,
                    supported,
                    failed,
                    rejected,
                    error_type,
                    error,
                    unexpected,
                ) in results:
                    ai_reviewed += reviewed
                    ai_supported += supported
                    ai_failures += failed
                    if error_type:
                        ai_review_error_types.append(error_type)
                        ai_review_errors.append(error)
                        ai_review_unexpected_failures += int(unexpected)
                    rejected_count += rejected
                    if finding is not None:
                        findings.append(finding)
                        verified_round.append((candidate, finding))

            next_round = []
            if context is not None and plan is not None and verified_round:
                ai_variant_rounds += 1
                round_key = unit_key(sorted(candidate_fingerprint(codebase, item) for item, _ in verified_round))
                variants, sweep_failures = _resumable(
                    checkpoint, "variants", round_key, lambda: sweeper(root, context, plan, verified_round)
                )
                ai_variant_failures += sweep_failures
                ai_variant_unexpected_failures += int(getattr(deep_hunt_agent, "variant_unexpected_failures", 0))
                for variant in variants:
                    if not seen_candidates.admit(variant):
                        continue
                    next_round.append(variant)
                    ai_variant_candidates += 1

                chainer = getattr(deep_hunt_agent, "chain_capability_pivots", None)
                if callable(chainer):
                    ai_capability_chain_rounds += 1
                    pivots, chain_failures = _resumable(
                        checkpoint, "capability_chain", round_key, lambda: chainer(root, context, plan, verified_round)
                    )
                    ai_capability_chain_failures += chain_failures
                    ai_capability_chain_unexpected_failures += int(
                        getattr(deep_hunt_agent, "capability_chain_unexpected_failures", 0)
                    )
                    for pivot in pivots:
                        if not seen_candidates.admit(pivot):
                            continue
                        next_round.append(pivot)
                        ai_capability_chain_candidates += 1
            work_queue = next_round
        ai_consolidation_failures = 0
        ai_consolidation_error_type = ""
        ai_consolidation_error = ""
        ai_consolidation_unexpected_failure = False
        pre_consolidation_findings = len(findings)
        try:
            findings = consolidator(findings)
            for finding in findings:
                finding.priority_score = priority_score(
                    finding.severity,
                    finding.confidence,
                    str(finding.metadata.get("route_depth", "standard")),
                )
        except Exception as exc:  # noqa: BLE001
            ai_consolidation_failures = 1
            ai_consolidation_error_type = type(exc).__name__
            ai_consolidation_error = str(exc)[:240]
            ai_consolidation_unexpected_failure = not isinstance(exc, AIStageError)
        findings.sort(key=lambda item: (-item.priority_score, item.evidence.path, item.evidence.start_line))

        persistence_findings_saved = 0
        persistence_finding_error_type = ""
        persistence_finding_error = ""
        if self.session_factory is not None and persistence_indexed:
            try:
                with unit_of_work(self.session_factory, self.tenant_id) as repository:
                    for finding in findings:
                        finding_id = _stable_id("finding", codebase_id, finding.fingerprint)
                        evidence = [
                            FindingEvidenceInput(
                                "primary",
                                finding.evidence.path,
                                finding.evidence.start_line,
                                finding.evidence.end_line,
                                finding.evidence.snippet,
                                hashlib.sha256(finding.evidence.snippet.encode("utf-8")).hexdigest(),
                                finding.validator,
                            )
                        ]
                        dependencies = _finding_dependencies(
                            finding,
                            persisted_ir[1] if persisted_ir is not None else [],
                        )
                        repository.save_finding(
                            finding_id,
                            codebase_id,
                            scan_id,
                            finding.fingerprint,
                            finding.title,
                            finding.vulnerability_class,
                            finding.severity.value,
                            finding.state.value,
                            finding.confidence,
                            finding.message,
                            finding.impact,
                            finding.remediation,
                            finding.metadata,
                            evidence,
                            dependencies,
                        )
                        persistence_findings_saved += 1
            except Exception as exc:  # noqa: BLE001
                persistence_finding_error_type = type(exc).__name__
                persistence_finding_error = str(exc)[:240]

        ai_patch_proposals = 0
        ai_patch_verified = 0
        ai_patch_unverified = 0
        ai_patch_proposal_failures = 0
        ai_patch_unexpected_failures = 0
        if propose_patches:
            proposer = getattr(deep_hunt_agent, "propose_patch", None)
            verifier = getattr(deep_hunt_agent, "verify_patch", None)
            if callable(proposer) and callable(verifier):
                for finding in findings:
                    try:
                        proposal = proposer(root, finding)
                        finding.metadata["patch_proposal"] = proposal.to_dict()
                        ai_patch_proposals += 1
                        if not proposal.proposed:
                            continue
                        verification = verifier(root, finding, proposal, config.security_context)
                        finding.metadata["patch_verification"] = verification.to_dict()
                        if verification.verified:
                            ai_patch_verified += 1
                        else:
                            ai_patch_unverified += 1
                        ai_patch_unexpected_failures += int(verification.unexpected_failure)
                    except Exception as exc:  # noqa: BLE001
                        ai_patch_proposal_failures += 1
                        ai_patch_unexpected_failures += int(not isinstance(exc, AIStageError))
                        finding.metadata["patch_proposal_error"] = {
                            "error_type": type(exc).__name__,
                            "error": str(exc)[:240],
                        }

        policy = PolicyEngine().evaluate(findings, config.policy)
        ai_search_query_failures = len(getattr(deep_hunt_agent, "search_query_errors", []))
        ai_knowledge_failures = len(getattr(deep_hunt_agent, "knowledge_errors", []))
        ai_scan_incomplete = bool(
            ai_context_failures
            or ai_planning_failures
            or ai_discovery_failures
            or ai_required_coverage_unresolved
            or ai_discovery_contract_failures
            or ai_failures
            or ai_variant_failures
            or ai_capability_chain_failures
            or ai_consolidation_failures
            or ai_search_query_failures
        )
        if ai_scan_incomplete and policy.decision is PolicyDecision.PASS:
            # Coverage failures must never be reported as a clean scan, so a would-be
            # PASS is downgraded to a distinct INCOMPLETE decision rather than WARN,
            # which stays reserved for a completed scan with findings worth a warning.
            policy = PolicyResult(
                PolicyDecision.INCOMPLETE,
                [
                    "PlaidNox Deep Hunt was incomplete; review coverage gaps and error metrics "
                    "before treating this scan as clean"
                ],
            )
        elif ai_scan_incomplete:
            policy = PolicyResult(
                policy.decision,
                [*policy.reasons, "PlaidNox Deep Hunt was also incomplete; review recorded error metrics"],
            )
        persistence_scan_finalized = False
        if self.session_factory is not None and scan_id:
            try:
                with unit_of_work(self.session_factory, self.tenant_id) as repository:
                    persistence_scan_finalized = repository.finish_scan(
                        scan_id,
                        coverage_complete=not ai_scan_incomplete,
                        failure_code="ai_scan_incomplete" if ai_scan_incomplete else "",
                    )
                    # Feed the tenant monthly cost quota; without this no usage
                    # event is ever written and the quota can never trip.
                    usage_by_model = getattr(
                        getattr(deep_hunt_agent, "model_budget", None), "usage_by_model", dict
                    )()
                    # scan_id is stable per revision, but every run (rescan, worker
                    # retry) really spends, so each run gets its own usage identity.
                    usage_run = uuid.uuid4().hex
                    for model_alias, (input_tokens, output_tokens, cost_usd) in usage_by_model.items():
                        repository.record_model_usage(
                            stable_id("usage", scan_id, usage_run, model_alias),
                            scan_id,
                            model_alias,
                            input_tokens,
                            output_tokens,
                            cost_usd,
                        )
            except Exception as exc:  # noqa: BLE001
                persistence_error_type = persistence_error_type or type(exc).__name__
                persistence_error = persistence_error or str(exc)[:240]
        prompt_cache_metrics = getattr(deep_hunt_agent, "prompt_cache_metrics", dict)()
        model_input_metrics = getattr(deep_hunt_agent, "model_input_metrics", dict)()
        model_budget_metrics = getattr(deep_hunt_agent, "model_budget_metrics", dict)()
        discovery_metrics = dict(getattr(deep_hunt_agent, "discovery_metrics", {}))
        model_input_audit = getattr(deep_hunt_agent, "model_input_audit", list)()
        checkpoint_resume_cursor = checkpoint.resume_cursor() if checkpoint is not None else {}
        if model_input_audit:
            repository_context["model_input_audit"] = model_input_audit
        result = ScanResult(
            codebase=codebase,
            revision=revision,
            mode=ScanMode.DEEP,
            findings=findings,
            policy=policy,
            metrics={
                "saist_candidates": len(saist_candidates),
                "ai_discovery_candidates": len(ai_discovery_candidates),
                "ai_context_failures": ai_context_failures,
                "ai_context_error_type": ai_context_error_type,
                "ai_context_error": ai_context_error,
                "ai_context_unexpected_failures": ai_context_unexpected_failures,
                "ai_planning_failures": ai_planning_failures,
                "ai_discovery_failures": ai_discovery_failures,
                "ai_discovery_error_types": ai_discovery_error_types,
                "ai_discovery_errors": ai_discovery_errors,
                "ai_discovery_unexpected_failures": ai_discovery_unexpected_failures,
                "ai_discovery_unresolved_obligations": ai_discovery_unresolved_obligations,
                "ai_required_coverage_unresolved": ai_required_coverage_unresolved,
                **{
                    f"discovery_{key}": value
                    for key, value in getattr(deep_hunt_agent, "discovery_metrics", {}).items()
                    if key.startswith("canonical_") or key in {"obligations_reconciled_by_sibling", "candidate_grounding_rejections"}
                },
                "ai_discovery_contract_failures": ai_discovery_contract_failures,
                "deduplicated_candidates": duplicate_count,
                "rejected_candidates": rejected_count,
                "validated_findings": len(findings),
                "graph_symbols": len(graph.symbols),
                "graph_routes": len(graph.routes),
                "security_ir_files": len(graph.files),
                "security_ir_calls": len(graph.calls),
                "tree_sitter_files": graph.tree_sitter_files,
                "syntax_fallback_files": graph.fallback_files,
                "rg_queries": graph.rg_queries + int(discovery_metrics.get("queries_raw", 0)),
                "rg_hits": len(graph.search_hits)
                + int(discovery_metrics.get("rg_hits_unique", 0)),
                "rg_queries_recon": graph.rg_queries,
                "rg_queries_discovery": int(discovery_metrics.get("queries_raw", 0)),
                "rg_hits_recon": len(graph.search_hits),
                "rg_hits_discovery": int(discovery_metrics.get("rg_hits_unique", 0)),
                "config_source": config.source_ref,
                "target_code_executed": False,
                "ai_reviews": ai_reviewed,
                "ai_supported": ai_supported,
                "ai_review_failures": ai_failures,
                "ai_review_error_types": ai_review_error_types,
                "ai_review_errors": ai_review_errors,
                "ai_review_unexpected_failures": ai_review_unexpected_failures,
                "ai_variant_candidates": ai_variant_candidates,
                "ai_variant_failures": ai_variant_failures,
                "ai_variant_unexpected_failures": ai_variant_unexpected_failures,
                "ai_variant_rounds": ai_variant_rounds,
                "ai_capability_chain_candidates": ai_capability_chain_candidates,
                "ai_capability_chain_failures": ai_capability_chain_failures,
                "ai_capability_chain_unexpected_failures": ai_capability_chain_unexpected_failures,
                "ai_capability_chain_rounds": ai_capability_chain_rounds,
                "ai_pre_consolidation_findings": pre_consolidation_findings,
                "ai_consolidation_failures": ai_consolidation_failures,
                "ai_consolidation_error_type": ai_consolidation_error_type,
                "ai_consolidation_error": ai_consolidation_error,
                "ai_consolidation_unexpected_failure": ai_consolidation_unexpected_failure,
                "ai_scan_incomplete": ai_scan_incomplete,
                "ai_search_query_failures": ai_search_query_failures,
                "ai_search_query_errors": list(getattr(deep_hunt_agent, "search_query_errors", [])),
                "ai_knowledge_failures": ai_knowledge_failures,
                "ai_knowledge_errors": list(getattr(deep_hunt_agent, "knowledge_errors", [])),
                "ai_patch_proposals": ai_patch_proposals,
                "ai_patch_verified": ai_patch_verified,
                "ai_patch_unverified": ai_patch_unverified,
                "ai_patch_proposal_failures": ai_patch_proposal_failures,
                "ai_patch_unexpected_failures": ai_patch_unexpected_failures,
                "deep_budget_demotions": deep_budget_demotions,
                "verification_started": ai_reviewed + ai_failures,
                "verification_supported": ai_supported,
                "verification_rejected": rejected_count,
                "verification_unresolved": ai_failures,
                "checkpoint_enabled": checkpoint is not None,
                "checkpoint_units_reused": checkpoint.hits if checkpoint is not None else 0,
                "checkpoint_units_saved": checkpoint.writes if checkpoint is not None else 0,
                "checkpoint_units_discarded_stale": checkpoint.discarded if checkpoint is not None else 0,
                "checkpoint_units_pending": (
                    sum(
                        count
                        for status, count in checkpoint.status_counts().items()
                        if status not in {"completed", "superseded"}
                    )
                    if checkpoint is not None
                    else 0
                ),
                "checkpoint_units_failed_retryable": (
                    checkpoint.status_counts().get("failed_retryable", 0) if checkpoint is not None else 0
                ),
                "checkpoint_units_failed_final": (
                    checkpoint.status_counts().get("failed_final", 0) if checkpoint is not None else 0
                ),
                "checkpoint_units_completed": (
                    checkpoint.status_counts().get("completed", 0) if checkpoint is not None else 0
                ),
                "checkpoint_units_superseded": (
                    checkpoint.status_counts().get("superseded", 0) if checkpoint is not None else 0
                ),
                "checkpoint_resume_stage": checkpoint_resume_cursor.get("stage", ""),
                "checkpoint_resume_operation": checkpoint_resume_cursor.get("operation", ""),
                "checkpoint_resume_error_type": checkpoint_resume_cursor.get("last_error_type", ""),
                "persistence_enabled": persistence_enabled,
                "persistence_indexed": persistence_indexed,
                "persistence_error_type": persistence_error_type,
                "persistence_error": persistence_error,
                "persistence_findings_saved": persistence_findings_saved,
                "persistence_finding_error_type": persistence_finding_error_type,
                "persistence_finding_error": persistence_finding_error,
                "persistence_findings_flagged_for_revalidation": persistence_findings_flagged_for_revalidation,
                "persistence_scan_finalized": persistence_scan_finalized,
                **prompt_cache_metrics,
                **model_input_metrics,
                **model_budget_metrics,
                **discovery_metrics,
            },
            repository_context=repository_context,
        )
        if checkpoint is not None:
            checkpoint.close()
        return result
