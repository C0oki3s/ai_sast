from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from .ai import AIConfigurationError, PlaidNoxDeepHuntAgent
from .assets import load_json
from .config import load_local_project_config
from .errors import AIStageError
from .fingerprint import candidate_fingerprint, deduplicate
from .graph import build_structural_graph
from .jev import JevClient, JevRouter
from .models import (
    Finding,
    FindingState,
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


class SastPipeline:
    def __init__(
        self,
        saist_detector: DatadogSAISTDetector | None = None,
        jev_client: JevClient | None = None,
        session_factory: sessionmaker[Session] | None = None,
        tenant_id: str = "default",
    ) -> None:
        self.saist_detector = saist_detector
        self.jev_client = jev_client
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
        configure_source_policy = getattr(deep_hunt_agent, "configure_source_policy", None)
        if callable(configure_source_policy):
            configure_source_policy(config.exclude, config.max_file_bytes)
        reset_model_input_audit = getattr(deep_hunt_agent, "reset_model_input_audit", None)
        if callable(reset_model_input_audit):
            reset_model_input_audit()

        codebase_id = ""
        scan_id = ""
        persistence_enabled = self.session_factory is not None
        persistence_indexed = False
        persistence_error_type = ""
        persistence_error = ""
        persisted_ir = None
        if self.session_factory is not None:
            try:
                codebase_id = _stable_id("codebase", self.tenant_id, codebase)
                snapshot_id = _stable_id("snapshot", self.tenant_id, codebase, revision)
                scan_id = _stable_id("scan", codebase_id, snapshot_id)
                workflow_version = str(load_json("prompts/manifest.json")["version"])
                persisted_ir = security_ir_inputs(root, graph)
                with unit_of_work(self.session_factory, self.tenant_id) as repository:
                    repository.add_codebase(codebase_id, external_key=codebase, display_name=codebase)
                    repository.add_snapshot(
                        snapshot_id, codebase_id, revision, tree_hash, _SECURITY_IR_CONTEXT_VERSION
                    )
                    repository.start_scan(scan_id, codebase_id, snapshot_id, mode="deep", workflow_version=workflow_version)
                    repository.save_security_ir(snapshot_id, *persisted_ir)
                persistence_indexed = True
            except Exception as exc:
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
        try:
            context = context_builder(root, codebase, revision, graph, config.business_context)
            repository_context = context.to_dict()
            plan = planner(context, config.security_context)
            repository_context["hunt_plan"] = plan.to_dict()
            ai_discovery_candidates, ai_discovery_failures = discovery(root, context, plan)
            ai_discovery_error_types = list(getattr(deep_hunt_agent, "discovery_error_types", []))
            ai_discovery_errors = list(getattr(deep_hunt_agent, "discovery_errors", []))
            ai_discovery_unexpected_failures = int(getattr(deep_hunt_agent, "discovery_unexpected_failures", 0))
        except Exception as exc:
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

        router = JevRouter(self.jev_client)
        validator = FindingValidator()
        findings = []
        rejected_count = 0
        ai_reviewed = 0
        ai_supported = 0
        ai_failures = 0
        ai_variant_candidates = 0
        ai_variant_failures = 0
        ai_variant_rounds = 0
        ai_variant_unexpected_failures = 0
        jev_routes = 0
        ai_review_error_types: list[str] = []
        ai_review_errors: list[str] = []
        ai_review_unexpected_failures = 0
        work_queue = list(candidates)
        seen_candidates = {candidate_fingerprint(codebase, candidate) for candidate in candidates}
        worker_count = int(load_json("runtime/agent.json")["discovery_max_workers"])

        def verify(candidate):
            route = router.classify(candidate)
            jev_used = route.reason.startswith("JEV ")
            finding = validator.validate(codebase, root, candidate, route)
            if finding is None:
                return candidate, None, 0, 0, 0, jev_used, 1, "", "", False
            try:
                hunt = getattr(deep_hunt_agent, "hunt", None)
                if not callable(hunt):
                    hunt = deep_hunt_agent.review
                review = hunt(root, candidate, finding, config.security_context, model_tier=route.model_tier)
                if not review.supported:
                    return candidate, None, 1, 0, 0, jev_used, 1, "", "", False
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
                    str(finding.metadata.get("jev_depth", "standard")),
                )
                finding.state = FindingState.VALIDATED
                finding.validator = "plaidnox-deep-hunt"
                return candidate, finding, 1, 1, 0, jev_used, 0, "", "", False
            except Exception as exc:
                unexpected = not isinstance(exc, AIStageError)
                return candidate, None, 0, 0, 1, jev_used, 1, type(exc).__name__, str(exc)[:240], unexpected

        while work_queue:
            verified_round = []
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                results = executor.map(verify, work_queue)
                for (
                    candidate,
                    finding,
                    reviewed,
                    supported,
                    failed,
                    jev_used,
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
                    jev_routes += int(jev_used)
                    rejected_count += rejected
                    if finding is not None:
                        findings.append(finding)
                        verified_round.append((candidate, finding))

            next_round = []
            if context is not None and plan is not None and verified_round:
                ai_variant_rounds += 1
                variants, sweep_failures = sweeper(root, context, plan, verified_round)
                ai_variant_failures += sweep_failures
                ai_variant_unexpected_failures += int(getattr(deep_hunt_agent, "variant_unexpected_failures", 0))
                for variant in variants:
                    fingerprint = candidate_fingerprint(codebase, variant)
                    if fingerprint in seen_candidates:
                        continue
                    seen_candidates.add(fingerprint)
                    next_round.append(variant)
                    ai_variant_candidates += 1
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
                    str(finding.metadata.get("jev_depth", "standard")),
                )
        except Exception as exc:
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
            except Exception as exc:
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
                    except Exception as exc:
                        ai_patch_proposal_failures += 1
                        ai_patch_unexpected_failures += int(not isinstance(exc, AIStageError))
                        finding.metadata["patch_proposal_error"] = {
                            "error_type": type(exc).__name__,
                            "error": str(exc)[:240],
                        }

        policy = PolicyEngine().evaluate(findings, config.policy)
        ai_scan_incomplete = bool(
            ai_context_failures
            or ai_planning_failures
            or ai_discovery_failures
            or ai_failures
            or ai_variant_failures
            or ai_consolidation_failures
        )
        if ai_scan_incomplete and policy.decision is PolicyDecision.PASS:
            # Coverage failures must never be reported as a clean scan, so a would-be
            # PASS is downgraded to a distinct INCOMPLETE decision rather than WARN,
            # which stays reserved for a completed scan with findings worth a warning.
            policy = PolicyResult(
                PolicyDecision.INCOMPLETE,
                ["PlaidNox Deep Hunt was incomplete; review recorded error metrics before treating this scan as clean"],
            )
        elif ai_scan_incomplete:
            policy = PolicyResult(
                policy.decision,
                [*policy.reasons, "PlaidNox Deep Hunt was also incomplete; review recorded error metrics"],
            )
        prompt_cache_metrics = getattr(deep_hunt_agent, "prompt_cache_metrics", dict)()
        model_input_metrics = getattr(deep_hunt_agent, "model_input_metrics", dict)()
        model_input_audit = getattr(deep_hunt_agent, "model_input_audit", list)()
        if model_input_audit:
            repository_context["model_input_audit"] = model_input_audit
        return ScanResult(
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
                "deduplicated_candidates": duplicate_count,
                "rejected_candidates": rejected_count,
                "validated_findings": len(findings),
                "graph_symbols": len(graph.symbols),
                "graph_routes": len(graph.routes),
                "security_ir_files": len(graph.files),
                "security_ir_calls": len(graph.calls),
                "tree_sitter_files": graph.tree_sitter_files,
                "syntax_fallback_files": graph.fallback_files,
                "rg_queries": graph.rg_queries,
                "rg_hits": len(graph.search_hits),
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
                "ai_pre_consolidation_findings": pre_consolidation_findings,
                "ai_consolidation_failures": ai_consolidation_failures,
                "ai_consolidation_error_type": ai_consolidation_error_type,
                "ai_consolidation_error": ai_consolidation_error,
                "ai_consolidation_unexpected_failure": ai_consolidation_unexpected_failure,
                "ai_scan_incomplete": ai_scan_incomplete,
                "ai_patch_proposals": ai_patch_proposals,
                "ai_patch_verified": ai_patch_verified,
                "ai_patch_unverified": ai_patch_unverified,
                "ai_patch_proposal_failures": ai_patch_proposal_failures,
                "ai_patch_unexpected_failures": ai_patch_unexpected_failures,
                "jev_routes": jev_routes,
                "persistence_enabled": persistence_enabled,
                "persistence_indexed": persistence_indexed,
                "persistence_error_type": persistence_error_type,
                "persistence_error": persistence_error,
                "persistence_findings_saved": persistence_findings_saved,
                "persistence_finding_error_type": persistence_finding_error_type,
                "persistence_finding_error": persistence_finding_error,
                **prompt_cache_metrics,
                **model_input_metrics,
            },
            repository_context=repository_context,
        )
