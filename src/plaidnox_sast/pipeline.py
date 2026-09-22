from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .ai import AIConfigurationError, PlaidNoxDeepHuntAgent
from .assets import load_json
from .config import load_local_project_config
from .fingerprint import candidate_fingerprint, deduplicate
from .graph import build_structural_graph
from .jev import JevClient, JevRouter
from .models import (
    FindingState,
    PolicyDecision,
    PolicyResult,
    ScanMode,
    ScanResult,
    Severity,
)
from .policy import PolicyEngine
from .saist import DatadogSAISTDetector
from .validation import FindingValidator, priority_score


class SastPipeline:
    def __init__(
        self,
        saist_detector: DatadogSAISTDetector | None = None,
        jev_client: JevClient | None = None,
    ) -> None:
        self.saist_detector = saist_detector
        self.jev_client = jev_client

    def scan_snapshot(
        self,
        root: Path,
        codebase: str,
        revision: str | None = None,
        deep_hunt_agent: PlaidNoxDeepHuntAgent | None = None,
    ) -> ScanResult:
        """Run the complete deep-hunt workflow against an immutable source snapshot."""

        root = root.resolve()
        if deep_hunt_agent is None:
            raise AIConfigurationError("PlaidNox Deep Hunt is required for every operational scan")
        config = load_local_project_config(root)
        graph = build_structural_graph(root, exclude=config.exclude, max_file_bytes=config.max_file_bytes)
        revision = revision or _snapshot_revision(graph)
        configure_source_policy = getattr(deep_hunt_agent, "configure_source_policy", None)
        if callable(configure_source_policy):
            configure_source_policy(config.exclude, config.max_file_bytes)

        repository_context: dict[str, object] = {}
        context = None
        plan = None
        ai_discovery_candidates = []
        ai_context_failures = 0
        ai_planning_failures = 0
        ai_discovery_failures = 0
        ai_discovery_error_types: list[str] = []
        ai_discovery_errors: list[str] = []
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
        except Exception as exc:
            ai_context_failures += 1
            repository_context = {"error": type(exc).__name__}
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
        jev_routes = 0
        work_queue = list(candidates)
        seen_candidates = {candidate_fingerprint(codebase, candidate) for candidate in candidates}
        worker_count = int(load_json("runtime/agent.json")["discovery_max_workers"])

        def verify(candidate):
            route = router.classify(candidate)
            jev_used = route.reason.startswith("JEV ")
            finding = validator.validate(codebase, root, candidate, route)
            if finding is None:
                return candidate, None, 0, 0, 0, jev_used, 1
            try:
                hunt = getattr(deep_hunt_agent, "hunt", None)
                if not callable(hunt):
                    hunt = deep_hunt_agent.review
                review = hunt(root, candidate, finding, config.security_context)
                if not review.supported:
                    return candidate, None, 1, 0, 0, jev_used, 1
                finding.metadata["deep_hunt"] = review.to_dict()
                finding.title = review.title or finding.title
                finding.vulnerability_class = review.vulnerability_class or finding.vulnerability_class
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
                return candidate, finding, 1, 1, 0, jev_used, 0
            except Exception:
                return candidate, None, 0, 0, 1, jev_used, 1

        while work_queue:
            verified_round = []
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                results = executor.map(verify, work_queue)
                for candidate, finding, reviewed, supported, failed, jev_used, rejected in results:
                    ai_reviewed += reviewed
                    ai_supported += supported
                    ai_failures += failed
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
        findings.sort(key=lambda item: (-item.priority_score, item.evidence.path, item.evidence.start_line))
        policy = PolicyEngine().evaluate(findings, config.policy)
        if (
            ai_context_failures
            or ai_planning_failures
            or ai_discovery_failures
            or ai_failures
            or ai_variant_failures
            or ai_consolidation_failures
        ) and policy.decision is PolicyDecision.PASS:
            policy = PolicyResult(
                PolicyDecision.WARN,
                ["PlaidNox Deep Hunt was incomplete; review recorded error metrics before treating this scan as clean"],
            )
        prompt_cache_metrics = getattr(deep_hunt_agent, "prompt_cache_metrics", lambda: {})()
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
                "ai_planning_failures": ai_planning_failures,
                "ai_discovery_failures": ai_discovery_failures,
                "ai_discovery_error_types": ai_discovery_error_types,
                "ai_discovery_errors": ai_discovery_errors,
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
                "ai_variant_candidates": ai_variant_candidates,
                "ai_variant_failures": ai_variant_failures,
                "ai_variant_rounds": ai_variant_rounds,
                "ai_pre_consolidation_findings": pre_consolidation_findings,
                "ai_consolidation_failures": ai_consolidation_failures,
                "ai_consolidation_error_type": ai_consolidation_error_type,
                "ai_consolidation_error": ai_consolidation_error,
                "jev_routes": jev_routes,
                **prompt_cache_metrics,
            },
            repository_context=repository_context,
        )


def _snapshot_revision(graph) -> str:
    digest = hashlib.sha256()
    for item in sorted(graph.files, key=lambda value: value.path):
        digest.update(item.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(item.content_hash.encode("ascii"))
        digest.update(b"\0")
    return f"snapshot-{digest.hexdigest()}"
