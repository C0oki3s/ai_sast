"""Compute Layer-1 ApplicationContext from an immutable base revision."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from plaidnox_sast.ai import AIRepositoryContext, PlaidNoxDeepHuntAgent
from plaidnox_sast.graph import build_structural_graph

from .assets import load_json
from .context_store import ApplicationContext
from .snapshots import materialize_revision, tree_hash


class ApplicationContextBuilder(Protocol):
    def build(
        self,
        repo_path: Path,
        baseline_revision: str,
        codebase_id: str,
        tenant_id: str,
    ) -> ApplicationContext: ...


class SastApplicationContextBuilder:
    """Adapter from Code Scanning's repository recon into SCM's durable context."""

    def __init__(self, agent: PlaidNoxDeepHuntAgent, business_context: str = "") -> None:
        self._agent = agent
        self._business_context = business_context

    def build(
        self,
        repo_path: Path,
        baseline_revision: str,
        codebase_id: str,
        tenant_id: str,
    ) -> ApplicationContext:
        runtime = load_json("runtime/review.json")
        with materialize_revision(repo_path, baseline_revision) as root:
            graph = build_structural_graph(root)
            context = self._agent.build_repository_context(
                root,
                codebase_id,
                baseline_revision,
                graph,
                business_context=self._business_context,
            )
        return _from_repository_context(
            context,
            tenant_id=tenant_id,
            source_tree_hash=tree_hash(repo_path, baseline_revision),
            context_version=str(runtime["context_version"]),
            builder_version=str(runtime["context_builder_version"]),
        )


def _from_repository_context(
    context: AIRepositoryContext,
    *,
    tenant_id: str,
    source_tree_hash: str,
    context_version: str,
    builder_version: str,
) -> ApplicationContext:
    security_controls: list[object] = []
    security_controls.extend(
        {"kind": "authentication_path", **item} for item in context.authentication_paths
    )
    security_controls.extend(
        {"kind": "authorization_decision", **item} for item in context.authorization_decisions
    )
    security_controls.extend(
        {"kind": "security_invariant", "statement": statement}
        for statement in context.security_invariants
    )
    coverage = list(context.coverage_ledger) or list(context.production_areas)
    complete = sum(
        1
        for item in coverage
        if item.get("status", item.get("coverage_state")) == "complete"
    )
    confidence = complete / len(coverage) if coverage else 0.0
    return ApplicationContext(
        codebase_id=context.codebase,
        tenant_id=tenant_id,
        baseline_revision=context.revision,
        source_tree_hash=source_tree_hash,
        builder_version=builder_version,
        application_type=context.architecture,
        entry_points=tuple(context.entry_points),
        components=(*context.applications, *context.production_areas),
        security_controls=tuple(security_controls),
        routes=tuple(context.entry_points),
        sensitive_effects=tuple(context.sensitive_effects),
        environment_metadata={
            "source_inventory": context.source_inventory,
            "source_tree": context.source_tree,
            "graph_symbols": context.graph_symbols,
            "graph_routes": context.graph_routes,
            "actors": context.actors,
            "sensitive_assets": context.sensitive_assets,
            "input_surfaces": context.input_surfaces,
            "trust_boundaries": context.trust_boundaries,
            "coverage_gaps": context.coverage_gaps,
            "indirect_dispatch": context.indirect_dispatch,
            "build_time_variants": context.build_time_variants,
            "coverage_ledger": context.coverage_ledger,
        },
        identity_provider=None,
        prior_finding_refs=(),
        confidence=confidence,
        context_version=context_version,
        computed_at=datetime.now(UTC),
    )
