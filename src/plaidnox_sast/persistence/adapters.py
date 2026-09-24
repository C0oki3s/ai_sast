"""PostgreSQL-backed twins of `context_fabric.ContextFabricStore` and
`knowledge.KnowledgeStore`, matching their public method signatures exactly.

`ai.py` and `knowledge.KnowledgeCoordinator` depend on
these stores only through duck-typed method calls, so these adapters are
drop-in replacements: `cli.py` decides which backend to construct, and
nothing else in the codebase needs to change.

Row identity is derived deterministically from `(codebase, revision)` via
`stable_id`, the same scheme `pipeline.py` uses to index a snapshot's Security
IR. In the live pipeline, `pipeline.py` always indexes the codebase/snapshot/
scan rows before `PlaidNoxDeepHuntAgent` touches either store, so these
adapters normally just look the rows up; the self-healing inserts below only
matter when a store is exercised standalone (e.g. in tests) or when the
pipeline's own indexing was skipped or failed.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ..assets import load_json
from ..context_fabric import (
    extractor_outdated,
    ContextBase,
    ContextOverlay,
    PreparedContext,
    SecurityContextPacket,
    SecurityMemory,
)
from ..graph import StructuralGraph
from ..knowledge import KnowledgeDecision, KnowledgeEntry
from .repositories import (
    SECURITY_IR_CONTEXT_VERSION,
    KnowledgeInput,
    KnowledgeValue,
    security_ir_inputs,
    snapshot_tree_hash,
    stable_id,
    symbol_id,
    unit_of_work,
)


def _derive_ids(repository: str, revision: str, tenant_id: str) -> tuple[str, str, str]:
    """Derive globally safe primary keys within an explicit tenant namespace."""

    codebase_id = stable_id("codebase", tenant_id, repository)
    snapshot_id = stable_id("snapshot", tenant_id, repository, revision)
    scan_id = stable_id("scan", codebase_id, snapshot_id)
    return codebase_id, snapshot_id, scan_id


def _entry_from_value(value: KnowledgeValue) -> KnowledgeEntry:
    return KnowledgeEntry(
        knowledge_id=value.knowledge_id,
        topic=value.topic,
        vulnerability_class=value.vulnerability_class,
        ecosystem=value.ecosystem,
        framework=value.framework,
        content=value.content,
        source_url=value.source_url,
        source_title=value.source_title,
        source_updated_at=value.source_updated_at,
        provenance=value.provenance,
        confidence=value.confidence,
        content_hash=value.content_hash,
        claims=list(value.claims),
    )


class PostgresContextFabricStore:
    """Tenant-scoped ORM implementation of the complete Context Fabric API."""

    def __init__(self, session_factory: sessionmaker[Session], tenant_id: str) -> None:
        self.session_factory = session_factory
        self.tenant_id = tenant_id

    def create_base(self, repository: str, commit: str, root: Path, graph: StructuralGraph) -> ContextBase:
        codebase_id, snapshot_id, _scan_id = _derive_ids(repository, commit, self.tenant_id)
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            existing = repo.get_snapshot(snapshot_id)
            if existing is not None:
                repo.save_security_ir(snapshot_id, *security_ir_inputs(root, graph))
                return ContextBase(snapshot_id, repository, commit, repo.count_symbols(snapshot_id), reused=True)
            repo.add_codebase(codebase_id, external_key=repository, display_name=repository)
            repo.add_snapshot(
                snapshot_id, codebase_id, commit, snapshot_tree_hash(graph), SECURITY_IR_CONTEXT_VERSION
            )
            repo.save_security_ir(snapshot_id, *security_ir_inputs(root, graph))
            return ContextBase(snapshot_id, repository, commit, repo.count_symbols(snapshot_id))

    def prepare_snapshot(
        self,
        repository: str,
        commit: str,
        root: Path,
        graph: StructuralGraph,
        profile: str = "general",
    ) -> PreparedContext:
        codebase_id, snapshot_id, _scan_id = _derive_ids(repository, commit, self.tenant_id)
        current = self.create_base(repository, commit, root, graph)
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            cached = repo.get_repository_context(snapshot_id)
            if cached is not None and not extractor_outdated(cached, graph):
                return PreparedContext(current, None, None, None, cached, [], True)
            prior_value = repo.latest_snapshot(codebase_id, exclude_snapshot_id=snapshot_id)
            if prior_value is None:
                return PreparedContext(
                    current,
                    None,
                    None,
                    None,
                    None,
                    [item.path for item in graph.files],
                    False,
                )
            prior_files = {
                item.path: item.content_hash
                for item in repo.list_source_files(prior_value.snapshot_id)
            }
            previous_context = repo.get_repository_context(prior_value.snapshot_id)
            prior_count = repo.count_symbols(prior_value.snapshot_id)
        current_files = {item.path: item.content_hash for item in graph.files}
        changed_paths = sorted(
            path
            for path in set(prior_files) | set(current_files)
            if prior_files.get(path) != current_files.get(path)
        )
        previous = ContextBase(
            prior_value.snapshot_id,
            repository,
            prior_value.revision,
            prior_count,
            reused=True,
        )
        if not changed_paths:
            return PreparedContext(current, previous, None, None, previous_context, [], True)
        overlay = self.create_overlay(previous, commit, root, changed_paths, graph)
        packet = self.compile_packet(overlay, profile)
        return PreparedContext(
            current,
            previous,
            overlay,
            packet,
            previous_context,
            changed_paths,
            False,
        )

    def save_repository_context(
        self,
        context_id: str,
        repository: str,
        context: dict[str, object],
    ) -> None:
        codebase_id, _snapshot_id, _scan_id = _derive_ids(repository, "context", self.tenant_id)
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            repo.save_repository_context(context_id, codebase_id, context)

    def create_overlay(
        self,
        base: ContextBase,
        head_commit: str,
        root: Path,
        changed_paths: Iterable[str],
        graph: StructuralGraph,
    ) -> ContextOverlay:
        changed = sorted({path.replace("\\", "/") for path in changed_paths})
        codebase_id, snapshot_id, _scan_id = _derive_ids(base.repository, head_commit, self.tenant_id)
        files, symbols, edges = security_ir_inputs(root, graph)
        current_by_id = {
            symbol_id(item.stable_key): item
            for item in symbols
            if item.path in changed
        }
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            prior = {
                item.symbol_id: item
                for item in repo.list_symbols(base.context_id, paths=changed)
            }
            changed_ids = {
                current_id
                for current_id, item in current_by_id.items()
                if current_id not in prior or prior[current_id].content_hash != item.content_hash
            }
            changed_ids.update(set(prior) - set(current_by_id))
            maximum_depth = int(load_json("runtime/code_intelligence.json")["maximum_reverse_dependency_depth"])
            affected = repo.reverse_dependencies(base.context_id, changed_ids, hops=maximum_depth)

            repo.add_codebase(codebase_id, external_key=base.repository, display_name=base.repository)
            repo.add_snapshot(
                snapshot_id,
                codebase_id,
                head_commit,
                snapshot_tree_hash(graph),
                SECURITY_IR_CONTEXT_VERSION,
                parent_snapshot_id=base.context_id,
            )
            repo.save_security_ir(snapshot_id, files, symbols, edges)

        reused = (
            100
            if base.symbol_count == 0
            else round(max(0, base.symbol_count - len(changed_ids)) * 100 / base.symbol_count)
        )
        return ContextOverlay(
            overlay_id=snapshot_id,
            base_context_id=base.context_id,
            repository=base.repository,
            head_commit=head_commit,
            changed_paths=changed,
            changed_symbols=sorted(changed_ids),
            affected_symbols=affected,
            context_reused_percent=reused,
        )

    def add_memory(
        self,
        repository: str,
        scope: str,
        category: str,
        statement: str,
        source: str,
    ) -> SecurityMemory:
        codebase_id, _snapshot_id, _scan_id = _derive_ids(repository, "memory", self.tenant_id)
        memory_id = stable_id("memory", repository, scope, category, statement)
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            repo.add_codebase(codebase_id, external_key=repository, display_name=repository)
            value = repo.upsert_security_memory(
                memory_id,
                codebase_id,
                scope,
                category,
                statement,
                source,
            )
        return SecurityMemory(
            memory_id=value.memory_id,
            repository=repository,
            scope=value.scope,
            category=value.category,
            statement=value.statement,
            source=value.provenance,
            status=value.status,
            version=value.version,
        )

    def link_finding(
        self,
        repository: str,
        fingerprint: str,
        context_id: str,
        symbol_ids: Iterable[str],
    ) -> None:
        codebase_id, _snapshot_id, _scan_id = _derive_ids(repository, "finding", self.tenant_id)
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            repo.link_finding_symbols(codebase_id, fingerprint, context_id, symbol_ids)

    def compile_packet(
        self,
        overlay: ContextOverlay,
        profile: str,
        max_slices: int | None = None,
    ) -> SecurityContextPacket:
        if max_slices is None:
            max_slices = int(load_json("runtime/code_intelligence.json")["maximum_context_packet_slices"])
        if max_slices < 1:
            raise ValueError("max_slices must be positive")
        relevant = list(dict.fromkeys(overlay.changed_symbols + overlay.affected_symbols))[:max_slices]
        codebase_id, _snapshot_id, _scan_id = _derive_ids(overlay.repository, "packet", self.tenant_id)
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            current = {item.symbol_id: item for item in repo.list_symbols(overlay.overlay_id, relevant)}
            missing = [item for item in relevant if item not in current]
            base = {item.symbol_id: item for item in repo.list_symbols(overlay.base_context_id, missing)}
            rows = [current.get(item) or base.get(item) for item in relevant]
            memories = repo.active_security_memories(codebase_id, profile)
            prior = repo.prior_findings_for_symbols(codebase_id, overlay.base_context_id, relevant)
        code_slices = [
            {
                "symbol_id": item.symbol_id,
                "path": item.path,
                "name": item.qualified_name,
                "content": item.content,
            }
            for item in rows
            if item is not None
        ]
        memory_objects = [
            SecurityMemory(
                memory_id=item.memory_id,
                repository=overlay.repository,
                scope=item.scope,
                category=item.category,
                statement=item.statement,
                source=item.provenance,
                status=item.status,
                version=item.version,
            )
            for item in memories
        ]
        return SecurityContextPacket(
            profile=profile,
            changed_symbols=overlay.changed_symbols,
            affected_symbols=overlay.affected_symbols,
            code_slices=code_slices,
            memories=memory_objects,
            prior_findings=prior,
            cache={
                "base_context_hit": True,
                "reused_symbol_count": max(0, len(code_slices) - len(overlay.changed_symbols)),
                "context_reused_percent": overlay.context_reused_percent,
            },
        )


class PostgresKnowledgeStore:
    """PostgreSQL-backed twin of `knowledge.KnowledgeStore`.

    Drop-in for `KnowledgeCoordinator(store, router, research_provider)`;
    `KnowledgeCoordinator` are backend-agnostic and are
    reused unmodified.
    """

    def __init__(self, session_factory: sessionmaker[Session], tenant_id: str) -> None:
        self.session_factory = session_factory
        self.tenant_id = tenant_id

    def upsert(self, entry: KnowledgeEntry) -> KnowledgeEntry:
        value = entry.normalised()
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            saved = repo.upsert_knowledge(
                KnowledgeInput(
                    value.knowledge_id,
                    value.topic,
                    value.vulnerability_class,
                    value.ecosystem,
                    value.framework,
                    value.content,
                    value.source_url,
                    value.source_title,
                    value.source_updated_at,
                    value.provenance,
                    value.confidence,
                    value.content_hash,
                    value.claims,
                )
            )
            return _entry_from_value(saved)

    def search(self, query: str, limit: int | None = None) -> list[KnowledgeEntry]:
        runtime = load_json("runtime/agent.json")
        result_limit = int(limit or runtime["knowledge_result_limit"])
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            results = repo.search_knowledge(query, result_limit)
            return [_entry_from_value(item) for item in results]

    def record_usage(
        self,
        repository: str,
        scan_id: str,
        task_id: str,
        query: str,
        decision: KnowledgeDecision,
        entries: list[KnowledgeEntry],
    ) -> None:
        """`task_id` here is the hunt task's LLM-assigned key, not a stored row id.

        The referenced hunt-task row is created eagerly (skeletal, if it does
        not exist yet) so this satisfies the usage record's foreign key even
        when `record_usage` runs before `save_plan` -- which is the normal
        order in `PlaidNoxDeepHuntAgent.plan_tasks`: knowledge is resolved
        per task before the finished plan is persisted.
        """

        _codebase_id, _snapshot_id, real_scan_id = _derive_ids(repository, scan_id, self.tenant_id)
        workflow_version = str(load_json("prompts/manifest.json")["version"])
        plan_id = stable_id("plan", real_scan_id)
        selected = entries or [None]
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            repo.ensure_hunt_plan(plan_id, real_scan_id, workflow_version)
            task = repo.upsert_hunt_task(plan_id, task_id, task_id, "", {})
            for index, entry in enumerate(selected):
                knowledge_id = entry.knowledge_id if entry else None
                usage_id = stable_id("use", real_scan_id, task_id, query, str(knowledge_id), str(index))
                repo.record_knowledge_usage(
                    usage_id,
                    real_scan_id,
                    task.task_id,
                    knowledge_id,
                    query,
                    decision.action,
                    decision.confidence,
                    decision.reason,
                )

    def save_plan(self, repository: str, commit: str, strategy: str, tasks: list[dict[str, Any]]) -> str:
        _codebase_id, _snapshot_id, real_scan_id = _derive_ids(repository, commit, self.tenant_id)
        workflow_version = str(load_json("prompts/manifest.json")["version"])
        plan_id = stable_id("plan", real_scan_id)
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            repo.ensure_hunt_plan(plan_id, real_scan_id, workflow_version, strategy=strategy)
            for task in tasks:
                task_key = str(task["task_id"])
                repo.upsert_hunt_task(
                    plan_id, task_key, str(task.get("title", "")), str(task.get("objective", "")), task
                )
        return plan_id

    def load_plan(self, repository: str, commit: str) -> dict[str, Any] | None:
        _codebase_id, _snapshot_id, real_scan_id = _derive_ids(repository, commit, self.tenant_id)
        workflow_version = str(load_json("prompts/manifest.json")["version"])
        plan_id = stable_id("plan", real_scan_id)
        with unit_of_work(self.session_factory, self.tenant_id) as repo:
            plan = repo.get_hunt_plan(plan_id)
            if plan is None or not plan.strategy or plan.workflow_version != workflow_version:
                return None
            tasks = repo.list_hunt_tasks(plan.plan_id)
            return {
                "plan_id": plan.plan_id,
                "strategy": plan.strategy,
                "tasks": [item.task_data for item in tasks],
            }
