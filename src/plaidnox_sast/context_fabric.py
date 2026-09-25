"""Durable, content-addressed security context for incremental code scanning.

This module deliberately stores *derived understanding*, not credentials, raw
prompts, or LLM responses. A context base is immutable; later source snapshots
add a small overlay and only revalidate graph-connected paths.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from .assets import load_json, load_text
from .graph import StructuralGraph, Symbol, stable_symbol_id, stable_symbol_keys
from .worksets import security_summaries_from_graph, validate_security_contract


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _persist_security_summaries(
    conn: sqlite3.Connection, context_id: str, graph: StructuralGraph
) -> None:
    existing_rows = conn.execute(
        load_text("sql/context/list_symbol_summaries.sql"), (context_id,)
    ).fetchall()
    existing = {row["symbol_id"]: json.loads(row["summary_json"]) for row in existing_rows}
    summaries = security_summaries_from_graph(graph)
    for summary in summaries:
        value = summary.to_dict()
        validate_security_contract("security_summary", value)
        prior = existing.get(summary.symbol_id)
        if prior is not None:
            if prior != value:
                raise ValueError(
                "immutable Context Fabric snapshot has conflicting symbol summary data"
            )
            continue
        conn.execute(
            load_text("sql/context/insert_symbol_summary.sql"),
            (
                context_id,
                summary.symbol_id,
                summary.content_hash,
                json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            ),
        )
    incoming_ids = {item.symbol_id for item in summaries}
    if existing and set(existing) != incoming_ids:
        raise ValueError(
            "immutable Context Fabric snapshot has a conflicting symbol summary set"
        )


def _persist_overlay_security_summaries(
    conn: sqlite3.Connection,
    overlay_id: str,
    summaries: Iterable[dict[str, Any]],
    deleted_symbol_ids: Iterable[str] = (),
) -> None:
    existing_rows = conn.execute(
        load_text("sql/context/list_overlay_summary_states.sql"), (overlay_id,)
    ).fetchall()
    existing = {
        row["symbol_id"]: (
            row["summary_state"],
            json.loads(row["summary_json"]) if row["summary_json"] is not None else None,
        )
        for row in existing_rows
    }
    incoming = {str(item["symbol_id"]): dict(item) for item in summaries}
    for symbol_id, value in incoming.items():
        validate_security_contract("security_summary", value)
        prior = existing.get(symbol_id)
        if prior is not None:
            if prior != ("active", value):
                raise ValueError("immutable Context Fabric overlay has conflicting summary data")
            continue
        conn.execute(
            load_text("sql/context/insert_overlay_symbol_summary.sql"),
            (
                overlay_id,
                symbol_id,
                str(value["content_hash"]),
                json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            ),
        )
    deleted = set(deleted_symbol_ids) - set(incoming)
    for symbol_id in deleted:
        prior = existing.get(symbol_id)
        if prior is not None:
            if prior != ("deleted", None):
                raise ValueError("immutable Context Fabric overlay has conflicting summary tombstone")
            continue
        conn.execute(
            load_text("sql/context/insert_overlay_summary_tombstone.sql"),
            (overlay_id, symbol_id),
        )
    if existing and set(existing) != set(incoming) | deleted:
        raise ValueError("immutable Context Fabric overlay has a conflicting summary set")


def _normalise(value: str) -> str:
    return "\n".join(line.rstrip() for line in value.splitlines()).strip()


@dataclass(frozen=True, slots=True)
class ContextBase:
    context_id: str
    repository: str
    commit: str
    symbol_count: int
    reused: bool = False


@dataclass(frozen=True, slots=True)
class ContextOverlay:
    overlay_id: str
    base_context_id: str
    repository: str
    head_commit: str
    changed_paths: list[str]
    changed_symbols: list[str]
    affected_symbols: list[str]
    context_reused_percent: int


@dataclass(frozen=True, slots=True)
class SecurityMemory:
    memory_id: str
    repository: str
    scope: str
    category: str
    statement: str
    source: str
    status: str = "active"
    version: int = 1


@dataclass(frozen=True, slots=True)
class SecurityContextPacket:
    profile: str
    changed_symbols: list[str]
    affected_symbols: list[str]
    code_slices: list[dict[str, str]]
    memories: list[SecurityMemory]
    prior_findings: list[str]
    cache: dict[str, int | bool]

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["memories"] = [asdict(memory) for memory in self.memories]
        return data


@dataclass(frozen=True, slots=True)
class PreparedContext:
    """Incremental context selected for one immutable source snapshot."""

    current: ContextBase
    previous: ContextBase | None
    overlay: ContextOverlay | None
    packet: SecurityContextPacket | None
    previous_repository_context: dict[str, object] | None
    changed_paths: list[str]
    reused: bool


class ContextFabric(Protocol):
    """Persistence-neutral Context Fabric contract used by the scan agent."""

    def create_base(
        self,
        repository: str,
        commit: str,
        root: Path,
        graph: StructuralGraph,
    ) -> ContextBase: ...

    def create_overlay(
        self,
        base: ContextBase,
        head_commit: str,
        root: Path,
        changed_paths: Iterable[str],
        graph: StructuralGraph,
    ) -> ContextOverlay: ...

    def add_memory(
        self,
        repository: str,
        scope: str,
        category: str,
        statement: str,
        source: str,
    ) -> SecurityMemory: ...

    def link_finding(
        self,
        repository: str,
        fingerprint: str,
        context_id: str,
        symbol_ids: Iterable[str],
    ) -> None: ...

    def compile_packet(
        self,
        overlay: ContextOverlay,
        profile: str,
        max_slices: int | None = None,
    ) -> SecurityContextPacket: ...

    def prepare_snapshot(
        self,
        repository: str,
        commit: str,
        root: Path,
        graph: StructuralGraph,
        profile: str = "general",
    ) -> PreparedContext: ...

    def save_repository_context(
        self,
        context_id: str,
        repository: str,
        context: dict[str, object],
    ) -> None: ...


class ContextFabricStore:
    """SQLite Context Fabric adapter for explicit local operation and tests."""

    def __init__(self, database: Path) -> None:
        self.database = database
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_schema(self) -> None:
        manifest = load_json("migrations/context_fabric.json")
        with self._connect() as conn:
            for migration in manifest["migrations"]:
                conn.executescript(load_text(str(migration)))

    def create_base(self, repository: str, commit: str, root: Path, graph: StructuralGraph) -> ContextBase:
        with self._connect() as conn:
            prior = conn.execute(
                load_text("sql/context/find_base.sql"), (repository, commit)
            ).fetchone()
            if prior:
                _persist_security_summaries(conn, prior["context_id"], graph)
                conn.executemany(
                    load_text("sql/context/insert_context_file.sql"),
                    [(prior["context_id"], item.path, item.content_hash) for item in graph.files],
                )
                count = conn.execute(
                    load_text("sql/context/count_symbols.sql"), (prior["context_id"],)
                ).fetchone()[0]
                return ContextBase(prior["context_id"], repository, commit, count, reused=True)

            symbols = _snapshot_symbols(root, graph)
            context_id = f"ctx-{_sha256(repository + ':' + commit)[:12]}"
            conn.execute(load_text("sql/context/insert_base.sql"), (context_id, repository, commit))
            conn.executemany(
                load_text("sql/context/insert_symbol.sql"),
                [(context_id, *symbol) for symbol in symbols],
            )
            conn.executemany(
                load_text("sql/context/insert_edge.sql"),
                [
                    (context_id, source, target, relation)
                    for source, target, relation in _relationship_edges(symbols, graph)
                ],
            )
            conn.executemany(
                load_text("sql/context/insert_context_file.sql"),
                [(context_id, item.path, item.content_hash) for item in graph.files],
            )
            _persist_security_summaries(conn, context_id, graph)
            return ContextBase(context_id, repository, commit, len(symbols))

    def list_security_summaries(self, context_id: str) -> list[dict[str, Any]]:
        """Load versioned structural summaries from an immutable local base."""
        with self._connect() as conn:
            rows = conn.execute(
                load_text("sql/context/list_symbol_summaries.sql"), (context_id,)
            ).fetchall()
        return [json.loads(row["summary_json"]) for row in rows]

    def list_overlay_security_summaries(self, overlay_id: str) -> list[dict[str, Any]]:
        """Load only changed-symbol summaries stored in a branch overlay."""
        with self._connect() as conn:
            rows = conn.execute(
                load_text("sql/context/list_overlay_symbol_summaries.sql"), (overlay_id,)
            ).fetchall()
        return [json.loads(row["summary_json"]) for row in rows]

    def effective_security_summaries(self, overlay_id: str) -> list[dict[str, Any]]:
        """Merge base summaries with changed overlay records and deletion tombstones."""
        with self._connect() as conn:
            base = conn.execute(
                load_text("sql/context/select_overlay_base.sql"), (overlay_id,)
            ).fetchone()
            if base is None:
                raise ValueError("Context Fabric overlay does not exist")
            base_rows = conn.execute(
                load_text("sql/context/list_symbol_summaries.sql"),
                (base["base_context_id"],),
            ).fetchall()
            overlay_rows = conn.execute(
                load_text("sql/context/list_overlay_summary_states.sql"), (overlay_id,)
            ).fetchall()
        merged = {
            row["symbol_id"]: json.loads(row["summary_json"]) for row in base_rows
        }
        for row in overlay_rows:
            if row["summary_state"] == "deleted":
                merged.pop(row["symbol_id"], None)
            else:
                merged[row["symbol_id"]] = json.loads(row["summary_json"])
        return [merged[key] for key in sorted(merged)]

    def prepare_snapshot(
        self,
        repository: str,
        commit: str,
        root: Path,
        graph: StructuralGraph,
        profile: str = "general",
    ) -> PreparedContext:
        with self._connect() as conn:
            exact = conn.execute(
                load_text("sql/context/find_base.sql"), (repository, commit)
            ).fetchone()
            if exact is not None:
                cached = self._load_repository_context(conn, exact["context_id"])
                if cached is not None and not extractor_outdated(cached, graph):
                    count = conn.execute(
                        load_text("sql/context/count_symbols.sql"), (exact["context_id"],)
                    ).fetchone()[0]
                    current = ContextBase(exact["context_id"], repository, commit, count, reused=True)
                    return PreparedContext(current, None, None, None, cached, [], True)
            prior = conn.execute(
                load_text("sql/context/latest_base.sql"),
                (repository, exact["context_id"] if exact is not None else ""),
            ).fetchone()

        if prior is None:
            current = self.create_base(repository, commit, root, graph)
            return PreparedContext(current, None, None, None, None, [item.path for item in graph.files], False)

        with self._connect() as conn:
            prior_count = conn.execute(
                load_text("sql/context/count_symbols.sql"), (prior["context_id"],)
            ).fetchone()[0]
            prior_files = {
                row["path"]: row["content_hash"]
                for row in conn.execute(
                    load_text("sql/context/select_context_files.sql"), (prior["context_id"],)
                ).fetchall()
            }
            previous_context = self._load_repository_context(conn, prior["context_id"])
        current_files = {item.path: item.content_hash for item in graph.files}
        changed_paths = sorted(
            path
            for path in set(prior_files) | set(current_files)
            if prior_files.get(path) != current_files.get(path)
        )
        previous = ContextBase(
            prior["context_id"],
            repository,
            prior["commit_sha"],
            prior_count,
            reused=True,
        )
        current = self.create_base(repository, commit, root, graph)
        if not changed_paths and not extractor_outdated(previous_context, graph):
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
        serialized = json.dumps(context, sort_keys=True, ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                load_text("sql/context/upsert_repository_context.sql"),
                (context_id, repository, serialized, _sha256(serialized)),
            )

    @staticmethod
    def _load_repository_context(
        conn: sqlite3.Connection,
        context_id: str,
    ) -> dict[str, object] | None:
        row = conn.execute(
            load_text("sql/context/load_repository_context.sql"), (context_id,)
        ).fetchone()
        if row is None:
            return None
        value = json.loads(row["context_json"])
        return value if isinstance(value, dict) else None

    def create_overlay(
        self,
        base: ContextBase,
        head_commit: str,
        root: Path,
        changed_paths: Iterable[str],
        graph: StructuralGraph,
    ) -> ContextOverlay:
        changed = sorted({path.replace("\\", "/") for path in changed_paths})
        current = _snapshot_symbols(root, graph, set(changed))
        with self._connect() as conn:
            base_symbols = conn.execute(
                load_text("sql/context/select_base_symbols.sql"), (base.context_id,)
            ).fetchall()
            prior_by_id = {row["symbol_id"]: row for row in base_symbols}
            current_summaries = security_summaries_from_graph(graph)
            current_summary_by_id = {item.symbol_id: item.to_dict() for item in current_summaries}
            base_summary_by_id = {
                row["symbol_id"]: json.loads(row["summary_json"])
                for row in conn.execute(
                    load_text("sql/context/list_symbol_summaries.sql"),
                    (base.context_id,),
                ).fetchall()
            }
            summary_update_ids = {
                symbol_id
                for symbol_id, summary in current_summary_by_id.items()
                if base_summary_by_id.get(symbol_id) != summary
            }
            current_ids = {item[0] for item in current}
            changed_ids: list[str] = []
            for symbol_id, path, name, line, content_hash, _content in current:
                prior = prior_by_id.get(symbol_id)
                if prior is None or prior["content_hash"] != content_hash:
                    changed_ids.append(symbol_id)
            for row in base_symbols:
                if row["path"] in changed and row["symbol_id"] not in current_ids:
                    changed_ids.append(row["symbol_id"])
            for symbol_id, summary in current_summary_by_id.items():
                prior_summary = base_summary_by_id.get(symbol_id)
                if prior_summary is None or prior_summary["content_hash"] != summary["content_hash"]:
                    changed_ids.append(symbol_id)

            changed_ids = sorted(set(changed_ids))
            affected = self._reverse_dependencies(conn, base.context_id, changed_ids)
            overlay_id = f"ovl-{_sha256(base.context_id + ':' + head_commit)[:12]}"
            conn.execute(
                load_text("sql/context/upsert_overlay.sql"),
                (overlay_id, base.context_id, base.repository, head_commit),
            )
            conn.executemany(
                load_text("sql/context/upsert_overlay_change.sql"),
                [
                    (
                        overlay_id,
                        symbol_id,
                        "deleted"
                        if symbol_id not in current_ids and symbol_id not in current_summary_by_id
                        else "modified"
                        if symbol_id in prior_by_id
                        else "added",
                    )
                    for symbol_id in changed_ids
                ],
            )
            conn.execute(load_text("sql/context/delete_overlay_symbols.sql"), (overlay_id,))
            conn.executemany(
                load_text("sql/context/insert_overlay_symbol.sql"),
                [(overlay_id, symbol_id, path, name, line, content) for symbol_id, path, name, line, _content_hash, content in current],
            )
            changed_id_set = set(changed_ids)
            current_summary_ids = {item.symbol_id for item in current_summaries}
            base_summary_ids = set(base_summary_by_id)
            _persist_overlay_security_summaries(
                conn,
                overlay_id,
                [
                    item.to_dict()
                    for item in current_summaries
                    if item.symbol_id in summary_update_ids
                ],
                deleted_symbol_ids=(base_summary_ids & changed_id_set) - current_summary_ids,
            )
            reused = 100 if base.symbol_count == 0 else round(max(0, base.symbol_count - len(set(changed_ids))) * 100 / base.symbol_count)
            return ContextOverlay(overlay_id, base.context_id, base.repository, head_commit, changed, sorted(set(changed_ids)), affected, reused)

    def add_memory(self, repository: str, scope: str, category: str, statement: str, source: str) -> SecurityMemory:
        memory_id = f"mem-{_sha256(repository + scope + category + statement)[:12]}"
        memory = SecurityMemory(memory_id, repository, scope, category, statement, source)
        with self._connect() as conn:
            conn.execute(
                load_text("sql/context/upsert_memory.sql"),
                (memory.memory_id, memory.repository, memory.scope, memory.category, memory.statement, memory.source, memory.status, memory.version),
            )
        return memory

    def link_finding(self, repository: str, fingerprint: str, context_id: str, symbol_ids: Iterable[str]) -> None:
        with self._connect() as conn:
            conn.executemany(
                load_text("sql/context/link_finding.sql"),
                [(repository, fingerprint, symbol_id, context_id) for symbol_id in set(symbol_ids)],
            )

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
        with self._connect() as conn:
            rows = []
            if relevant:
                placeholders = ",".join("?" for _ in relevant)
                packet_query = load_text("sql/context/compile_packet.sql").replace(
                    "{{symbol_placeholders}}", placeholders
                )
                rows = conn.execute(
                    packet_query,
                    [overlay.overlay_id, *relevant, overlay.base_context_id, *relevant, overlay.overlay_id],
                ).fetchall()
            memories = conn.execute(
                load_text("sql/context/active_memories.sql"),
                (overlay.repository, profile),
            ).fetchall()
            prior = []
            if relevant:
                placeholders = ",".join("?" for _ in relevant)
                prior_query = load_text("sql/context/prior_findings.sql").replace(
                    "{{symbol_placeholders}}", placeholders
                )
                prior = conn.execute(
                    prior_query,
                    [overlay.repository, *relevant],
                ).fetchall()
        slices = [{"symbol_id": row["symbol_id"], "path": row["path"], "name": row["name"], "content": row["content"]} for row in rows]
        memory_objects = [SecurityMemory(**dict(row)) for row in memories]
        return SecurityContextPacket(
            profile=profile,
            changed_symbols=overlay.changed_symbols,
            affected_symbols=overlay.affected_symbols,
            code_slices=slices,
            memories=memory_objects,
            prior_findings=sorted(row["fingerprint"] for row in prior),
            cache={
                "base_context_hit": True,
                "reused_symbol_count": max(0, len(rows) - len(overlay.changed_symbols)),
                "context_reused_percent": overlay.context_reused_percent,
            },
        )

    @staticmethod
    def _reverse_dependencies(conn: sqlite3.Connection, context_id: str, changed_symbols: list[str]) -> list[str]:
        affected = set(changed_symbols)
        frontier = set(changed_symbols)
        maximum_depth = int(load_json("runtime/code_intelligence.json")["maximum_reverse_dependency_depth"])
        for _ in range(maximum_depth):
            if not frontier:
                break
            placeholders = ",".join("?" for _ in frontier)
            dependency_query = load_text("sql/context/reverse_dependencies.sql").replace(
                "{{symbol_placeholders}}", placeholders
            )
            rows = conn.execute(
                dependency_query,
                [context_id, *frontier],
            ).fetchall()
            next_frontier = {row["source_symbol"] for row in rows} - affected
            affected.update(next_frontier)
            frontier = next_frontier
        return sorted(affected)


def extractor_outdated(cached: Mapping[str, Any] | None, graph: StructuralGraph) -> bool:
    """A cached context built before route extraction existed must be rebuilt once."""
    if cached is None:
        return False
    return bool(graph.routes) and int(cached.get("graph_routes", 0) or 0) == 0


def _snapshot_symbols(
    root: Path,
    graph: StructuralGraph,
    only_paths: set[str] | None = None,
) -> list[tuple[str, str, str, int, str, str]]:
    records: list[tuple[str, str, str, int, str, str]] = []
    symbols_by_path: dict[str, list[Symbol]] = {}
    for symbol in graph.symbols + graph.routes:
        symbols_by_path.setdefault(symbol.path, []).append(symbol)
    for file_ir in sorted(graph.files, key=lambda item: item.path):
        relative = file_ir.path
        if only_paths is not None and relative not in only_paths:
            continue
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        entries = sorted(symbols_by_path.get(relative, []), key=lambda item: item.line)
        if not entries:
            entries = [Symbol(relative, relative, 1, max(1, len(lines)), "file", relative, "")]
        stable_key_by_symbol = stable_symbol_keys(entries)
        for symbol in entries:
            name = symbol.qualified_name or symbol.name
            line = symbol.line
            end = max(symbol.end_line, line)
            content = _normalise("\n".join(lines[line - 1 : min(end, len(lines))]))
            content_hash = _sha256(content)
            stable_key = stable_key_by_symbol[id(symbol)]
            symbol_id = stable_symbol_id(stable_key)
            records.append((symbol_id, relative, name, line, content_hash, content))
    return records


def _relationship_edges(
    symbols: list[tuple[str, str, str, int, str, str]],
    graph: StructuralGraph,
) -> list[tuple[str, str, str]]:
    """Resolve Tree-sitter calls and references onto stable symbol IDs."""

    by_path_and_name: dict[tuple[str, str], list[str]] = {}
    by_name: dict[str, list[str]] = {}
    for symbol_id, path, name, _line, _hash, _content in symbols:
        by_path_and_name.setdefault((path, name), []).append(symbol_id)
        by_name.setdefault(name, []).append(symbol_id)
        by_name.setdefault(name.rsplit(".", 1)[-1], []).append(symbol_id)
    edges: set[tuple[str, str, str]] = set()
    for call in graph.calls:
        sources = by_path_and_name.get((call.path, call.caller), [])
        callee_name = call.callee.rsplit(".", 1)[-1]
        targets = by_name.get(callee_name, [])
        for source_id in sources:
            for target_id in targets:
                if source_id != target_id:
                    edges.add((source_id, target_id, "calls"))
    for reference in graph.references:
        sources = by_path_and_name.get((reference.path, reference.source), [])
        target_name = reference.target.rsplit(".", 1)[-1]
        targets = by_name.get(target_name, [])
        for source_id in sources:
            for target_id in targets:
                if source_id != target_id:
                    edges.add((source_id, target_id, "references"))
    return sorted(edges)
