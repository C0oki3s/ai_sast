"""Durable, content-addressed security context for incremental code scanning.

This module deliberately stores *derived understanding*, not credentials, raw
prompts, or LLM responses. A context base is immutable; later source snapshots
add a small overlay and only revalidate graph-connected paths.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from .assets import load_json, load_text
from .graph import StructuralGraph, Symbol


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
                [(context_id, source, target) for source, target in _call_edges(symbols, graph)],
            )
            return ContextBase(context_id, repository, commit, len(symbols))

    def create_overlay(
        self,
        base: ContextBase,
        head_commit: str,
        root: Path,
        changed_paths: Iterable[str],
        graph: StructuralGraph,
    ) -> ContextOverlay:
        changed = sorted(set(path.replace("\\", "/") for path in changed_paths))
        current = _snapshot_symbols(root, graph, set(changed))
        with self._connect() as conn:
            base_symbols = conn.execute(
                load_text("sql/context/select_base_symbols.sql"), (base.context_id,)
            ).fetchall()
            prior_by_id = {row["symbol_id"]: row for row in base_symbols}
            current_ids = {item[0] for item in current}
            changed_ids: list[str] = []
            for symbol_id, path, name, line, content_hash, _content in current:
                prior = prior_by_id.get(symbol_id)
                if prior is None or prior["content_hash"] != content_hash:
                    changed_ids.append(symbol_id)
            for row in base_symbols:
                if row["path"] in changed and row["symbol_id"] not in current_ids:
                    changed_ids.append(row["symbol_id"])

            affected = self._reverse_dependencies(conn, base.context_id, changed_ids)
            overlay_id = f"ovl-{_sha256(base.context_id + ':' + head_commit)[:12]}"
            conn.execute(
                load_text("sql/context/upsert_overlay.sql"),
                (overlay_id, base.context_id, base.repository, head_commit),
            )
            conn.executemany(
                load_text("sql/context/upsert_overlay_change.sql"),
                [(overlay_id, symbol_id) for symbol_id in changed_ids],
            )
            conn.execute(load_text("sql/context/delete_overlay_symbols.sql"), (overlay_id,))
            conn.executemany(
                load_text("sql/context/insert_overlay_symbol.sql"),
                [(overlay_id, symbol_id, path, name, line, content) for symbol_id, path, name, line, _content_hash, content in current],
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
        identity_counts: dict[tuple[str, str], int] = {}
        for symbol in entries:
            name = symbol.qualified_name or symbol.name
            identity_counts[(symbol.kind, name)] = identity_counts.get((symbol.kind, name), 0) + 1
        duplicate_occurrences: dict[tuple[str, str, str], int] = {}
        for symbol in entries:
            name = symbol.qualified_name or symbol.name
            line = symbol.line
            end = max(symbol.end_line, line)
            content = _normalise("\n".join(lines[line - 1 : min(end, len(lines))]))
            content_hash = _sha256(content)
            stable_key = f"{relative}:{symbol.kind}:{name}"
            if identity_counts[(symbol.kind, name)] > 1:
                signature_hash = _sha256(_normalise(symbol.signature))[:16]
                duplicate_key = (symbol.kind, name, signature_hash)
                occurrence = duplicate_occurrences.get(duplicate_key, 0)
                duplicate_occurrences[duplicate_key] = occurrence + 1
                stable_key = f"{stable_key}:{signature_hash}:{occurrence}"
            symbol_id = f"sym-{_sha256(stable_key)[:16]}"
            records.append((symbol_id, relative, name, line, content_hash, content))
    return records


def _call_edges(
    symbols: list[tuple[str, str, str, int, str, str]],
    graph: StructuralGraph,
) -> list[tuple[str, str]]:
    """Resolve Tree-sitter call facts onto stable Context Fabric symbol IDs."""

    by_path_and_name: dict[tuple[str, str], list[str]] = {}
    by_name: dict[str, list[str]] = {}
    for symbol_id, path, name, _line, _hash, _content in symbols:
        by_path_and_name.setdefault((path, name), []).append(symbol_id)
        by_name.setdefault(name, []).append(symbol_id)
        by_name.setdefault(name.rsplit(".", 1)[-1], []).append(symbol_id)
    edges: set[tuple[str, str]] = set()
    for call in graph.calls:
        sources = by_path_and_name.get((call.path, call.caller), [])
        callee_name = call.callee.rsplit(".", 1)[-1]
        targets = by_name.get(callee_name, [])
        for source_id in sources:
            for target_id in targets:
                if source_id != target_id:
                    edges.add((source_id, target_id))
    return sorted(edges)
