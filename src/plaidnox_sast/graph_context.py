"""Bounded, source-checked context retrieval over a Graphify code snapshot."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .assets import load_json
from .graphify_adapter import CodeEdge, CodeGraphSnapshot, CodeNode, GraphifyAdapterError
from .redaction import redact


@dataclass(frozen=True, slots=True)
class GraphLookup:
    nodes: tuple[CodeNode, ...]
    edges: tuple[CodeEdge, ...]
    truncated: bool
    unresolved_edges: int


@dataclass(frozen=True, slots=True)
class SourceWindow:
    path: str
    start_line: int
    end_line: int
    source_hash: str
    excerpt: str


class GraphContextBroker:
    """Read structural relationships without inferring security semantics."""

    def __init__(
        self,
        root: Path,
        snapshot: CodeGraphSnapshot,
        *,
        maximum_edges: int | None = None,
        maximum_source_characters: int | None = None,
    ) -> None:
        policy = load_json("runtime/code_intelligence.json")
        self.root = root.resolve()
        self.snapshot = snapshot
        self.maximum_edges = maximum_edges or int(policy["maximum_flow_edges"])
        self.maximum_source_characters = maximum_source_characters or int(
            policy["source_window_max_characters"]
        )
        if self.maximum_edges < 1 or self.maximum_source_characters < 1:
            raise ValueError("Graph context limits must be positive")
        self._nodes = {node.id: node for node in snapshot.nodes}

    def definitions(self, label: str, *, path: str | None = None) -> tuple[CodeNode, ...]:
        """Return exact label matches; several results remain explicitly ambiguous."""
        return tuple(
            node
            for node in self.snapshot.nodes
            if node.label == label and (path is None or node.path == path)
        )

    def callers(self, node_id: str) -> GraphLookup:
        return self._related(node_id, relation="calls", direction="incoming")

    def callees(self, node_id: str) -> GraphLookup:
        return self._related(node_id, relation="calls", direction="outgoing")

    def references(self, node_id: str) -> GraphLookup:
        return self._related(node_id, relation="references", direction="incoming")

    def neighborhood(self, node_id: str) -> GraphLookup:
        return self._related(node_id, relation=None, direction="both")

    def resolve_request(self, request: dict, *, maximum_results: int = 8) -> dict:
        """Resolve a typed expansion against observed Graphify nodes and edges.

        Results retain Graphify provenance. Names such as `readers` or
        `authorization_decision` are retrieval intents only; generic graph
        references never establish data flow or security behavior.
        """
        if maximum_results < 1:
            raise ValueError("maximum_results must be positive")
        kind = str(request.get("kind", ""))
        path = str(request.get("path", "") or "")
        symbol = str(request.get("symbol", "") or "")
        query = str(request.get("query", "") or request.get("pattern", "") or symbol)
        resolver = load_json("runtime/graph_context_queries.json")["resolvers"].get(kind)
        if not isinstance(resolver, dict):
            return {"request": kind, "nodes": [], "edges": [], "source_windows": [], "truncated": False}
        mode = str(resolver.get("mode", ""))
        if mode == "window":
            if not path:
                return {"request": kind, "nodes": [], "edges": [], "source_windows": [], "truncated": False}
            try:
                window = self.source_window(path, int(request.get("start_line", 0)), int(request.get("end_line", 0)))
            except (GraphifyAdapterError, TypeError, ValueError):
                return {"request": kind, "nodes": [], "edges": [], "source_windows": [], "truncated": False}
            return {"request": kind, "nodes": [], "edges": [], "source_windows": [_window_payload(window)], "truncated": False}

        if mode == "definition":
            matches = self.definitions(symbol, path=path or None)
            lookup = GraphLookup(matches[:maximum_results], (), len(matches) > maximum_results, self.snapshot.unresolved_edges)
        elif mode == "relationship":
            seeds = self.definitions(symbol, path=path or None)
            edges = []
            related_nodes: dict[str, CodeNode] = {}
            expected_relation = resolver.get("relation")
            direction = str(resolver.get("direction", "both"))
            for seed in seeds:
                lookup_part = self._related(seed.id, relation=expected_relation, direction=direction)
                edges.extend(lookup_part.edges)
                related_nodes.update((node.id, node) for node in lookup_part.nodes)
            selected_edges = tuple(dict.fromkeys(edges))[:maximum_results]
            selected_nodes = tuple(sorted(related_nodes.values(), key=lambda item: (item.path, item.line, item.id)))[:maximum_results]
            lookup = GraphLookup(selected_nodes, selected_edges, len(edges) > maximum_results, self.snapshot.unresolved_edges)
        elif mode == "label_search":
            terms = tuple(term.casefold() for term in re.findall(r"[A-Za-z0-9_$.-]+", query) if len(term) > 1)
            matches = [node for node in self.snapshot.nodes if (not path or node.path == path) and terms and all(term in node.label.casefold() for term in terms)]
            matches.sort(key=lambda item: (item.path, item.line, item.id))
            lookup = GraphLookup(tuple(matches[:maximum_results]), (), len(matches) > maximum_results, self.snapshot.unresolved_edges)
        else:
            return {"request": kind, "nodes": [], "edges": [], "source_windows": [], "truncated": False}

        source_windows = []
        policy = load_json("runtime/code_intelligence.json")
        before = int(policy["investigation_context_lines_before"])
        after = int(policy["investigation_context_lines_after"])
        for node in lookup.nodes:
            try:
                source_windows.append(_window_payload(self.source_window_around_node(node.id, lines_before=before, lines_after=after)))
            except GraphifyAdapterError:
                continue
        return {
            "request": kind,
            "nodes": [
                {"node_id": node.id, "label": node.label, "path": node.path, "line": node.line, "source_hash": node.source_hash}
                for node in lookup.nodes
            ],
            "edges": [
                {"edge_id": _edge_id(edge), "source_id": edge.source_id, "target_id": edge.target_id, "relation": edge.relation, "provenance": edge.provenance, "path": edge.path, "line": edge.line}
                for edge in lookup.edges
            ],
            "source_windows": source_windows,
            "truncated": lookup.truncated,
            "unresolved_edges": lookup.unresolved_edges,
        }

    def source_window_around_node(
        self,
        node_id: str,
        *,
        lines_before: int,
        lines_after: int,
    ) -> SourceWindow:
        """Read a small exact window around a graph node's verified source anchor."""
        if lines_before < 0 or lines_after < 0:
            raise ValueError("source context line counts must be nonnegative")
        node = self._nodes.get(node_id)
        if node is None:
            raise GraphifyAdapterError("unknown graph node")
        source = self.root / node.path
        if source.resolve() != source or self.root not in source.parents:
            raise GraphifyAdapterError("source path escaped the immutable snapshot")
        try:
            content = source.read_bytes()
            if hashlib.sha256(content).hexdigest() != self.snapshot.source_hashes[node.path]:
                raise GraphifyAdapterError("source changed after Graphify extraction")
            line_count = len(content.decode("utf-8").splitlines())
        except (OSError, UnicodeDecodeError) as exc:
            raise GraphifyAdapterError("source window cannot be read") from exc
        start = max(1, node.line - lines_before)
        end = min(max(1, line_count), node.line + lines_after)
        return self.source_window(node.path, start, end)

    def source_window(self, path: str, start_line: int, end_line: int) -> SourceWindow:
        """Return exact, redacted source; reject stale or out-of-policy evidence."""
        expected_hash = self.snapshot.source_hashes.get(path)
        if expected_hash is None:
            raise GraphifyAdapterError("source path is not in the Graphify snapshot")
        source = self.root / path
        if source.resolve() != source or self.root not in source.parents:
            raise GraphifyAdapterError("source path escaped the immutable snapshot")
        try:
            content = source.read_bytes()
            decoded = content.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise GraphifyAdapterError("source window cannot be read") from exc
        if hashlib.sha256(content).hexdigest() != expected_hash:
            raise GraphifyAdapterError("source changed after Graphify extraction")
        lines = decoded.splitlines(keepends=True)
        if start_line < 1 or end_line < start_line or end_line > len(lines):
            raise GraphifyAdapterError("source window line range is invalid")
        excerpt = redact("".join(lines[start_line - 1 : end_line]))
        if len(excerpt) > self.maximum_source_characters:
            raise GraphifyAdapterError("source window exceeds the configured context budget")
        return SourceWindow(path, start_line, end_line, expected_hash, excerpt)

    def _related(self, node_id: str, *, relation: str | None, direction: str) -> GraphLookup:
        if node_id not in self._nodes:
            raise GraphifyAdapterError("unknown graph node")
        selected = tuple(
            edge
            for edge in self.snapshot.edges
            if (relation is None or edge.relation.casefold() == relation.casefold())
            and (
                (direction == "incoming" and edge.target_id == node_id)
                or (direction == "outgoing" and edge.source_id == node_id)
                or (direction == "both" and (edge.source_id == node_id or edge.target_id == node_id))
            )
        )
        bounded = selected[: self.maximum_edges]
        nodes = tuple(
            self._nodes[related_id]
            for related_id in dict.fromkeys(
                edge.source_id if edge.target_id == node_id else edge.target_id for edge in bounded
            )
        )
        return GraphLookup(nodes, bounded, len(selected) > len(bounded), self.snapshot.unresolved_edges)


def _window_payload(window: SourceWindow) -> dict:
    return {
        "path": window.path,
        "start_line": window.start_line,
        "end_line": window.end_line,
        "content_hash": window.source_hash,
        "excerpt": window.excerpt,
        "redaction_state": "redacted",
    }


def _edge_id(edge: CodeEdge) -> str:
    identity = [
        edge.source_id,
        edge.target_id,
        edge.relation,
        edge.provenance,
        edge.path,
        edge.line,
        edge.source_hash,
    ]
    canonical = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
