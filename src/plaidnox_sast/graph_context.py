"""Bounded, source-checked context retrieval over a Graphify code snapshot."""

from __future__ import annotations

import hashlib
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

    def _related(self, node_id: str, *, relation: str | None, direction: str) -> GraphLookup:
        if node_id not in self._nodes:
            raise GraphifyAdapterError("unknown graph node")
        selected = tuple(
            edge
            for edge in self.snapshot.edges
            if (relation is None or edge.relation == relation)
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
