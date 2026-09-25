"""Source-grounded adapter for Graphify's structural, model-free extractor.

This is a migration boundary. It does not replace the live scanner's index or
make security claims; callers must admit the source snapshot through the same
policy as the rest of Code Scanning.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from .graph import source_files


class GraphifyAdapterError(RuntimeError):
    """Graph extraction or provenance validation failed."""


@dataclass(frozen=True, slots=True)
class CodeNode:
    id: str
    path: str
    line: int
    label: str
    source_hash: str


@dataclass(frozen=True, slots=True)
class CodeEdge:
    source_id: str
    target_id: str
    relation: str
    provenance: str
    path: str
    line: int
    source_hash: str


@dataclass(frozen=True, slots=True)
class CodeGraphSnapshot:
    source_hashes: Mapping[str, str]
    nodes: tuple[CodeNode, ...]
    edges: tuple[CodeEdge, ...]
    unresolved_edges: int
    unindexed_files: tuple[str, ...] = ()
    extractor_version: str = ""

    @property
    def snapshot_id(self) -> str:
        identity = json.dumps(
            {"extractor_version": self.extractor_version, "source_hashes": self.source_hashes},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def neighborhood(self, node_id: str, *, maximum_edges: int) -> tuple[CodeEdge, ...]:
        """Return a bounded one-hop view; an unknown node is a typed failure."""
        if maximum_edges < 1:
            raise ValueError("maximum_edges must be positive")
        if node_id not in {node.id for node in self.nodes}:
            raise GraphifyAdapterError("unknown graph node")
        return tuple(
            edge
            for edge in self.edges
            if edge.source_id == node_id or edge.target_id == node_id
        )[:maximum_edges]

    def difference(self, previous: CodeGraphSnapshot) -> GraphDelta:
        """Compare source and structural evidence across immutable snapshots."""
        current_files = set(self.source_hashes)
        previous_files = set(previous.source_hashes)
        current_nodes = {node.id: node for node in self.nodes}
        previous_nodes = {node.id: node for node in previous.nodes}
        current_edges = set(self.edges)
        previous_edges = set(previous.edges)
        changed_files = {
            path
            for path in current_files & previous_files
            if self.source_hashes[path] != previous.source_hashes[path]
        }
        changed_node_ids = {
            node_id
            for node_id in current_nodes.keys() & previous_nodes.keys()
            if current_nodes[node_id] != previous_nodes[node_id]
        }
        return GraphDelta(
            added_files=tuple(sorted(current_files - previous_files)),
            changed_files=tuple(sorted(changed_files)),
            removed_files=tuple(sorted(previous_files - current_files)),
            added_node_ids=tuple(sorted(current_nodes.keys() - previous_nodes.keys())),
            changed_node_ids=tuple(sorted(changed_node_ids)),
            removed_node_ids=tuple(sorted(previous_nodes.keys() - current_nodes.keys())),
            added_edges=tuple(sorted(current_edges - previous_edges, key=_edge_sort_key)),
            removed_edges=tuple(sorted(previous_edges - current_edges, key=_edge_sort_key)),
        )


@dataclass(frozen=True, slots=True)
class GraphDelta:
    added_files: tuple[str, ...]
    changed_files: tuple[str, ...]
    removed_files: tuple[str, ...]
    added_node_ids: tuple[str, ...]
    changed_node_ids: tuple[str, ...]
    removed_node_ids: tuple[str, ...]
    added_edges: tuple[CodeEdge, ...]
    removed_edges: tuple[CodeEdge, ...]


def _edge_sort_key(edge: CodeEdge) -> tuple[str, str, str, str, int]:
    return (edge.source_id, edge.target_id, edge.relation, edge.path, edge.line)


def _line_number(value: object) -> int:
    if not isinstance(value, str) or not value.startswith("L") or not value[1:].isdigit():
        raise GraphifyAdapterError("Graphify returned an invalid source location")
    return int(value[1:])


def _stable_id(path: str, label: str, occurrence: int) -> str:
    identity = f"{path}\0{label}\0{occurrence}".encode("utf-8")
    return f"graph-node-{hashlib.sha256(identity).hexdigest()[:24]}"


def _relative_path(value: object, root: Path, admitted: set[str]) -> str:
    if not isinstance(value, str) or not value:
        raise GraphifyAdapterError("Graphify returned an invalid source path")
    candidate = Path(value)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    try:
        path = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise GraphifyAdapterError("Graphify source path escaped the snapshot") from exc
    if path not in admitted:
        raise GraphifyAdapterError("Graphify cited a source excluded by policy")
    return path


def normalize_extraction(
    root: Path,
    admitted_files: Iterable[Path],
    extracted: Mapping[str, Any],
) -> CodeGraphSnapshot:
    """Assign portable IDs and validate every source location against the snapshot."""
    root = root.resolve()
    paths = tuple(sorted((path.resolve() for path in admitted_files)))
    admitted = {path.relative_to(root).as_posix() for path in paths}
    source_bytes = {path.relative_to(root).as_posix(): path.read_bytes() for path in paths}
    hashes = {path: hashlib.sha256(content).hexdigest() for path, content in source_bytes.items()}
    line_counts = {path: max(1, len(content.splitlines())) for path, content in source_bytes.items()}

    raw_nodes = extracted.get("nodes")
    raw_edges = extracted.get("edges")
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise GraphifyAdapterError("Graphify returned a malformed graph")

    ordered_nodes: list[tuple[str, int, str, str]] = []
    for raw in raw_nodes:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            raise GraphifyAdapterError("Graphify returned a malformed node")
        path = _relative_path(raw.get("source_file"), root, admitted)
        line = _line_number(raw.get("source_location"))
        if not 1 <= line <= line_counts[path]:
            raise GraphifyAdapterError("Graphify node location is outside the source")
        label = raw.get("label")
        if not isinstance(label, str) or not label:
            raise GraphifyAdapterError("Graphify returned a node without a label")
        ordered_nodes.append((path, line, label, raw["id"]))

    nodes: list[CodeNode] = []
    raw_to_stable: dict[str, str] = {}
    occurrence_counts: dict[tuple[str, str], int] = defaultdict(int)
    for path, line, label, raw_id in sorted(ordered_nodes):
        if raw_id in raw_to_stable:
            raise GraphifyAdapterError("Graphify returned duplicate node IDs")
        key = (path, label)
        occurrence = occurrence_counts[key]
        occurrence_counts[key] += 1
        stable_id = _stable_id(path, label, occurrence)
        raw_to_stable[raw_id] = stable_id
        nodes.append(CodeNode(stable_id, path, line, label, hashes[path]))

    edges: list[CodeEdge] = []
    unresolved = 0
    for raw in raw_edges:
        if not isinstance(raw, dict):
            raise GraphifyAdapterError("Graphify returned a malformed edge")
        path = _relative_path(raw.get("source_file"), root, admitted)
        line = _line_number(raw.get("source_location"))
        if not 1 <= line <= line_counts[path]:
            raise GraphifyAdapterError("Graphify edge location is outside the source")
        source_id = raw_to_stable.get(raw.get("source"))
        target_id = raw_to_stable.get(raw.get("target"))
        if source_id is None or target_id is None:
            unresolved += 1
            continue
        relation = raw.get("relation")
        provenance = raw.get("confidence")
        if not isinstance(relation, str) or not relation:
            raise GraphifyAdapterError("Graphify returned an edge without a relation")
        if provenance not in {"EXTRACTED", "INFERRED", "AMBIGUOUS"}:
            raise GraphifyAdapterError("Graphify returned an unknown edge provenance")
        edges.append(CodeEdge(source_id, target_id, relation, provenance, path, line, hashes[path]))

    indexed_paths = {node.path for node in nodes}
    try:
        extractor_version = version("graphifyy")
    except PackageNotFoundError:
        extractor_version = "unavailable"
    return CodeGraphSnapshot(
        hashes,
        tuple(nodes),
        tuple(edges),
        unresolved,
        tuple(sorted(admitted - indexed_paths)),
        extractor_version,
    )


def extract_structural_graph(
    root: Path,
    *,
    exclude: Iterable[str] = (),
    max_file_bytes: int | None = None,
    cache_root: Path | None = None,
    extractor: Callable[..., Mapping[str, Any]] | None = None,
) -> CodeGraphSnapshot:
    """Run Graphify AST extraction only on files admitted by PlaidNox policy."""
    root = root.resolve()
    admitted = source_files(root, exclude=exclude, max_file_bytes=max_file_bytes)
    try:
        source_hashes_before = {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in admitted
        }
    except OSError as exc:
        raise GraphifyAdapterError("source snapshot changed before Graphify extraction") from exc
    if extractor is None:
        try:
            from graphify.extract import extract as extractor
        except ImportError as exc:
            raise GraphifyAdapterError("install the code-graph extra to use Graphify") from exc
    def run_with_cache(external_cache: Path) -> CodeGraphSnapshot:
        try:
            result = extractor(admitted, cache_root=external_cache, parallel=False)
            snapshot = normalize_extraction(root, admitted, result)
        except GraphifyAdapterError:
            raise
        except Exception as exc:
            raise GraphifyAdapterError("Graphify structural extraction failed") from exc
        if dict(snapshot.source_hashes) != source_hashes_before:
            raise GraphifyAdapterError("source snapshot changed during Graphify extraction")
        return snapshot

    if cache_root is None:
        with tempfile.TemporaryDirectory(prefix="plaidnox-graphify-") as temporary_cache:
            return run_with_cache(Path(temporary_cache))
    external_cache = cache_root.resolve()
    if external_cache == root or root in external_cache.parents:
        raise GraphifyAdapterError("Graphify cache must be outside the source snapshot")
    return run_with_cache(external_cache)
