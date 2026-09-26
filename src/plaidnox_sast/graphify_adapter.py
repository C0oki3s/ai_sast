"""Source-grounded adapter for Graphify's structural, model-free extractor.

This is a migration boundary. It does not replace the live scanner's index or
make security claims; callers must admit the source snapshot through the same
policy as the rest of Code Scanning.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unicodedata
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from .assets import load_json
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


def affected_investigation_ids(
    investigations: Iterable[Any],
    delta: GraphDelta,
    *,
    snapshot: CodeGraphSnapshot | None = None,
    maximum_reverse_depth: int | None = None,
    maximum_reverse_nodes: int | None = None,
) -> tuple[str, ...]:
    """Return investigations whose explicit evidence intersects a graph delta.

    The repository-wide snapshot dependency is intentionally ignored: treating it
    as a dependency would invalidate every investigation after every edit. Callers
    may add reverse-dependency fanout separately when their graph provider can
    prove those relationships.
    """
    investigations = tuple(investigations)
    changed_paths = set(delta.added_files + delta.changed_files + delta.removed_files)
    changed_nodes = set(delta.added_node_ids + delta.changed_node_ids + delta.removed_node_ids)
    changed_edge_ids = {
        graph_edge_identity(edge) for edge in (*delta.added_edges, *delta.removed_edges)
    }
    changed_edges = (*delta.added_edges, *delta.removed_edges)
    fanout_nodes = set(changed_nodes)
    fanout_nodes.update(
        node_id
        for edge in changed_edges
        for node_id in (edge.source_id, edge.target_id)
    )
    fanout_truncated = False
    if snapshot is not None:
        config = load_json("runtime/code_intelligence.json")
        depth_limit = int(
            maximum_reverse_depth
            if maximum_reverse_depth is not None
            else config["maximum_reverse_dependency_depth"]
        )
        node_limit = int(
            maximum_reverse_nodes
            if maximum_reverse_nodes is not None
            else config["maximum_reverse_dependency_nodes"]
        )
        if depth_limit < 1 or node_limit < 1:
            raise ValueError("reverse dependency bounds must be positive")
        fanout_nodes.update(
            node.id for node in snapshot.nodes if node.path in changed_paths
        )
        incoming: dict[str, set[str]] = defaultdict(set)
        for edge in snapshot.edges:
            incoming[edge.target_id].add(edge.source_id)
        reached = set(fanout_nodes)
        frontier = set(fanout_nodes)
        for _depth in range(depth_limit):
            following = {
                source_id
                for target_id in frontier
                for source_id in incoming.get(target_id, ())
                if source_id not in reached
            }
            if not following:
                frontier = set()
                break
            if len(reached) + len(following) > node_limit:
                fanout_truncated = True
                break
            reached.update(following)
            frontier = following
        if frontier and any(incoming.get(node_id) for node_id in frontier):
            fanout_truncated = True
        fanout_nodes = reached
    affected: list[str] = []

    for value in investigations:
        payload = _investigation_payload(value)
        if not isinstance(payload, Mapping):
            continue
        investigation_id = payload.get("investigation_id")
        if not isinstance(investigation_id, str) or not investigation_id:
            continue

        node_ids = set(_nested_values(payload.get("target_ref", {}), "node_id"))
        node_ids.update(_nested_values(payload.get("target_ref", {}), "node_ids"))
        edge_ids = set(_nested_values(payload.get("target_ref", {}), "edge_id"))
        for reference in payload.get("graph_refs", ()):
            if isinstance(reference, Mapping):
                node_ids.update(_nested_values(reference, "node_id"))
                edge_ids.update(_nested_values(reference, "edge_id"))

        dependencies = payload.get("context_dependencies", ())
        for dependency in dependencies:
            if not isinstance(dependency, Mapping):
                continue
            kind = dependency.get("kind")
            key = dependency.get("key")
            if not isinstance(key, str):
                continue
            if kind == "graph_node":
                node_ids.add(key)
            elif kind == "graph_edge":
                edge_ids.add(key)
            elif kind in {"file", "source_file"}:
                if key in changed_paths:
                    affected.append(investigation_id)
                    break
        else:
            source_paths = {
                str(window.get("path"))
                for window in payload.get("source_windows", ())
                if isinstance(window, Mapping) and isinstance(window.get("path"), str)
            }
            if (
                source_paths & changed_paths
                or node_ids & fanout_nodes
                or edge_ids & changed_edge_ids
                or any(
                    edge.source_id in node_ids or edge.target_id in node_ids
                    for edge in changed_edges
                )
            ):
                affected.append(investigation_id)

    if fanout_truncated:
        # A bounded traversal cannot prove unaffected status beyond its frontier.
        # Conservatively invalidate all valid investigation identities.
        for value in investigations:
            payload = _investigation_payload(value)
            if isinstance(payload, Mapping):
                investigation_id = payload.get("investigation_id")
                if isinstance(investigation_id, str) and investigation_id:
                    affected.append(investigation_id)

    return tuple(sorted(set(affected)))


def _nested_values(value: Any, key: str) -> set[str]:
    """Collect typed graph references from bounded nested investigation data."""
    found: set[str] = set()
    if isinstance(value, Mapping):
        item = value.get(key)
        if isinstance(item, str):
            found.add(item)
        elif isinstance(item, (list, tuple)):
            found.update(entry for entry in item if isinstance(entry, str))
        for child in value.values():
            found.update(_nested_values(child, key))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.update(_nested_values(child, key))
    return found


def graph_edge_identity(edge: CodeEdge) -> str:
    """Stable fingerprint for one source-grounded Graphify edge."""
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


def graph_node_neighborhood_hash(snapshot: CodeGraphSnapshot, node_id: str) -> str | None:
    """Fingerprint all observed incoming/outgoing edges for one stable node."""
    if node_id not in {node.id for node in snapshot.nodes}:
        return None
    edge_ids = sorted(
        graph_edge_identity(edge)
        for edge in snapshot.edges
        if edge.source_id == node_id or edge.target_id == node_id
    )
    return hashlib.sha256(
        json.dumps(edge_ids, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def investigation_graph_mismatches(
    investigation: Any,
    snapshot: CodeGraphSnapshot,
    *,
    expected_planning_context_hash: str | None = None,
) -> tuple[str, ...]:
    """Explain why persisted graph evidence cannot be reused in ``snapshot``.

    Older investigation records without full node-neighborhood fingerprints are
    deliberately invalidated: their bounded prompt edges cannot prove that no
    new relationship was added outside the selected slice.
    """
    payload = _investigation_payload(investigation)
    if not isinstance(payload, Mapping):
        return ("invalid_investigation_payload",)

    nodes = {node.id: node for node in snapshot.nodes}
    edge_ids = {graph_edge_identity(edge) for edge in snapshot.edges}
    dependencies = payload.get("context_dependencies", ())
    mismatches: set[str] = set()
    node_dependencies: set[str] = set()
    neighborhood_dependencies: dict[str, str] = {}
    planning_context_found = False

    for dependency in dependencies:
        if not isinstance(dependency, Mapping):
            continue
        kind = dependency.get("kind")
        key = dependency.get("key")
        expected_hash = dependency.get("hash")
        if not isinstance(key, str):
            continue
        if kind == "graph_node":
            node_dependencies.add(key)
            node = nodes.get(key)
            if node is None:
                mismatches.add("graph_node_missing")
            elif node.source_hash != expected_hash:
                mismatches.add("graph_node_changed")
        elif kind == "graph_edge" and key not in edge_ids:
            mismatches.add("graph_edge_missing")
        elif kind == "graph_node_neighborhood" and isinstance(expected_hash, str):
            neighborhood_dependencies[key] = expected_hash
        elif kind == "planning_context" and expected_planning_context_hash is not None:
            planning_context_found = True
            if expected_hash != expected_planning_context_hash:
                mismatches.add("planning_context_changed")

    for node_id in node_dependencies:
        expected = neighborhood_dependencies.get(node_id)
        if expected is None:
            mismatches.add("graph_node_neighborhood_unavailable")
            continue
        current = graph_node_neighborhood_hash(snapshot, node_id)
        if current is None:
            mismatches.add("graph_node_missing")
        elif current != expected:
            mismatches.add("graph_node_neighborhood_changed")
    if expected_planning_context_hash is not None and not planning_context_found:
        mismatches.add("planning_context_unavailable")

    source_hashes = snapshot.source_hashes
    for window in payload.get("source_windows", ()):
        if not isinstance(window, Mapping):
            continue
        path = window.get("path")
        content_hash = window.get("content_hash")
        if isinstance(path, str) and source_hashes.get(path) != content_hash:
            mismatches.add("source_window_changed")

    return tuple(sorted(mismatches))


def _investigation_payload(value: Any) -> Any:
    payload_method = getattr(value, "payload", None)
    if callable(payload_method):
        return payload_method()
    return getattr(value, "investigation_data", value)


def _edge_sort_key(edge: CodeEdge) -> tuple[str, str, str, str, int]:
    return (edge.source_id, edge.target_id, edge.relation, edge.path, edge.line)


def _line_number(value: object) -> int:
    if not isinstance(value, str) or not value.startswith("L") or not value[1:].isdigit():
        raise GraphifyAdapterError("Graphify returned an invalid source location")
    return int(value[1:])


def _stable_id(path: str, label: str, occurrence: int) -> str:
    identity = f"{path}\0{label}\0{occurrence}".encode("utf-8")
    return f"graph-node-{hashlib.sha256(identity).hexdigest()[:24]}"


def _graphify_stable_id(path: str, raw_id: str, root_name: str) -> str | None:
    """Normalize Graphify's structural ID when it includes the extraction root.

    Graphify builds some IDs from absolute paths, which makes its raw IDs vary
    with the temporary extraction directory. Removing only that known prefix
    preserves the remaining structural identity (including parent symbols for
    methods) across line shifts and extraction roots. Unknown ID formats use
    the conservative source-order fallback in ``normalize_extraction``.
    """
    def normalize(value: str) -> str:
        value = unicodedata.normalize("NFKC", value)
        return re.sub(r"_+", "_", re.sub(r"[^\w]+", "_", value, flags=re.UNICODE)).strip("_").casefold()

    if not re.fullmatch(r"[\w]+", raw_id, flags=re.UNICODE):
        return None
    prefix = normalize(root_name)
    candidate = normalize(raw_id)
    if not candidate or not re.fullmatch(r"[\w]+", candidate, flags=re.UNICODE):
        return None
    semantic_id = (
        candidate[len(prefix) + 1 :]
        if prefix and candidate.startswith(f"{prefix}_")
        else candidate
    )
    if not semantic_id:
        return None
    identity = f"{path}\0graphify\0{semantic_id}".encode("utf-8")
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
    seen_raw_node_ids: set[str] = set()
    for raw in raw_nodes:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            raise GraphifyAdapterError("Graphify returned a malformed node")
        if not raw.get("source_file") and not raw.get("source_location"):
            # Graphify represents external imports as location-free nodes. They
            # are not source evidence; edges to them are counted unresolved.
            continue
        if raw["id"] in seen_raw_node_ids:
            raise GraphifyAdapterError("Graphify returned duplicate node IDs")
        seen_raw_node_ids.add(raw["id"])
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
        key = (path, label)
        occurrence = occurrence_counts[key]
        occurrence_counts[key] += 1
        stable_id = _graphify_stable_id(path, raw_id, root.name) or _stable_id(
            path, label, occurrence
        )
        if any(node.id == stable_id for node in nodes):
            raise GraphifyAdapterError("Graphify node identity is ambiguous after normalization")
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
        package_version = version("graphifyy")
    except PackageNotFoundError:
        package_version = "unavailable"
    extractor_version = f"graphifyy-{package_version}+plaidnox-id-v2"
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
