"""Machine-readable vulnerable snippets and validated semantic evidence traces."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from plaidnox_sast.graph import StructuralGraph, Symbol
from plaidnox_sast.redaction import redact

from .evidence import EvidenceRole, ReviewEvidence
from .l1_review import L1Candidate


@dataclass(frozen=True, slots=True)
class VulnerableSnippet:
    path: str
    start_line: int
    end_line: int
    content: str


@dataclass(frozen=True, slots=True)
class EvidenceTraceNode:
    node_id: str
    role: EvidenceRole
    kind: str
    path: str
    start_line: int | None
    end_line: int | None
    symbol: str
    expression: str
    label: str
    summary: str
    provenance: str


@dataclass(frozen=True, slots=True)
class EvidenceTraceEdge:
    source: str
    target: str
    relation: str
    via: str


@dataclass(frozen=True, slots=True)
class EvidenceTrace:
    trace_type: str
    step_count: int
    file_count: int
    nodes: tuple[EvidenceTraceNode, ...]
    edges: tuple[EvidenceTraceEdge, ...]
    entry_nodes: tuple[str, ...]
    terminal_nodes: tuple[str, ...]
    attack_path: str
    gained_capability: str
    complete: bool
    evidence_gaps: tuple[str, ...]


_ROLE_LAYER = {
    EvidenceRole.ATTACKER_ORIGIN: 0,
    EvidenceRole.ROOT_CAUSE_CHANGED_CODE: 1,
    EvidenceRole.SECURITY_BOUNDARY: 2,
    EvidenceRole.DEFENSE_REMOVED_OR_BYPASSED: 3,
    EvidenceRole.DOWNSTREAM_TRUST: 4,
    EvidenceRole.SENSITIVE_EFFECT: 5,
}

_NODE_KIND = {
    EvidenceRole.ATTACKER_ORIGIN: "SOURCE",
    EvidenceRole.ROOT_CAUSE_CHANGED_CODE: "PROPAGATION",
    EvidenceRole.SECURITY_BOUNDARY: "TRUST_BOUNDARY",
    EvidenceRole.DEFENSE_REMOVED_OR_BYPASSED: "SECURITY_CONTROL",
    EvidenceRole.DOWNSTREAM_TRUST: "AUTHORIZATION_DECISION",
    EvidenceRole.SENSITIVE_EFFECT: "SENSITIVE_EFFECT",
}


def build_vulnerable_snippet(root: Path, candidate: L1Candidate) -> VulnerableSnippet | None:
    """Return only the changed root-cause range, redacted before it leaves the verifier."""

    target = (root / candidate.changed_path).resolve()
    resolved_root = root.resolve()
    if resolved_root not in target.parents or not target.is_file():
        return None
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = max(1, candidate.changed_lines.start)
    end = min(len(lines), max(start, candidate.changed_lines.end))
    if start > len(lines):
        return None
    content = redact("\n".join(lines[start - 1 : end])[:4000])
    return VulnerableSnippet(candidate.changed_path, start, end, content)


def build_evidence_trace(
    root: Path,
    graph: StructuralGraph,
    candidate: L1Candidate,
    evidence: tuple[ReviewEvidence, ...],
    *,
    attack_path: str,
    gained_capability: str,
    evidence_gaps: tuple[str, ...] = (),
) -> EvidenceTrace | None:
    """Build a branching trace from verified evidence and machine-supported relationships.

    The LLM may identify useful evidence locations, but it never gets to invent
    graph edges. Every node is checked against the immutable head snapshot and
    every edge must be supported by the structural graph, a shared structural
    anchor, or a route that explicitly references the upstream middleware/control.
    Unsupported hops remain visible as evidence gaps and make the trace incomplete.
    """

    nodes: list[EvidenceTraceNode] = []
    gaps: list[str] = [redact(value.strip()) for value in evidence_gaps if value.strip()]
    seen: set[tuple[str, str, int | None, int | None, str]] = set()

    for item in evidence:
        if item.role not in _ROLE_LAYER:
            continue
        validated = _validated_node(root, graph, item)
        if validated is None:
            gaps.append(
                f"Evidence location could not be machine-validated: {item.path}:{item.start_line or '?'}"
            )
            continue
        key = (
            item.role.value,
            validated.path,
            validated.start_line,
            validated.end_line,
            validated.summary,
        )
        if key in seen:
            continue
        seen.add(key)
        nodes.append(validated)

    if not nodes:
        return None

    if not any(node.role == EvidenceRole.ROOT_CAUSE_CHANGED_CODE for node in nodes):
        root_evidence = ReviewEvidence(
            role=EvidenceRole.ROOT_CAUSE_CHANGED_CODE,
            source="changed_code",
            path=candidate.changed_path,
            start_line=candidate.changed_lines.start,
            end_line=candidate.changed_lines.end,
            summary=f"{candidate.behavior_before} -> {candidate.behavior_after}",
        )
        validated_root = _validated_node(root, graph, root_evidence)
        if validated_root is not None:
            nodes.append(validated_root)
        else:
            gaps.append("Changed root-cause range could not be machine-validated")

    by_layer: dict[int, list[EvidenceTraceNode]] = {}
    for node in nodes:
        by_layer.setdefault(_ROLE_LAYER[node.role], []).append(node)
    populated_layers = sorted(by_layer)

    edges: list[EvidenceTraceEdge] = []
    incoming: set[str] = set()
    for index in range(len(populated_layers) - 1):
        sources = by_layer[populated_layers[index]]
        targets = by_layer[populated_layers[index + 1]]
        for target in targets:
            target_supported = False
            for source in sources:
                support = _transition_support(root, graph, source, target)
                if support is None:
                    continue
                relation, via = support
                edges.append(
                    EvidenceTraceEdge(
                        source=source.node_id,
                        target=target.node_id,
                        relation=relation,
                        via=via,
                    )
                )
                incoming.add(target.node_id)
                target_supported = True
                if len(edges) >= 64:
                    break
            if not target_supported:
                gaps.append(
                    "No machine-supported transition into "
                    f"{target.path}:{target.start_line or '?'} ({target.label})"
                )
            if len(edges) >= 64:
                break
        if len(edges) >= 64:
            gaps.append("Trace edge limit reached before every transition could be represented")
            break

    first_layer = by_layer[populated_layers[0]]
    last_layer = by_layer[populated_layers[-1]]
    unique_gaps = tuple(dict.fromkeys(redact(value.strip()) for value in gaps if value.strip()))
    represented_roles = {node.role for node in nodes}
    non_entry_ids = {node.node_id for node in nodes} - {node.node_id for node in first_layer}
    complete = (
        not unique_gaps
        and EvidenceRole.ROOT_CAUSE_CHANGED_CODE in represented_roles
        and bool(represented_roles & {EvidenceRole.DOWNSTREAM_TRUST, EvidenceRole.SENSITIVE_EFFECT})
        and non_entry_ids.issubset(incoming)
    )

    return EvidenceTrace(
        trace_type="taint_and_trust",
        step_count=len(nodes),
        file_count=len({node.path for node in nodes}),
        nodes=tuple(nodes),
        edges=tuple(edges),
        entry_nodes=tuple(item.node_id for item in first_layer),
        terminal_nodes=tuple(item.node_id for item in last_layer),
        attack_path=redact(attack_path.strip()),
        gained_capability=redact(gained_capability.strip()),
        complete=complete,
        evidence_gaps=unique_gaps,
    )


def _validated_node(
    root: Path,
    graph: StructuralGraph,
    item: ReviewEvidence,
) -> EvidenceTraceNode | None:
    path = item.path.strip()
    if not path or item.start_line is None:
        return None
    target = (root / path).resolve()
    resolved_root = root.resolve()
    if resolved_root not in target.parents or not target.is_file():
        return None
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = int(item.start_line)
    end = int(item.end_line or start)
    if start < 1 or end < start or end > len(lines):
        return None

    expression = redact("\n".join(lines[start - 1 : end])[:1200])
    anchor = _anchor_at(graph, path, start, end)
    symbol = anchor.qualified_name or anchor.name if anchor is not None else path
    key = (item.role.value, path, start, end, item.summary, symbol, expression)
    digest = hashlib.sha256("|".join(str(value) for value in key).encode("utf-8")).hexdigest()[:16]
    return EvidenceTraceNode(
        node_id=f"trace_{digest}",
        role=item.role,
        kind=_NODE_KIND[item.role],
        path=path,
        start_line=start,
        end_line=end,
        symbol=redact(symbol),
        expression=expression,
        label=_label(item.role),
        summary=redact(item.summary.strip()),
        provenance=redact(item.source.strip()),
    )


def _anchor_at(
    graph: StructuralGraph,
    path: str,
    start_line: int,
    end_line: int,
) -> Symbol | None:
    candidates = [
        symbol
        for symbol in (*graph.symbols, *graph.routes)
        if symbol.path == path
        and symbol.line <= start_line
        and (symbol.end_line <= 0 or end_line <= symbol.end_line)
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda value: max(1, value.end_line - value.line))


def _transition_support(
    root: Path,
    graph: StructuralGraph,
    source: EvidenceTraceNode,
    target: EvidenceTraceNode,
) -> tuple[str, str] | None:
    source_aliases = _symbol_aliases(source.symbol)
    target_aliases = _symbol_aliases(target.symbol)

    if source.path == target.path and source.symbol == target.symbol:
        return "propagates_to", f"within structural anchor {source.symbol}"

    target_anchor = _anchor_at(
        graph,
        target.path,
        int(target.start_line or 1),
        int(target.end_line or target.start_line or 1),
    )
    if target_anchor is not None and target_anchor.kind == "route":
        route_source = _source_range(root, target_anchor.path, target_anchor.line, target_anchor.end_line)
        for alias in sorted(source_aliases, key=len, reverse=True):
            if alias and re.search(rf"\b{re.escape(alias)}\b", route_source):
                return "propagates_to", f"{alias} is explicitly attached to {target_anchor.name}"

    for call in graph.calls:
        caller_aliases = _symbol_aliases(call.caller)
        callee_aliases = _symbol_aliases(call.callee)
        if source_aliases & caller_aliases and target_aliases & callee_aliases:
            return "propagates_to", f"call {call.caller} -> {call.callee} at {call.path}:{call.line}"
        if target_aliases & caller_aliases and source_aliases & callee_aliases:
            return "propagates_to", f"call {call.caller} -> {call.callee} at {call.path}:{call.line}"

    for reference in graph.references:
        source_names = _symbol_aliases(reference.source)
        target_names = _symbol_aliases(reference.target)
        if source_aliases & source_names and target_aliases & target_names:
            return "propagates_to", (
                f"reference {reference.source} -> {reference.target} at "
                f"{reference.path}:{reference.line}"
            )
        if target_aliases & source_names and source_aliases & target_names:
            return "propagates_to", (
                f"reference {reference.source} -> {reference.target} at "
                f"{reference.path}:{reference.line}"
            )

    return None


def _source_range(root: Path, path: str, start_line: int, end_line: int) -> str:
    target = root / path
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(1, start_line)
    end = min(len(lines), max(start, end_line))
    return "\n".join(lines[start - 1 : end])


def _symbol_aliases(value: str) -> set[str]:
    normalized = value.strip()
    if not normalized:
        return set()
    aliases = {normalized, normalized.rsplit(".", 1)[-1]}
    if normalized.startswith("route:"):
        aliases.add(normalized.removeprefix("route:"))
    return {item for item in aliases if item}


def _label(role: EvidenceRole) -> str:
    return {
        EvidenceRole.ATTACKER_ORIGIN: "Attacker origin",
        EvidenceRole.ROOT_CAUSE_CHANGED_CODE: "Changed root cause",
        EvidenceRole.SECURITY_BOUNDARY: "Security boundary",
        EvidenceRole.DEFENSE_REMOVED_OR_BYPASSED: "Defense removed or bypassed",
        EvidenceRole.DOWNSTREAM_TRUST: "Downstream trust",
        EvidenceRole.SENSITIVE_EFFECT: "Sensitive effect",
    }[role]
