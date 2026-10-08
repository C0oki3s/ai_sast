"""Machine-readable vulnerable snippets and validated semantic evidence traces."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import Path

from plaidnox_sast.graph import StructuralGraph, Symbol
from plaidnox_sast.redaction import redact, redact_code

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
    # Redacted source window around the node (a few lines of context either side),
    # captured from the immutable head snapshot so the trace can be rendered later
    # without re-reading the repository.
    code: str = ""
    code_start_line: int | None = None
    code_end_line: int | None = None
    # 1-based position in the attack path (source first, sensitive effect last).
    step: int | None = None


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

# Context lines kept around each trace node, and the hard cap on a stored window.
_CODE_CONTEXT_LINES = 4
_CODE_WINDOW_MAX_LINES = 40
_CODE_WINDOW_MAX_CHARS = 4000

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
    content = redact_code("\n".join(lines[start - 1 : end])[:4000])
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
    """Build the attack path, source to sink, from verified evidence and supported links.

    The verifier lists its locations in attack order; that order is kept and each
    node gets its ``step``. The changed root-cause lines are always a step: merged
    into the verifier's location when it cites them, otherwise placed after the
    attacker origin. Overlapping locations collapse into one step.

    The LLM never gets to invent a link. Every node is checked against the
    immutable head snapshot, and every link between consecutive steps must be
    supported by the structural graph, a shared function, a variable assigned in
    one step and used in the next, or a route that names the upstream control.
    Unsupported hops stay visible as evidence gaps and mark the trace incomplete.
    """

    gaps: list[str] = [redact(value.strip()) for value in evidence_gaps if value.strip()]
    root_item = ReviewEvidence(
        role=EvidenceRole.ROOT_CAUSE_CHANGED_CODE,
        source="changed_code",
        path=candidate.changed_path,
        start_line=candidate.changed_lines.start,
        end_line=candidate.changed_lines.end,
        summary=_root_cause_summary(candidate),
    )
    located = [item for item in evidence if item.source == "deep_hunt" and item.role in _ROLE_LAYER]
    if located:
        ordered = _attack_order(located, root_item)
    else:
        # No verifier locations: fall back to the role order.
        ordered = sorted(
            [item for item in evidence if item.role in _ROLE_LAYER and item.source != "changed_code"] + [root_item],
            key=lambda item: _ROLE_LAYER[item.role],
        )

    nodes: list[EvidenceTraceNode] = []
    for item in ordered:
        validated = _validated_node(root, graph, item)
        if validated is None:
            gaps.append(
                f"Evidence location could not be machine-validated: {item.path}:{item.start_line or '?'}"
            )
            continue
        nodes.append(validated)
    if not nodes:
        return None
    nodes = [replace(node, step=index) for index, node in enumerate(nodes, 1)]

    # Each step links to the nearest earlier step that supports it, so a bug that
    # reaches two routes stays two branches instead of an invented route-to-route hop.
    edges: list[EvidenceTraceEdge] = []
    incoming: set[str] = set()
    outgoing: set[str] = set()
    for index, target in enumerate(nodes[1:], 1):
        for source in reversed(nodes[:index]):
            support = _transition_support(root, graph, source, target)
            if support is None:
                continue
            relation, via = support
            edges.append(EvidenceTraceEdge(source=source.node_id, target=target.node_id, relation=relation, via=via))
            incoming.add(target.node_id)
            outgoing.add(source.node_id)
            break
        else:
            gaps.append(
                f"No machine-supported transition into step {target.step} "
                f"({target.path}:{target.start_line or '?'}, {target.label}) from an earlier step"
            )

    unique_gaps = tuple(dict.fromkeys(redact(value.strip()) for value in gaps if value.strip()))
    represented_roles = {node.role for node in nodes}
    complete = (
        not unique_gaps
        and EvidenceRole.ROOT_CAUSE_CHANGED_CODE in represented_roles
        and bool(represented_roles & {EvidenceRole.DOWNSTREAM_TRUST, EvidenceRole.SENSITIVE_EFFECT})
        and all(node.node_id in incoming for node in nodes[1:])
    )

    return EvidenceTrace(
        trace_type="taint_and_trust",
        step_count=len(nodes),
        file_count=len({node.path for node in nodes}),
        nodes=tuple(nodes),
        edges=tuple(edges),
        entry_nodes=tuple(node.node_id for node in nodes if node.node_id not in incoming),
        terminal_nodes=tuple(node.node_id for node in nodes if node.node_id not in outgoing),
        attack_path=redact(attack_path.strip()),
        gained_capability=redact(gained_capability.strip()),
        complete=complete,
        evidence_gaps=unique_gaps,
    )


def _root_cause_summary(candidate: L1Candidate) -> str:
    after = candidate.behavior_after.strip()
    return f"Changed in this pull request: {after}" if after else "Code changed in this pull request."


def _overlaps(first: ReviewEvidence, second: ReviewEvidence) -> bool:
    if first.path != second.path or first.start_line is None or second.start_line is None:
        return False
    first_end = first.end_line or first.start_line
    second_end = second.end_line or second.start_line
    return first.start_line <= second_end and second.start_line <= first_end


def _attack_order(located: list[ReviewEvidence], root_item: ReviewEvidence) -> list[ReviewEvidence]:
    """The verifier's order, one step per place, with the changed root cause always present."""

    steps: list[ReviewEvidence] = []
    root_placed = False
    for item in located:
        if any(_overlaps(item, kept) and item.role == kept.role for kept in steps):
            continue  # the same lines cited twice for the same role: keep the first mention
        middle = item.role not in {EvidenceRole.ATTACKER_ORIGIN, EvidenceRole.SENSITIVE_EFFECT}
        if not root_placed and middle and _overlaps(item, root_item):
            # The verifier cites the changed lines: that location is the root-cause step,
            # with the verifier's own explanation and the full changed range.
            start = min(item.start_line or 1, root_item.start_line or 1)
            end = max(item.end_line or item.start_line or 1, root_item.end_line or root_item.start_line or 1)
            steps.append(replace(root_item, start_line=start, end_line=end, summary=item.summary or root_item.summary))
            root_placed = True
            continue
        steps.append(item)
    if not root_placed:
        origins = [index for index, item in enumerate(steps) if item.role == EvidenceRole.ATTACKER_ORIGIN]
        at = origins[-1] + 1 if origins else 0
        steps.insert(at, root_item)
    return steps


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

    expression = redact_code("\n".join(lines[start - 1 : end])[:1200])
    code_start, code_end, code = _code_window(lines, start, end)
    anchor = _anchor_at(graph, path, start, end)
    symbol = anchor.qualified_name or anchor.name if anchor is not None else path
    propagation = item.step_role == "propagation"
    key = (item.role.value, path, start, end, item.summary, symbol, expression)
    digest = hashlib.sha256("|".join(str(value) for value in key).encode("utf-8")).hexdigest()[:16]
    return EvidenceTraceNode(
        node_id=f"trace_{digest}",
        role=item.role,
        kind="PROPAGATION" if propagation else _NODE_KIND[item.role],
        path=path,
        start_line=start,
        end_line=end,
        symbol=redact(symbol),
        expression=expression,
        label="Propagation" if propagation else _label(item.role),
        summary=redact(item.summary.strip()),
        provenance=redact(item.source.strip()),
        code=code,
        code_start_line=code_start,
        code_end_line=code_end,
    )


def _code_window(lines: list[str], start: int, end: int) -> tuple[int, int, str]:
    """Node range plus surrounding context, bounded and redacted before persistence."""

    first = max(1, start - _CODE_CONTEXT_LINES)
    last = min(len(lines), end + _CODE_CONTEXT_LINES)
    # Blank lines at the edges of the context add nothing; never trim the node itself.
    while first < start and not lines[first - 1].strip():
        first += 1
    while last > end and not lines[last - 1].strip():
        last -= 1
    if last - first + 1 > _CODE_WINDOW_MAX_LINES:
        # Keep the node itself; trim context first, then the tail of a very long node.
        first = max(1, start - 1)
        last = min(len(lines), first + _CODE_WINDOW_MAX_LINES - 1)
    window = "\n".join(lines[first - 1 : last])
    if len(window) > _CODE_WINDOW_MAX_CHARS:
        kept: list[str] = []
        size = 0
        for line in lines[first - 1 : last]:
            if size + len(line) + 1 > _CODE_WINDOW_MAX_CHARS:
                break
            kept.append(line)
            size += len(line) + 1
        last = first + max(0, len(kept) - 1)
        window = "\n".join(kept)
    return first, last, redact_code(window)


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
    # A node outside any function or route (its symbol is just the file) only links by
    # a value it shares with the step before it in the same file.
    source_anchored = source.symbol != source.path
    target_anchored = target.symbol != target.path

    if source.path == target.path and source.symbol == target.symbol:
        flowing = _flowing_names(source.expression, target.expression)
        if flowing:
            return "propagates_to", f"`{flowing[0]}` flows on within `{_short(source.symbol)}`"
        if source_anchored:
            return "propagates_to", f"same function `{_short(source.symbol)}`"
        return None
    if not (source_anchored and target_anchored):
        return None

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
                return "propagates_to", f"`{alias}` runs before route `{_short(target_anchor.name)}`"

    for call in graph.calls:
        caller_aliases = _symbol_aliases(call.caller)
        callee_aliases = _symbol_aliases(call.callee)
        if (source_aliases & caller_aliases and target_aliases & callee_aliases) or (
            target_aliases & caller_aliases and source_aliases & callee_aliases
        ):
            return "propagates_to", f"`{_short(call.caller)}` calls `{_short(call.callee)}` ({call.path}:{call.line})"

    for reference in graph.references:
        source_names = _symbol_aliases(reference.source)
        target_names = _symbol_aliases(reference.target)
        if (source_aliases & source_names and target_aliases & target_names) or (
            target_aliases & source_names and source_aliases & target_names
        ):
            return "propagates_to", (
                f"`{_short(reference.source)}` uses `{_short(reference.target)}` ({reference.path}:{reference.line})"
            )

    return None


_ASSIGNED = re.compile(
    r"(?:\b(?:const|let|var|final|val|my)\s+|^|[;{(,]\s*)"
    r"(?:\{\s*([\w\s,:]+)\}|\[\s*([\w\s,]+)\]|([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*))\s*(?::\s*[\w<>\[\]|]+\s*)?=(?!=)",
    re.MULTILINE,
)
_COMMON_NAMES = frozenset({"i", "j", "k", "e", "err", "error", "res", "result", "self", "this", "_"})


def _flowing_names(source_code: str, target_code: str) -> list[str]:
    """Names assigned in the source step that the target step uses."""

    names: list[str] = []
    for match in _ASSIGNED.finditer(source_code):
        group = match.group(1) or match.group(2) or match.group(3) or ""
        for raw in re.split(r"[,\s]+", group):
            name = raw.split(":")[-1].strip()
            if name and name not in _COMMON_NAMES and name not in names:
                names.append(name)
    return [name for name in names if re.search(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", target_code)]


def _short(symbol: str) -> str:
    value = symbol.removeprefix("route:").strip()
    return value.rsplit("/", 1)[-1] if "/" in value and " " not in value and not value.startswith("/") else value


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
