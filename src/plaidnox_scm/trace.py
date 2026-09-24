"""Machine-readable vulnerable snippets and semantic evidence traces."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

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
    path: str
    start_line: int | None
    end_line: int | None
    label: str
    summary: str


@dataclass(frozen=True, slots=True)
class EvidenceTraceEdge:
    source: str
    target: str
    relation: str = "supports_transition"


@dataclass(frozen=True, slots=True)
class EvidenceTrace:
    trace_type: str
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
    candidate: L1Candidate,
    evidence: tuple[ReviewEvidence, ...],
    *,
    attack_path: str,
    gained_capability: str,
    evidence_gaps: tuple[str, ...] = (),
) -> EvidenceTrace | None:
    """Build a small branching graph from independently verified evidence roles.

    The graph is deliberately conservative. Nodes come only from evidence the
    verifier/context broker already accepted. Edges express an evidence-backed
    semantic transition between adjacent role layers; they do not claim a
    byte-level data-flow edge that static analysis has not proved. Multiple
    downstream-trust or sensitive-effect nodes naturally render as branches.
    """

    del candidate  # candidate identity is already represented by ROOT_CAUSE evidence
    nodes: list[EvidenceTraceNode] = []
    seen: set[tuple[str, str, int | None, int | None, str]] = set()
    for item in evidence:
        if item.role not in _ROLE_LAYER:
            continue
        key = (item.role.value, item.path, item.start_line, item.end_line, item.summary)
        if key in seen:
            continue
        seen.add(key)
        digest = hashlib.sha256("|".join(str(value) for value in key).encode("utf-8")).hexdigest()[:16]
        nodes.append(
            EvidenceTraceNode(
                node_id=f"trace_{digest}",
                role=item.role,
                path=item.path,
                start_line=item.start_line,
                end_line=item.end_line,
                label=_label(item.role),
                summary=redact(item.summary.strip()),
            )
        )
    if not nodes:
        return None

    by_layer: dict[int, list[EvidenceTraceNode]] = {}
    for node in nodes:
        by_layer.setdefault(_ROLE_LAYER[node.role], []).append(node)
    populated_layers = sorted(by_layer)

    # Connect only adjacent *populated* semantic layers. This gives the UI a
    # useful path while avoiding invented intermediate source-code hops.
    edges: list[EvidenceTraceEdge] = []
    for index in range(len(populated_layers) - 1):
        sources = by_layer[populated_layers[index]]
        targets = by_layer[populated_layers[index + 1]]
        for source in sources:
            for target in targets:
                edges.append(EvidenceTraceEdge(source.node_id, target.node_id))
                if len(edges) >= 64:
                    break
            if len(edges) >= 64:
                break
        if len(edges) >= 64:
            break

    first_layer = by_layer[populated_layers[0]]
    last_layer = by_layer[populated_layers[-1]]
    gaps = tuple(dict.fromkeys(redact(value.strip()) for value in evidence_gaps if value.strip()))
    complete = not gaps and bool(
        any(node.role == EvidenceRole.ROOT_CAUSE_CHANGED_CODE for node in nodes)
        and any(
            node.role in {EvidenceRole.DOWNSTREAM_TRUST, EvidenceRole.SENSITIVE_EFFECT}
            for node in nodes
        )
    )
    return EvidenceTrace(
        trace_type="taint_and_trust",
        nodes=tuple(nodes),
        edges=tuple(edges),
        entry_nodes=tuple(item.node_id for item in first_layer),
        terminal_nodes=tuple(item.node_id for item in last_layer),
        attack_path=redact(attack_path.strip()),
        gained_capability=redact(gained_capability.strip()),
        complete=complete,
        evidence_gaps=gaps,
    )


def _label(role: EvidenceRole) -> str:
    return {
        EvidenceRole.ATTACKER_ORIGIN: "Attacker origin",
        EvidenceRole.ROOT_CAUSE_CHANGED_CODE: "Changed root cause",
        EvidenceRole.SECURITY_BOUNDARY: "Security boundary",
        EvidenceRole.DEFENSE_REMOVED_OR_BYPASSED: "Defense removed or bypassed",
        EvidenceRole.DOWNSTREAM_TRUST: "Downstream trust",
        EvidenceRole.SENSITIVE_EFFECT: "Sensitive effect",
    }[role]
