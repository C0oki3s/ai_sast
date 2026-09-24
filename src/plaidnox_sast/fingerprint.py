from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field

from .assets import load_json
from .models import Candidate, CandidateEvidencePacket


def _normalize(value: str) -> str:
    value = value.strip().lower().replace("\\", "/")
    value = re.sub(r"\b\d+\b", "#", value)
    value = re.sub(r"\s+", " ", value)
    return value


def candidate_fingerprint(repository: str, candidate: Candidate) -> str:
    """Stable across line movements; follows the PLAN.md deduplication identity."""
    ev = candidate.evidence
    graph_path = " -> ".join(ev.graph_path) or f"{ev.source_symbol} -> {ev.sink_symbol}"
    parts = (
        repository,
        candidate.vulnerability_class,
        ev.source_symbol or ev.path,
        ev.sink_symbol or candidate.rule_id,
        graph_path,
        candidate_semantic_key(candidate),
        root_equivalence_key(candidate),
    )
    canonical = "\x1f".join(_normalize(part) for part in parts)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


# Words that describe a whole family of weaknesses rather than one root cause.
# Sharing only these must not merge two candidates ("authentication" covers both
# rate-limiting gaps and JWT trust bugs).
_GENERIC_WORDS = frozenset(
    "a all allow allows an and any app application are can directly for from into is lead leading leads may not that used uses using was when where authentication authorization access control bypass check checks claim "
    "failure improper injection insufficient issue missing of on or security the to unverified untrusted "
    "user via vulnerability weakness with without".split()
)
_NEARBY_LINES = 6


def _issue_tokens(candidate: Candidate) -> frozenset[str]:
    """Specific words of the model's own naming; stemmed so 'limiting' == 'limit'."""
    metadata = candidate.metadata
    text = " ".join(
        (candidate.title, candidate.vulnerability_class, str(metadata.get("category", "")), candidate.evidence.sink_symbol)
    )
    tokens = set()
    for word in re.findall(r"[a-z0-9]+", text.lower()):
        if len(word) < 3 or word in _GENERIC_WORDS:
            continue
        for suffix in ("ing", "es", "s", "ed"):
            if word.endswith(suffix) and len(word) - len(suffix) >= 3:
                word = word[: -len(suffix)]
                break
        tokens.add(word)
    return frozenset(tokens)


def _classification_ids(candidate: Candidate) -> frozenset[str]:
    references = candidate.metadata.get("classification_references") or []
    return frozenset(
        str(item.get("identifier", "")).upper() for item in references if isinstance(item, dict) and item.get("identifier")
    )


def candidate_semantic_key(candidate: Candidate) -> str:
    """Semantic identity of one broken control at one code root.

    The symbol and security-control name identify the implementation point;
    broken invariant and gained capability prevent distinct weaknesses in the
    same control from being collapsed into one finding.
    """
    root = candidate.metadata.get("root_cause") or {}
    symbol = _normalize(str(root.get("symbol", "")))
    control = re.sub(r"[^a-z0-9]+", "-", str(root.get("security_control", "")).lower()).strip("-")
    invariant = _normalize(str(root.get("broken_invariant", "")))
    capability = _normalize(str(root.get("capability", "")))
    if not symbol or not control:
        return ""
    # Older/non-AI candidates may not carry the richer fields. Keep their
    # historical symbol+control identity instead of making dedupe disappear.
    semantic_tail = f"|{invariant}|{capability}" if invariant or capability else ""
    return f"{_normalize(candidate.evidence.path)}|{symbol}|{control}{semantic_tail}"


def root_cause_key(candidate: Candidate) -> str:
    """Compatibility alias for the canonical semantic candidate identity."""

    return candidate_semantic_key(candidate)


def root_equivalence_key(candidate: Candidate) -> str:
    """Structural root plus open-taxonomy effect/capability families.

    Family IDs are model-classified under the external discovery contract. An
    unresolved family deliberately disables cross-hypothesis clustering.
    """

    families = candidate.metadata.get("root_equivalence") or {}
    root = candidate.metadata.get("root_cause") or {}
    path = _normalize(candidate.evidence.path)
    symbol = _normalize(str(root.get("symbol", "")))
    effect = _normalize(str(families.get("effect_family_id", "")))
    capability = _normalize(str(families.get("capability_family_id", "")))
    if not path or not symbol or not effect or not capability:
        return ""
    if effect == "unresolved" or capability == "unresolved":
        return ""
    return "|".join((path, symbol, effect, capability))


def _same_candidate_or_cluster(first: Candidate, second: Candidate, nearby_lines: int = _NEARBY_LINES) -> bool:
    first_key = root_equivalence_key(first)
    second_key = root_equivalence_key(second)
    if first_key and second_key and first_key != second_key:
        return False
    return is_same_issue(first, second, nearby_lines) or bool(first_key and first_key == second_key)


@dataclass(slots=True)
class CandidateCluster:
    """Hypotheses with one structural root and one effect/capability family."""

    canonical: Candidate
    equivalence_key: str = ""
    members: list[Candidate] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.members:
            self.members = [self.canonical]


def _cluster_hypothesis(candidate: Candidate) -> dict[str, object]:
    return {
        "rule_id": candidate.rule_id,
        "title": candidate.title,
        "vulnerability_class": candidate.vulnerability_class,
        "root_cause": dict(candidate.metadata.get("root_cause") or {}),
        "root_equivalence": dict(candidate.metadata.get("root_equivalence") or {}),
        "evidence": {
            "path": candidate.evidence.path,
            "start_line": candidate.evidence.start_line,
            "end_line": candidate.evidence.end_line,
            "snippet": candidate.evidence.snippet[:1200],
        },
        "attacker_influence": str(candidate.metadata.get("attacker_influence", ""))[:300],
        "evidence_basis": dict(candidate.metadata.get("evidence_basis") or {}),
    }


def absorb_cluster(kept: Candidate, duplicate: Candidate) -> None:
    """Retain paraphrased hypotheses and evidence under one verifiable root."""

    members = kept.metadata.setdefault("candidate_cluster_variants", [_cluster_hypothesis(kept)])
    hypothesis = _cluster_hypothesis(duplicate)
    identity = (
        hypothesis["root_cause"].get("symbol"),
        hypothesis["root_equivalence"].get("effect_family_id"),
        hypothesis["root_equivalence"].get("capability_family_id"),
        hypothesis["evidence"].get("path"),
        hypothesis["evidence"].get("start_line"),
        hypothesis["evidence"].get("end_line"),
    )
    for existing in members:
        existing_identity = (
            existing.get("root_cause", {}).get("symbol"),
            existing.get("root_equivalence", {}).get("effect_family_id"),
            existing.get("root_equivalence", {}).get("capability_family_id"),
            existing.get("evidence", {}).get("path"),
            existing.get("evidence", {}).get("start_line"),
            existing.get("evidence", {}).get("end_line"),
        )
        if identity == existing_identity:
            break
    else:
        maximum = int(load_json("runtime/agent.json")["candidate_cluster_member_limit"])
        if len(members) < maximum:
            members.append(hypothesis)
    absorb(kept, duplicate)


def candidate_evidence_packet(candidate: Candidate) -> CandidateEvidencePacket:
    """Compile merged discovery evidence into the Deep Hunt input contract."""

    basis = dict(candidate.metadata.get("evidence_basis") or {})
    root_cause = dict(candidate.metadata.get("root_cause") or {})
    graph_path = [str(item) for item in candidate.evidence.graph_path if str(item)]
    trace_edges = [
        {"source": source, "target": target}
        for source, target in zip(graph_path, graph_path[1:], strict=False)
    ]
    supporting = [
        dict(item)
        for item in candidate.metadata.get("supporting_evidence", [])
        if isinstance(item, dict)
    ]
    discovery_context = [
        dict(item)
        for item in candidate.metadata.get("discovery_context", [])
        if isinstance(item, dict)
    ]
    capability = str(
        candidate.metadata.get("gained_capability")
        or root_cause.get("capability", "")
    ).strip()
    invariant = str(
        candidate.metadata.get("broken_invariant")
        or root_cause.get("broken_invariant", "")
    ).strip()
    return CandidateEvidencePacket(
        candidate_id=candidate_semantic_key(candidate) or candidate_fingerprint("", candidate),
        root_cause=root_cause,
        attacker_origins=[str(item) for item in basis.get("origin", [])],
        security_boundary=[str(item) for item in basis.get("expected_boundary", [])],
        invariant=invariant,
        downstream_trust=supporting + discovery_context,
        sensitive_effects=[str(item) for item in basis.get("sensitive_effect", [])],
        gained_capabilities=[capability] if capability else [],
        trace_nodes=graph_path,
        trace_edges=trace_edges,
        evidence_gaps=[str(item) for item in basis.get("missing_evidence", [])]
        + [str(item) for item in candidate.metadata.get("required_context", [])],
        candidate_cluster_variants=[
            dict(item)
            for item in candidate.metadata.get("candidate_cluster_variants", [])
            if isinstance(item, dict)
        ],
    )


def absorb(kept: Candidate, duplicate: Candidate) -> None:
    """Fold a repeat report into the candidate already kept instead of dropping its evidence."""
    kept.metadata["duplicate_reports"] = int(kept.metadata.get("duplicate_reports", 0)) + 1
    support = kept.metadata.setdefault("supporting_evidence", [])
    entry = {
        "path": duplicate.evidence.path,
        "start_line": duplicate.evidence.start_line,
        "end_line": duplicate.evidence.end_line,
        "attack_path": duplicate.evidence.graph_path[-1] if duplicate.evidence.graph_path else "",
    }
    limit = int(load_json("runtime/agent.json")["candidate_supporting_evidence_limit"])
    if len(support) < limit and entry not in support:
        support.append(entry)
    for duplicate_support in duplicate.metadata.get("supporting_evidence", []):
        if (
            isinstance(duplicate_support, dict)
            and len(support) < limit
            and duplicate_support not in support
        ):
            support.append(dict(duplicate_support))
    merged_context = kept.metadata.setdefault("discovery_context", [])
    for context in duplicate.metadata.get("discovery_context", []):
        if (
            isinstance(context, dict)
            and len(merged_context) < limit
            and context not in merged_context
        ):
            merged_context.append(dict(context))


def is_same_issue(first: Candidate, second: Candidate, nearby_lines: int = _NEARBY_LINES) -> bool:
    """Whether two candidates describe one root cause at one place in the code.

    The model names the same bug differently on every call (class, category and
    symbols are free text), so exact-fingerprint matching lets one bug fan out
    into dozens of reviews. Rich semantic identities are authoritative: a
    mismatch never falls back to lexical similarity. Older candidates without
    that identity use a nearby-line/classification heuristic.
    """
    a, b = first.evidence, second.evidence
    if a.path != b.path:
        return False
    first_key = candidate_semantic_key(first)
    second_key = candidate_semantic_key(second)
    if first_key and second_key:
        return first_key == second_key
    shared_ids = _classification_ids(first) & _classification_ids(second)
    shared_words = _issue_tokens(first) & _issue_tokens(second)
    if abs(a.start_line - b.start_line) <= nearby_lines:
        return bool(shared_ids or shared_words)
    # Wide reports about one broad region (a middleware ordering flaw spans many
    # routes) need stronger agreement, since overlap alone is weak evidence.
    overlaps = a.start_line <= b.end_line and b.start_line <= a.end_line
    return overlaps and (bool(shared_ids) or len(shared_words) >= 2)


class CandidateIndex:
    """Thread-safe record of candidates already seen in a scan."""

    def __init__(self, nearby_lines: int = _NEARBY_LINES) -> None:
        # Variant sweeps look for siblings of a known bug, so they compare at
        # exact locations (nearby_lines=0); discovery collapses restatements.
        self._nearby_lines = nearby_lines
        self._lock = threading.Lock()
        self._kept: dict[str, list[CandidateCluster]] = {}

    def admit(self, candidate: Candidate) -> bool:
        """Record the candidate; False when it repeats one already seen."""
        with self._lock:
            kept = self._kept.setdefault(candidate.evidence.path, [])
            equivalence = root_equivalence_key(candidate)
            for cluster in kept:
                existing = cluster.canonical
                if _same_candidate_or_cluster(existing, candidate, self._nearby_lines):
                    if equivalence and equivalence == cluster.equivalence_key:
                        cluster.members.append(candidate)
                        absorb_cluster(existing, candidate)
                    else:
                        absorb(existing, candidate)
                    return False
            kept.append(CandidateCluster(candidate, equivalence))
            return True


def deduplicate(repository: str, candidates: list[Candidate]) -> tuple[list[Candidate], int]:
    unique: dict[str, Candidate] = {}
    for candidate in candidates:
        fingerprint = candidate_fingerprint(repository, candidate)
        current = unique.get(fingerprint)
        if current is None:
            unique[fingerprint] = candidate
        elif candidate.confidence > current.confidence:
            absorb(candidate, current)
            unique[fingerprint] = candidate
        else:
            absorb(current, candidate)
    clusters: list[Candidate] = []
    for candidate in sorted(unique.values(), key=lambda item: -item.confidence):
        match = next(
            (
                kept
                for kept in clusters
                if _same_candidate_or_cluster(kept, candidate)
            ),
            None,
        )
        if match is None:
            clusters.append(candidate)
        elif root_equivalence_key(match) and root_equivalence_key(match) == root_equivalence_key(candidate):
            absorb_cluster(match, candidate)
        else:
            absorb(match, candidate)
    order = {id(candidate): index for index, candidate in enumerate(unique.values())}
    clusters.sort(key=lambda item: order[id(item)])
    return clusters, len(candidates) - len(clusters)
