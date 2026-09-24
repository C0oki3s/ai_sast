from __future__ import annotations

import hashlib
import re
import threading

from .models import Candidate


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


def is_same_issue(first: Candidate, second: Candidate, nearby_lines: int = _NEARBY_LINES) -> bool:
    """Whether two candidates describe one root cause at one place in the code.

    The model names the same bug differently on every call (class, category and
    symbols are free text), so exact-fingerprint matching lets one bug fan out
    into dozens of reviews. Identity here is location plus meaning: same file,
    starting lines close together (or broadly overlapping with stronger agreement), and either a shared classification id or a
    shared specific word. Nearby but unrelated bugs (an injection next to a
    JWT flaw) share neither and stay separate.
    """
    a, b = first.evidence, second.evidence
    if a.path != b.path:
        return False
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
        self._kept: dict[str, list[Candidate]] = {}

    def admit(self, candidate: Candidate) -> bool:
        """Record the candidate; False when it repeats one already seen."""
        with self._lock:
            kept = self._kept.setdefault(candidate.evidence.path, [])
            for existing in kept:
                if is_same_issue(existing, candidate, self._nearby_lines):
                    existing.metadata["duplicate_reports"] = int(existing.metadata.get("duplicate_reports", 0)) + 1
                    return False
            kept.append(candidate)
            return True


def deduplicate(repository: str, candidates: list[Candidate]) -> tuple[list[Candidate], int]:
    unique: dict[str, Candidate] = {}
    for candidate in candidates:
        fingerprint = candidate_fingerprint(repository, candidate)
        current = unique.get(fingerprint)
        if current is None or candidate.confidence > current.confidence:
            unique[fingerprint] = candidate
    clusters: list[Candidate] = []
    for candidate in sorted(unique.values(), key=lambda item: -item.confidence):
        match = next((kept for kept in clusters if is_same_issue(kept, candidate)), None)
        if match is None:
            clusters.append(candidate)
        else:
            match.metadata["duplicate_reports"] = int(match.metadata.get("duplicate_reports", 0)) + 1
    order = {id(candidate): index for index, candidate in enumerate(unique.values())}
    clusters.sort(key=lambda item: order[id(item)])
    return clusters, len(candidates) - len(clusters)
