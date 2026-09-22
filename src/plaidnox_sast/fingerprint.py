from __future__ import annotations

import hashlib
import re

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


def deduplicate(repository: str, candidates: list[Candidate]) -> tuple[list[Candidate], int]:
    unique: dict[str, Candidate] = {}
    for candidate in candidates:
        fingerprint = candidate_fingerprint(repository, candidate)
        current = unique.get(fingerprint)
        if current is None or candidate.confidence > current.confidence:
            unique[fingerprint] = candidate
    return list(unique.values()), len(candidates) - len(unique)
