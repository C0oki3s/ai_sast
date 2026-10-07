"""Conservative identity matching for independently verified SCM findings."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace

from .l1_review import L1Candidate
from .verification import CandidateVerification

_CWE = re.compile(r"\bcwe[\s_:-]*(\d{1,5})\b", re.IGNORECASE)
_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_GENERIC = frozenset(
    "a an and are as at by can code data for from in into is it of on or security the to via with "
    "issue vulnerability weakness input output function request user access control missing improper "
    "allow allows use uses using not without change changed".split()
)


@dataclass(frozen=True, slots=True)
class IssueSignature:
    path: str
    symbol: str
    start: int
    end: int
    cwes: frozenset[str]
    class_tokens: frozenset[str]
    title_tokens: frozenset[str]
    fix_tokens: frozenset[str]
    invariant_tokens: frozenset[str]
    root_hash: str | None
    source_hash: str | None


def _tokens(text: str) -> frozenset[str]:
    return frozenset(word for word in re.findall(r"[a-z0-9]+", text.lower()) if len(word) > 2 and word not in _GENERIC)


def _similar(left: frozenset[str], right: frozenset[str], minimum: float) -> bool:
    return bool(left and right) and len(left & right) / len(left | right) >= minimum


def cwe_ids(references: Iterable[dict[str, object]], *texts: str) -> frozenset[str]:
    found: set[str] = set()
    for item in references:
        identifier = str(item.get("identifier") or "")
        if str(item.get("namespace") or "").upper() == "CWE" and identifier.isdigit():
            identifier = f"CWE-{identifier}"
        match = _CWE.search(identifier)
        if match:
            found.add(f"CWE-{int(match.group(1))}")
    for value in texts:
        found.update(f"CWE-{int(match.group(1))}" for match in _CWE.finditer(value))
    return frozenset(found)


def canonical_class(references: Iterable[dict[str, object]], vulnerability_class: str, title: str = "") -> str:
    cwes = cwe_ids(references, vulnerability_class, title)
    if cwes:
        return min(cwes, key=lambda value: int(value[4:])).lower()
    words = sorted(_tokens(vulnerability_class))
    return "-".join(words) or re.sub(r"\s+", " ", vulnerability_class.strip().lower())


def source_hash(code: str | None) -> str | None:
    if not code:
        return None
    # Whitespace-only edits do not change the source identity. Meaningful text does.
    normalized = " ".join(code.split())
    return hashlib.sha256(normalized.encode()).hexdigest() if normalized else None


def evidence_text(snippet_code: str | None, nodes: Iterable[tuple[str, str, str]]) -> str | None:
    """Version the root and validated trace source, without model prose or line offsets."""
    if not snippet_code:
        return None
    parts = [f"root:{snippet_code}"]
    parts.extend(f"{role}:{path}:{code}" for role, path, code in sorted(nodes) if code)
    return "\n".join(parts)


def signature(
    *, path: str, symbol: str, start_line: int, end_line: int | None, title: str,
    vulnerability_class: str, remediation: str = "", security_invariant: str = "",
    references: Iterable[dict[str, object]] = (), source_code: str | None = None,
    root_code: str | None = None,
) -> IssueSignature:
    start = max(1, int(start_line or 1))
    return IssueSignature(
        path=path.replace("\\", "/").strip().lstrip("./").lower(),
        symbol="".join(symbol.lower().split()).strip(),
        start=start,
        end=max(start, int(end_line or start)),
        cwes=cwe_ids(references, title, vulnerability_class),
        class_tokens=_tokens(vulnerability_class),
        title_tokens=_tokens(title),
        fix_tokens=_tokens(remediation),
        invariant_tokens=_tokens(security_invariant),
        root_hash=source_hash(root_code),
        source_hash=source_hash(source_code),
    )


def verification_signature(candidate: L1Candidate, verification: CandidateVerification) -> IssueSignature:
    snippet = verification.vulnerable_snippet
    trace = verification.evidence_trace
    source = evidence_text(
        snippet.content if snippet else None,
        ((node.role.value, node.path, node.code) for node in trace.nodes) if trace else (),
    )
    return signature(
        path=candidate.changed_path, symbol=candidate.changed_symbol,
        start_line=candidate.changed_lines.start, end_line=candidate.changed_lines.end,
        title=verification.title, vulnerability_class=verification.vulnerability_class,
        remediation=verification.remediation, security_invariant=verification.security_invariant,
        references=verification.classification_references,
        root_code=snippet.content if snippet else None,
        source_code=source,
    )


def same_issue(left: IssueSignature, right: IssueSignature) -> bool:
    """Prefer two visible findings over silently combining different bugs."""
    if not left.path or left.path != right.path:
        return False
    overlap = left.start <= right.end and right.start <= left.end
    nearby = max(left.start - right.end, right.start - left.end) <= 6
    same_source = bool(left.root_hash and left.root_hash == right.root_hash)
    if not (overlap or nearby or (left.symbol and left.symbol == right.symbol and same_source)):
        return False
    if left.cwes and right.cwes and not left.cwes.intersection(right.cwes):
        return False
    invariant_matches = _similar(left.invariant_tokens, right.invariant_tokens, 0.6)
    fix_matches = _similar(left.fix_tokens, right.fix_tokens, 0.65)
    class_matches = _similar(left.class_tokens, right.class_tokens, 0.6)
    title_matches = _similar(left.title_tokens, right.title_tokens, 0.65)
    if left.invariant_tokens and right.invariant_tokens and not invariant_matches:
        return False
    if left.cwes and right.cwes:
        return same_source or (invariant_matches and (fix_matches or title_matches))
    return (same_source or invariant_matches) and (fix_matches or (class_matches and title_matches))


@dataclass(frozen=True, slots=True)
class Consolidation:
    verifications: tuple[CandidateVerification, ...]
    merged_into: dict[str, str]


def consolidate_verified(
    candidates: tuple[L1Candidate, ...], verifications: tuple[CandidateVerification, ...]
) -> Consolidation:
    candidate_by_id = {item.candidate_id: item for item in candidates}
    verified = sorted(
        (item for item in verifications if item.state == "verified" and item.candidate_id in candidate_by_id),
        key=lambda item: (_SEVERITY.get(item.severity.lower(), 5), -item.confidence, item.candidate_id),
    )
    kept: list[tuple[IssueSignature, CandidateVerification]] = []
    merged: dict[str, str] = {}
    for item in verified:
        current = verification_signature(candidate_by_id[item.candidate_id], item)
        index = next((i for i, (existing, _) in enumerate(kept) if same_issue(existing, current)), None)
        if index is None:
            kept.append((current, item))
            continue
        existing_signature, strongest = kept[index]
        kept[index] = (existing_signature, _absorb(strongest, item))
        merged[item.candidate_id] = strongest.candidate_id
    kept_by_id = {item.candidate_id: item for _, item in kept}
    return Consolidation(
        tuple(kept_by_id.get(item.candidate_id, item) for item in verifications if item.candidate_id not in merged),
        merged,
    )


def _absorb(strongest: CandidateVerification, duplicate: CandidateVerification) -> CandidateVerification:
    evidence = list(strongest.evidence)
    keys = {(item.role, item.path, item.start_line, item.end_line) for item in evidence}
    for item in duplicate.evidence:
        key = (item.role, item.path, item.start_line, item.end_line)
        if key not in keys:
            evidence.append(item)
            keys.add(key)
    references = list(strongest.classification_references)
    for item in duplicate.classification_references:
        if item not in references:
            references.append(item)
    return replace(
        strongest, evidence=tuple(evidence), classification_references=tuple(references),
        evidence_gaps=tuple(dict.fromkeys((*strongest.evidence_gaps, *duplicate.evidence_gaps))),
    )
