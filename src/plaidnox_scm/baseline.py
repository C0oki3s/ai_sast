"""Baseline-relative classification for verified PR/MR findings.

This layer compares independently verified head results with immutable findings
from the exact base revision. It does not decide whether a vulnerability is
valid and it does not assign severity or merge policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from .baseline_models import BaselineFinding
from .dedupe import IssueSignature, canonical_class, evidence_text, same_issue, signature, verification_signature
from .diffing import Diff
from .l1_review import L1Candidate
from .verification import CandidateVerification

BaselineRelationship = Literal[
    "INTRODUCED",
    "REGRESSED",
    "MODIFIED_EXISTING",
    "EXISTING",
    "RESOLVED",
]


@dataclass(frozen=True, slots=True)
class FindingBaselineClassification:
    relationship: BaselineRelationship
    root_cause_fingerprint: str
    finding_fingerprint: str
    candidate_id: str | None
    verification_state: str
    baseline_state: str | None
    root_cause_path: str
    root_cause_symbol: str
    vulnerability_class: str
    title: str
    severity: str
    confidence: float
    root_cause_changed_in_review: bool
    reason: str


@dataclass(frozen=True, slots=True)
class PriorFinding:
    signature: IssueSignature
    root_cause_fingerprint: str
    finding_fingerprint: str


def prior_findings_from_stored(findings: Any) -> tuple[PriorFinding, ...]:
    """Read matchable identities from previous completed runs, newest first."""
    prior: list[PriorFinding] = []
    seen: set[str] = set()
    for item in findings or ():
        if not isinstance(item, dict):
            continue
        finding_id = str(item.get("finding_id") or "")
        root_id = str(item.get("root_cause_fingerprint") or "")
        path = str(item.get("root_cause_path") or "")
        if not finding_id or not root_id or not path or finding_id in seen:
            continue
        seen.add(finding_id)
        start = int(item.get("root_cause_start_line") or 1)
        snippet = item.get("vulnerable_snippet")
        code = (snippet.get("code") or snippet.get("content")) if isinstance(snippet, dict) else None
        trace = item.get("evidence_trace")
        nodes = trace.get("nodes") if isinstance(trace, dict) else None
        trace_nodes = (
            (str(node.get("role") or ""), str(node.get("path") or ""), str(node.get("code") or ""))
            for node in (nodes or ()) if isinstance(node, dict)
        )
        prior.append(PriorFinding(
            signature=signature(
                path=path, symbol=str(item.get("root_cause_symbol") or ""),
                start_line=start, end_line=int(item.get("root_cause_end_line") or start),
                title=str(item.get("title") or ""),
                vulnerability_class=str(item.get("category") or ""),
                remediation=str(item.get("remediation") or ""),
                security_invariant=str(item.get("security_invariant") or ""),
                references=(ref for ref in item.get("classification_references") or () if isinstance(ref, dict)),
                root_code=code if isinstance(code, str) else None,
                source_code=evidence_text(code if isinstance(code, str) else None, trace_nodes),
            ),
            root_cause_fingerprint=root_id,
            finding_fingerprint=finding_id,
        ))
    return tuple(prior)


def classify_against_baseline(
    codebase_id: str,
    diff: Diff,
    candidates: tuple[L1Candidate, ...],
    verifications: tuple[CandidateVerification, ...],
    baseline_findings: tuple[BaselineFinding, ...],
    security_controls: tuple[Any, ...],
    *,
    coverage_complete: bool,
    prior_findings: tuple[PriorFinding, ...] = (),
    forced_identities: dict[str, tuple[str, str]] | None = None,
    baseline_signatures: tuple[PriorFinding, ...] = (),
) -> tuple[FindingBaselineClassification, ...]:
    """Compare head verification results to findings from the exact base.

    A baseline finding is never called resolved merely because L1 did not emit
    a candidate. Resolution requires a matching, changed-root candidate whose
    independent verification rejected the vulnerability with complete
    evidence. This preserves existing debt when PR coverage is partial.
    """

    candidate_by_id = {item.candidate_id: item for item in candidates}
    baseline_by_root = {item.root_cause_fingerprint: item for item in baseline_findings}
    baseline_by_location: dict[tuple[str, str], list[BaselineFinding]] = {}
    for item in baseline_findings:
        baseline_by_location.setdefault(
            (_normalise_path(item.root_cause_path), _normalise_text(item.root_cause_symbol)),
            [],
        ).append(item)

    classifications: list[FindingBaselineClassification] = []
    matched_roots: set[str] = set()
    claimed_prior: set[str] = set()
    for verification in verifications:
        candidate = candidate_by_id.get(verification.candidate_id)
        if candidate is None:
            continue
        current = verification_signature(candidate, verification)
        root_changed = _path_changed(diff, candidate.changed_path)
        issue_class = canonical_class(
            verification.classification_references, verification.vulnerability_class, verification.title
        )
        root_fingerprint = root_cause_fingerprint(
            codebase_id,
            candidate.changed_path,
            candidate.changed_symbol,
            issue_class,
            current.source_hash if verification.state == "verified" else None,
        )
        reused_finding: str | None = None
        forced = (forced_identities or {}).get(verification.candidate_id)
        if forced is not None:
            # A tracked finding seen again (re-check, or identical code) keeps its identity.
            root_fingerprint, reused_finding = forced
        baseline = baseline_by_root.get(root_fingerprint)
        if baseline is None and forced is None and baseline_signatures and verification.state == "verified":
            # The same bug as an open default-branch finding, reworded or moved: existing debt.
            branch = next((item for item in baseline_signatures if same_issue(item.signature, current)), None)
            if branch is not None and branch.root_cause_fingerprint in baseline_by_root:
                baseline = baseline_by_root[branch.root_cause_fingerprint]
                root_fingerprint = baseline.root_cause_fingerprint
                reused_finding = branch.finding_fingerprint
        if baseline is None and forced is None:
            location_matches = baseline_by_location.get(
                (_normalise_path(candidate.changed_path), _normalise_text(candidate.changed_symbol)),
                [],
            )
            if len(location_matches) == 1 and canonical_class(
                (), location_matches[0].vulnerability_class, location_matches[0].title
            ) == issue_class:
                baseline = location_matches[0]
        if forced is None and reused_finding is None and verification.state == "verified" and prior_findings:
            prior = next((item for item in prior_findings
                          if item.finding_fingerprint not in claimed_prior
                          and item.signature.source_hash is not None
                          and item.signature.source_hash == current.source_hash
                          and same_issue(item.signature, current)), None)
            if prior is not None:
                claimed_prior.add(prior.finding_fingerprint)
                root_fingerprint = prior.root_cause_fingerprint
                reused_finding = prior.finding_fingerprint
        elif baseline is not None and not root_changed and reused_finding is None:
            # The unchanged baseline identity is safe to retain. A changed path
            # needs matching source evidence from a prior run before triage follows.
            root_fingerprint = baseline.root_cause_fingerprint

        if verification.state == "verified":
            relationship = _verified_relationship(
                candidate,
                baseline,
                root_changed,
                security_controls,
            )
        elif (
            verification.state == "rejected"
            and baseline is not None
            and baseline.lifecycle_state != "resolved"
            and root_changed
            and coverage_complete
        ):
            relationship = "RESOLVED"
        elif baseline is not None and baseline.lifecycle_state != "resolved":
            relationship = "EXISTING"
        else:
            continue

        if baseline is not None:
            matched_roots.add(baseline.root_cause_fingerprint)
        classifications.append(
            FindingBaselineClassification(
                relationship=relationship,
                root_cause_fingerprint=root_fingerprint,
                finding_fingerprint=(
                    reused_finding
                    or (baseline.finding_fingerprint if baseline is not None and not root_changed else None)
                    or finding_fingerprint(
                        root_fingerprint,
                        issue_class + "|" + "-".join(sorted(current.invariant_tokens)),
                    )
                ),
                candidate_id=candidate.candidate_id,
                verification_state=verification.state,
                baseline_state=baseline.lifecycle_state if baseline is not None else None,
                root_cause_path=candidate.changed_path,
                root_cause_symbol=candidate.changed_symbol,
                vulnerability_class=verification.vulnerability_class,
                title=verification.title,
                severity=verification.severity,
                confidence=verification.confidence,
                root_cause_changed_in_review=root_changed,
                reason=_classification_reason(relationship, verification.state),
            )
        )

    for baseline in baseline_findings:
        if baseline.root_cause_fingerprint in matched_roots or baseline.lifecycle_state == "resolved":
            continue
        classifications.append(
            FindingBaselineClassification(
                relationship="EXISTING",
                root_cause_fingerprint=baseline.root_cause_fingerprint,
                finding_fingerprint=baseline.finding_fingerprint,
                candidate_id=None,
                verification_state="baseline",
                baseline_state=baseline.lifecycle_state,
                root_cause_path=baseline.root_cause_path,
                root_cause_symbol=baseline.root_cause_symbol,
                vulnerability_class=baseline.vulnerability_class,
                title=baseline.title,
                severity=baseline.severity,
                confidence=baseline.confidence,
                root_cause_changed_in_review=_path_changed(diff, baseline.root_cause_path),
                reason="Verified baseline finding remains open; this review did not independently resolve it.",
            )
        )

    return tuple(
        sorted(
            classifications,
            key=lambda item: (
                item.relationship,
                item.root_cause_path,
                item.root_cause_symbol,
                item.finding_fingerprint,
            ),
        )
    )


def root_cause_fingerprint(
    codebase_id: str,
    path: str,
    symbol: str,
    vulnerability_class: str,
    evidence_hash: str | None = None,
) -> str:
    parts = ("root", codebase_id, _normalise_path(path), _normalise_text(symbol), _normalise_text(vulnerability_class))
    return _digest(*parts, evidence_hash) if evidence_hash else _digest(*parts)


def finding_fingerprint(root_fingerprint: str, issue_class: str) -> str:
    return _digest("finding", root_fingerprint, _normalise_text(issue_class))


def _verified_relationship(
    candidate: L1Candidate,
    baseline: BaselineFinding | None,
    root_changed: bool,
    security_controls: tuple[Any, ...],
) -> BaselineRelationship:
    if baseline is not None:
        if baseline.lifecycle_state == "resolved":
            return "REGRESSED"
        return "MODIFIED_EXISTING" if root_changed else "EXISTING"
    if root_changed and _is_baseline_security_control(candidate, security_controls):
        return "REGRESSED"
    return "INTRODUCED"


def _is_baseline_security_control(
    candidate: L1Candidate,
    security_controls: tuple[Any, ...],
) -> bool:
    candidate_path = _normalise_path(candidate.changed_path)
    candidate_symbol = _normalise_text(candidate.changed_symbol)
    for control in security_controls:
        for value in _string_values(control):
            normalised_path = _normalise_path(value)
            normalised_text = _normalise_text(value)
            path_stem = _normalise_text(
                normalised_path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            )
            if (
                candidate_path == normalised_path
                or candidate_symbol == normalised_text
                or candidate_symbol == path_stem
            ):
                return True
    return False


def _string_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, dict):
        return tuple(item for nested in value.values() for item in _string_values(nested))
    if isinstance(value, (list, tuple)):
        return tuple(item for nested in value for item in _string_values(nested))
    return ()


def _path_changed(diff: Diff, path: str) -> bool:
    normalised = _normalise_path(path)
    return any(
        normalised in {
            _normalise_path(item.path),
            _normalise_path(item.old_path or ""),
        }
        for item in diff.files
    )


def _normalise_path(value: str) -> str:
    return value.replace("\\", "/").strip().lstrip("./")


def _normalise_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _digest(*parts: str) -> str:
    payload = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _classification_reason(relationship: BaselineRelationship, state: str) -> str:
    reasons = {
        "INTRODUCED": "Verified at a changed root cause with no matching baseline finding or control.",
        "REGRESSED": "Verified change weakens a baseline security control or reopens a resolved finding.",
        "MODIFIED_EXISTING": "Verified baseline finding remains present and its root cause changed in this review.",
        "EXISTING": "Baseline finding remains open and was not independently resolved by this review.",
        "RESOLVED": "Affected baseline finding was independently rejected with complete review evidence.",
    }
    return f"{reasons[relationship]} Verification state: {state}."
