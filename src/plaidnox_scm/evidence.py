"""Provider-neutral PR/MR evidence-role model."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .assets import load_json
from .context_broker import CandidateContextExpansion
from .l1_review import L1Candidate


class EvidenceRole(StrEnum):
    ROOT_CAUSE_CHANGED_CODE = "ROOT_CAUSE_CHANGED_CODE"
    ATTACKER_ORIGIN = "ATTACKER_ORIGIN"
    SECURITY_BOUNDARY = "SECURITY_BOUNDARY"
    DEFENSE_REMOVED_OR_BYPASSED = "DEFENSE_REMOVED_OR_BYPASSED"
    DOWNSTREAM_TRUST = "DOWNSTREAM_TRUST"
    SENSITIVE_EFFECT = "SENSITIVE_EFFECT"
    CONTEXT_ONLY = "CONTEXT_ONLY"


@dataclass(frozen=True, slots=True)
class ReviewEvidence:
    role: EvidenceRole
    source: str
    path: str
    start_line: int | None
    end_line: int | None
    summary: str


def build_review_evidence(
    candidate: L1Candidate,
    expansion: CandidateContextExpansion,
    deep_hunt_locations: list[dict[str, Any]],
) -> tuple[ReviewEvidence, ...]:
    policy = load_json("runtime/review.json")["evidence_roles"]
    values = [
        ReviewEvidence(
            role=EvidenceRole(str(policy["root_cause"])),
            source="changed_code",
            path=candidate.changed_path,
            start_line=candidate.changed_lines.start,
            end_line=candidate.changed_lines.end,
            summary=f"{candidate.behavior_before} -> {candidate.behavior_after}",
        )
    ]
    context_role = EvidenceRole(str(policy["context"]))
    for item in expansion.evidence:
        for record in item.records:
            values.append(
                ReviewEvidence(
                    role=context_role,
                    source="context_broker",
                    path=str(record.get("path", "")),
                    start_line=_optional_line(record.get("start_line")),
                    end_line=_optional_line(record.get("end_line")),
                    summary=item.reason,
                )
            )
    mapping = {str(key): EvidenceRole(str(value)) for key, value in policy["deep_hunt_mapping"].items()}
    for location in deep_hunt_locations:
        role = mapping.get(str(location.get("role", "")))
        if role is None:
            continue
        values.append(
            ReviewEvidence(
                role=role,
                source="deep_hunt",
                path=str(location.get("path", "")),
                start_line=_optional_line(location.get("start_line")),
                end_line=_optional_line(location.get("end_line")),
                summary=f"Deep Hunt {location.get('role', 'evidence')!s} evidence",
            )
        )
    return tuple(values)


def _optional_line(value: object) -> int | None:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None
