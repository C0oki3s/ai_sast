from __future__ import annotations

from pathlib import Path

from .assets import load_json
from .fingerprint import candidate_fingerprint
from .models import Candidate, Finding, FindingState, RouteDecision, Severity


class FindingValidator:
    def validate(
        self,
        repository: str,
        root: Path,
        candidate: Candidate,
        route: RouteDecision,
    ) -> Finding | None:
        confidence = candidate.confidence
        validator = "candidate-intake"
        evidence = candidate.evidence

        impact = str(candidate.metadata.get("ai_business_impact") or candidate.message)
        defaults = load_json("policy/candidate_defaults.json")
        remediation = str(
            candidate.metadata.get("ai_remediation")
            or defaults["provisional_remediation"]
        )
        score = priority_score(candidate.severity, confidence, route.depth.value)
        return Finding(
            fingerprint=candidate_fingerprint(repository, candidate),
            repository=repository,
            rule_id=candidate.rule_id,
            title=candidate.title,
            vulnerability_class=candidate.vulnerability_class,
            severity=candidate.severity,
            confidence=confidence,
            state=FindingState.DISCOVERED,
            message=candidate.message,
            impact=impact,
            remediation=remediation,
            evidence=evidence,
            priority_score=score,
            validator=validator,
            metadata={
                **candidate.metadata,
                "jev_depth": route.depth.value,
                "jev_task_class": route.task_class,
                "jev_model_tier": route.model_tier.value,
                "jev_needs_validation": route.needs_validation,
                "jev_needs_deep_hunt": route.needs_deep_hunt,
                "context_profile": route.profile,
            },
        )


def priority_score(severity: Severity, confidence: float, depth: str) -> int:
    """Apply the externally versioned presentation-priority policy to an AI verdict."""
    policy = load_json("policy/priority.json")
    base = int(policy["severity_base"][severity.value])
    depth_bonus = int(policy["depth_bonus"].get(depth, 0))
    return min(int(policy["maximum_score"]), round(base * confidence + depth_bonus))
