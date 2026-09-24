"""Deterministic merge policy over verified SCM review facts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .assets import load_json
from .baseline import FindingBaselineClassification

MergeDecision = Literal[
    "PASS",
    "WARN",
    "BLOCK",
    "INCOMPLETE",
    "REQUIRE_SECURITY_APPROVAL",
]


# Human triage verdicts that the policy may honour, mapped to their policy key.
TRIAGE_CLOSED_STATES: dict[str, str] = {
    "false_positive": "false_positive_triage_decision",
    "accepted_risk": "accepted_risk_triage_decision",
}


class MergePolicyConfigurationError(RuntimeError):
    """Raised when the versioned merge policy cannot produce a safe decision."""


@dataclass(frozen=True, slots=True)
class FindingPolicyDisposition:
    finding_fingerprint: str
    relationship: str
    severity: str
    confidence: float
    decision: MergeDecision
    reason: str
    triage_state: str | None = None


@dataclass(frozen=True, slots=True)
class MergePolicyResult:
    decision: MergeDecision
    policy_version: str
    dispositions: tuple[FindingPolicyDisposition, ...]
    blocking_count: int
    warning_count: int
    approval_count: int
    existing_count: int
    resolved_count: int
    incomplete: bool
    reasons: tuple[str, ...]
    triaged_count: int = 0
    in_triage_count: int = 0


def evaluate_merge_policy(
    classifications: tuple[FindingBaselineClassification, ...],
    *,
    coverage_complete: bool,
    configuration_complete: bool = True,
    triage_states: Mapping[str, str] | None = None,
) -> MergePolicyResult:
    """`triage_states` maps finding fingerprint -> human triage state; it never widens a block."""

    policy = load_json("policies/default.json")
    _validate_policy(policy)
    blocking_relationships = {str(value) for value in policy["blocking_relationships"]}
    blocking_severities = {str(value).lower() for value in policy["blocking_severities"]}
    warning_severities = {str(value).lower() for value in policy["warning_severities"]}
    minimum_confidence = float(policy["minimum_verified_confidence"])
    dispositions: list[FindingPolicyDisposition] = []

    states = triage_states or {}
    for finding in classifications:
        triage_state = states.get(finding.finding_fingerprint)
        decision, reason = _finding_decision(
            finding,
            triage_state,
            blocking_relationships,
            blocking_severities,
            warning_severities,
            minimum_confidence,
            policy,
        )
        dispositions.append(
            FindingPolicyDisposition(
                finding_fingerprint=finding.finding_fingerprint,
                relationship=finding.relationship,
                severity=finding.severity,
                confidence=finding.confidence,
                decision=decision,
                reason=reason,
                triage_state=triage_state,
            )
        )

    incomplete = not coverage_complete or not configuration_complete
    candidate_decisions: list[MergeDecision] = [item.decision for item in dispositions]
    reasons = [item.reason for item in dispositions if item.decision != "PASS"]
    if incomplete:
        candidate_decisions.append(str(policy["incomplete_decision"]))  # type: ignore[arg-type]
        reasons.append("Required changed-surface coverage or review configuration is incomplete.")
    if not candidate_decisions:
        candidate_decisions.append("PASS")
    decision = _highest_precedence(candidate_decisions, policy)
    actionable = [
        (finding, item)
        for finding, item in zip(classifications, dispositions, strict=True)
        if finding.verification_state == "verified" and finding.relationship not in {"EXISTING", "RESOLVED"}
    ]
    return MergePolicyResult(
        decision=decision,
        policy_version=str(policy["version"]),
        dispositions=tuple(dispositions),
        blocking_count=sum(item.decision == "BLOCK" for item in dispositions),
        warning_count=sum(item.decision == "WARN" for item in dispositions),
        approval_count=sum(item.decision == "REQUIRE_SECURITY_APPROVAL" for item in dispositions),
        existing_count=sum(item.relationship == "EXISTING" for item in classifications),
        resolved_count=sum(item.relationship == "RESOLVED" for item in classifications),
        incomplete=incomplete,
        reasons=tuple(dict.fromkeys(reasons)),
        triaged_count=sum(item.triage_state in TRIAGE_CLOSED_STATES for _, item in actionable),
        in_triage_count=sum(item.triage_state not in TRIAGE_CLOSED_STATES for _, item in actionable),
    )


def _finding_decision(
    finding: FindingBaselineClassification,
    triage_state: str | None,
    blocking_relationships: set[str],
    blocking_severities: set[str],
    warning_severities: set[str],
    minimum_confidence: float,
    policy: dict[str, object],
) -> tuple[MergeDecision, str]:
    if finding.relationship == "EXISTING":
        return _configured_decision(policy, "existing_relationship_decision"), "Existing baseline debt is non-blocking."
    if finding.relationship == "RESOLVED":
        return _configured_decision(policy, "resolved_relationship_decision"), "Resolved baseline finding is informational."
    if finding.verification_state != "verified":
        return "PASS", "No current independently verified vulnerability requires merge action."
    if triage_state in TRIAGE_CLOSED_STATES:
        return (
            _configured_decision(policy, TRIAGE_CLOSED_STATES[triage_state]),
            f"Verified finding was triaged as {triage_state} by an authorized reviewer.",
        )
    if finding.confidence < minimum_confidence:
        return (
            _configured_decision(policy, "low_confidence_verified_decision"),
            "Verified result is below the configured automatic merge-decision confidence.",
        )
    severity = finding.severity.lower()
    if severity not in blocking_severities | warning_severities:
        return (
            _configured_decision(policy, "unknown_severity_decision"),
            f"Verified result uses unrecognized severity {finding.severity!r}.",
        )
    if finding.relationship in blocking_relationships and severity in blocking_severities:
        return "BLOCK", "Verified changed-root risk matches blocking policy."
    if finding.relationship in blocking_relationships and severity in warning_severities:
        return "WARN", "Verified changed-root risk matches warning policy."
    return "PASS", "Verified finding does not match an enabled new-risk merge rule."


def _configured_decision(policy: dict[str, object], key: str) -> MergeDecision:
    value = str(policy[key])
    if value not in _allowed_decisions():
        raise MergePolicyConfigurationError(f"{key} contains unsupported decision {value!r}")
    return value  # type: ignore[return-value]


def _highest_precedence(
    decisions: list[MergeDecision],
    policy: dict[str, object],
) -> MergeDecision:
    precedence = [str(value) for value in policy["decision_precedence"]]  # type: ignore[index]
    for value in precedence:
        if value in decisions:
            return value  # type: ignore[return-value]
    raise MergePolicyConfigurationError("decision_precedence does not cover the produced decisions")


def _validate_policy(policy: dict[str, object]) -> None:
    required = {
        "version",
        "blocking_relationships",
        "blocking_severities",
        "warning_severities",
        "minimum_verified_confidence",
        "existing_relationship_decision",
        "resolved_relationship_decision",
        "low_confidence_verified_decision",
        "unknown_severity_decision",
        "incomplete_decision",
        "decision_precedence",
        *TRIAGE_CLOSED_STATES.values(),
    }
    missing = sorted(required - set(policy))
    if missing:
        raise MergePolicyConfigurationError(f"merge policy is missing required fields: {', '.join(missing)}")
    blocking = {str(value).lower() for value in policy["blocking_severities"]}  # type: ignore[union-attr]
    warning = {str(value).lower() for value in policy["warning_severities"]}  # type: ignore[union-attr]
    if blocking & warning:
        raise MergePolicyConfigurationError("blocking and warning severity sets must be disjoint")
    minimum = float(policy["minimum_verified_confidence"])
    if not 0 <= minimum <= 1:
        raise MergePolicyConfigurationError("minimum_verified_confidence must be between zero and one")
    precedence = [str(value) for value in policy["decision_precedence"]]  # type: ignore[index]
    if set(precedence) != _allowed_decisions() or len(precedence) != len(set(precedence)):
        raise MergePolicyConfigurationError("decision_precedence must list every merge decision exactly once")
    for key in (
        "existing_relationship_decision",
        "resolved_relationship_decision",
        "low_confidence_verified_decision",
        "unknown_severity_decision",
        "incomplete_decision",
        *TRIAGE_CLOSED_STATES.values(),
    ):
        _configured_decision(policy, key)


def _allowed_decisions() -> set[str]:
    return {"PASS", "WARN", "BLOCK", "INCOMPLETE", "REQUIRE_SECURITY_APPROVAL"}
