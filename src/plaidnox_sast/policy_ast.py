from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .models import PolicyDecision, Severity
from .pr_review import ReviewFinding, ReviewFindingChange


class PolicyAction(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    REQUIRE_OWNER_APPROVAL = "require_owner_approval"
    REQUIRE_MANUAL_REVIEW = "require_manual_review"
    NOTIFY = "notify"


_ACTION_ORDER = {
    PolicyAction.ALLOW: 0,
    PolicyAction.NOTIFY: 1,
    PolicyAction.WARN: 2,
    PolicyAction.REQUIRE_OWNER_APPROVAL: 3,
    PolicyAction.REQUIRE_SECURITY_APPROVAL: 4,
    PolicyAction.REQUIRE_MANUAL_REVIEW: 5,
    PolicyAction.BLOCK: 6,
}


@dataclass(frozen=True, slots=True)
class PolicyMatch:
    target_branches: tuple[str, ...] = ()
    change_states: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    minimum_confidence: float | None = None
    verification_states: tuple[str, ...] = ()
    security_boundaries: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    environments: tuple[str, ...] = ()
    finding_types: tuple[str, ...] = ()
    credential_states: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CompiledPolicyRule:
    rule_id: str
    description: str
    match: PolicyMatch
    action: PolicyAction


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    policy_id: str
    version: int
    source_text: str
    rules: tuple[CompiledPolicyRule, ...]
    default_action: PolicyAction = PolicyAction.ALLOW


@dataclass(slots=True)
class CompiledPolicyResult:
    decision: PolicyDecision
    actions: list[PolicyAction]
    reasons: list[str]
    matched_rule_ids: list[str]


class CompiledPolicyEngine:
    """Deterministically evaluates a previously compiled natural-language policy."""

    def evaluate(
        self,
        policy: CompiledPolicy,
        findings: list[ReviewFinding],
        target_branch: str,
    ) -> CompiledPolicyResult:
        matches: list[tuple[CompiledPolicyRule, ReviewFinding]] = []
        for rule in policy.rules:
            for finding in findings:
                if self._matches(rule.match, finding, target_branch):
                    matches.append((rule, finding))

        if not matches:
            actions = [policy.default_action]
            return CompiledPolicyResult(
                self._decision(actions),
                actions,
                ["No compiled policy rule matched the PR/MR findings"],
                [],
            )

        actions = [rule.action for rule, _finding in matches]
        reasons = [
            f"{rule.rule_id}: {rule.description} matched {finding.finding.fingerprint}"
            for rule, finding in matches
        ]
        return CompiledPolicyResult(
            self._decision(actions),
            actions,
            reasons,
            list(dict.fromkeys(rule.rule_id for rule, _finding in matches)),
        )

    def _matches(self, condition: PolicyMatch, finding: ReviewFinding, target_branch: str) -> bool:
        value = finding.finding
        metadata = value.metadata

        if condition.target_branches and not any(
            fnmatch.fnmatch(target_branch, pattern) for pattern in condition.target_branches
        ):
            return False
        if condition.change_states and finding.change.value not in condition.change_states:
            return False
        if condition.severities and value.severity.value not in condition.severities:
            return False
        if condition.minimum_confidence is not None and value.confidence < condition.minimum_confidence:
            return False
        if condition.verification_states and value.state.value not in condition.verification_states:
            return False
        if condition.security_boundaries and str(metadata.get("security_boundary", "")) not in condition.security_boundaries:
            return False
        if condition.capabilities and str(metadata.get("capability", "")) not in condition.capabilities:
            return False
        if condition.environments and str(metadata.get("environment", "")) not in condition.environments:
            return False
        if condition.finding_types and str(metadata.get("finding_type", "")) not in condition.finding_types:
            return False
        if condition.credential_states and str(metadata.get("credential_state", "")) not in condition.credential_states:
            return False
        return True

    @staticmethod
    def _decision(actions: list[PolicyAction]) -> PolicyDecision:
        strongest = max(actions, key=lambda item: _ACTION_ORDER[item])
        if strongest is PolicyAction.BLOCK:
            return PolicyDecision.BLOCK
        if strongest in {
            PolicyAction.REQUIRE_SECURITY_APPROVAL,
            PolicyAction.REQUIRE_OWNER_APPROVAL,
            PolicyAction.REQUIRE_MANUAL_REVIEW,
        }:
            # Existing PolicyDecision has no approval state yet. Until the API grows one,
            # preserve merge-gating semantics as BLOCK while exposing the action separately.
            return PolicyDecision.BLOCK
        if strongest in {PolicyAction.WARN, PolicyAction.NOTIFY}:
            return PolicyDecision.WARN
        return PolicyDecision.PASS


def compiled_policy_from_dict(value: dict[str, Any]) -> CompiledPolicy:
    rules: list[CompiledPolicyRule] = []
    for raw in value.get("rules", []):
        match = raw.get("match", {})
        rules.append(
            CompiledPolicyRule(
                rule_id=str(raw["rule_id"]),
                description=str(raw.get("description", "")),
                match=PolicyMatch(
                    target_branches=tuple(str(item) for item in match.get("target_branches", [])),
                    change_states=tuple(str(item) for item in match.get("change_states", [])),
                    severities=tuple(str(item) for item in match.get("severities", [])),
                    minimum_confidence=(
                        float(match["minimum_confidence"])
                        if match.get("minimum_confidence") is not None
                        else None
                    ),
                    verification_states=tuple(str(item) for item in match.get("verification_states", [])),
                    security_boundaries=tuple(str(item) for item in match.get("security_boundaries", [])),
                    capabilities=tuple(str(item) for item in match.get("capabilities", [])),
                    environments=tuple(str(item) for item in match.get("environments", [])),
                    finding_types=tuple(str(item) for item in match.get("finding_types", [])),
                    credential_states=tuple(str(item) for item in match.get("credential_states", [])),
                ),
                action=PolicyAction(str(raw["action"])),
            )
        )
    return CompiledPolicy(
        policy_id=str(value["policy_id"]),
        version=int(value["version"]),
        source_text=str(value.get("source_text", "")),
        rules=tuple(rules),
        default_action=PolicyAction(str(value.get("default_action", "allow"))),
    )
