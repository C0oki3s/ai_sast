from plaidnox_sast.models import Evidence, Finding, FindingState, PolicyDecision, Severity
from plaidnox_sast.policy_ast import CompiledPolicyEngine, compiled_policy_from_dict
from plaidnox_sast.pr_review import ReviewFinding, ReviewFindingChange


def _finding(*, severity: Severity, confidence: float, boundary: str = "", environment: str = "") -> Finding:
    return Finding(
        fingerprint="fp-1",
        repository="org/repo",
        rule_id="ai",
        title="Example",
        vulnerability_class="authorization failure",
        severity=severity,
        confidence=confidence,
        state=FindingState.VALIDATED,
        message="example",
        impact="example",
        remediation="example",
        evidence=Evidence("app.py", 10, 12),
        priority_score=1,
        validator="plaidnox-deep-hunt",
        metadata={"security_boundary": boundary, "environment": environment},
    )


def test_compiled_policy_blocks_new_high_on_main() -> None:
    policy = compiled_policy_from_dict(
        {
            "policy_id": "default",
            "version": 1,
            "source_text": "Block new high or critical findings on main.",
            "default_action": "allow",
            "rules": [
                {
                    "rule_id": "new-high",
                    "description": "Block introduced high or critical findings on main",
                    "match": {
                        "target_branches": ["main"],
                        "change_states": ["introduced"],
                        "severities": ["high", "critical"],
                        "minimum_confidence": 0.7,
                        "verification_states": ["validated"],
                        "security_boundaries": [],
                        "capabilities": [],
                        "environments": [],
                        "finding_types": [],
                        "credential_states": [],
                    },
                    "action": "block",
                }
            ],
        }
    )
    result = CompiledPolicyEngine().evaluate(
        policy,
        [ReviewFinding(_finding(severity=Severity.HIGH, confidence=0.95), ReviewFindingChange.INTRODUCED)],
        "main",
    )
    assert result.decision is PolicyDecision.BLOCK
    assert result.matched_rule_ids == ["new-high"]


def test_existing_high_does_not_match_new_only_policy() -> None:
    policy = compiled_policy_from_dict(
        {
            "policy_id": "default",
            "version": 1,
            "source_text": "Block new high findings on main.",
            "default_action": "allow",
            "rules": [
                {
                    "rule_id": "new-high",
                    "description": "Block introduced high findings",
                    "match": {
                        "target_branches": ["main"],
                        "change_states": ["introduced"],
                        "severities": ["high"],
                        "minimum_confidence": null,
                        "verification_states": [],
                        "security_boundaries": [],
                        "capabilities": [],
                        "environments": [],
                        "finding_types": [],
                        "credential_states": [],
                    },
                    "action": "block",
                }
            ],
        }
    )
    result = CompiledPolicyEngine().evaluate(
        policy,
        [ReviewFinding(_finding(severity=Severity.HIGH, confidence=0.99), ReviewFindingChange.EXISTING)],
        "main",
    )
    assert result.decision is PolicyDecision.PASS
