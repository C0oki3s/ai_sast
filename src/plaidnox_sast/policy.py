from __future__ import annotations

from .config import PolicyConfig
from .models import Finding, PolicyDecision, PolicyResult


class PolicyEngine:
    def evaluate(self, findings: list[Finding], config: PolicyConfig) -> PolicyResult:
        blocking = [
            finding
            for finding in findings
            if finding.severity.value in config.block_severities
            and finding.confidence >= config.minimum_confidence
        ]
        if blocking:
            return PolicyResult(
                PolicyDecision.BLOCK,
                [f"{len(blocking)} validated high-impact finding(s) meet the block policy"],
            )
        warnings = [
            finding
            for finding in findings
            if finding.severity.value in config.warn_severities
            and finding.confidence >= config.minimum_confidence
        ]
        if warnings:
            return PolicyResult(
                PolicyDecision.WARN,
                [f"{len(warnings)} validated finding(s) meet the warning policy"],
            )
        return PolicyResult(PolicyDecision.PASS, ["No validated finding meets a warn or block threshold"])
