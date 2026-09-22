from plaidnox_sast.config import PolicyConfig
from plaidnox_sast.models import (
    Evidence,
    Finding,
    FindingState,
    PolicyDecision,
    PolicyResult,
    ScanMode,
    ScanResult,
    Severity,
)
from plaidnox_sast.policy import PolicyEngine
from plaidnox_sast.reporters import to_sarif, write_markdown


def finding(severity=Severity.HIGH, confidence=0.9):
    return Finding(
        fingerprint="abc",
        repository="org/repo",
        rule_id="secret",
        title="Secret",
        vulnerability_class="CWE-798",
        severity=severity,
        confidence=confidence,
        state=FindingState.VALIDATED,
        message="secret detected",
        impact="impact",
        remediation="rotate",
        evidence=Evidence("app.js", 2, 2, "[secret value redacted]"),
        priority_score=80,
        validator="plaidnox-deep-hunt",
    )


def test_policy_blocks_validated_high_severity():
    result = PolicyEngine().evaluate([finding()], PolicyConfig())
    assert result.decision is PolicyDecision.BLOCK


def test_policy_honors_confidence_threshold():
    result = PolicyEngine().evaluate([finding(confidence=0.4)], PolicyConfig())
    assert result.decision is PolicyDecision.PASS


def test_sarif_contains_redacted_evidence_and_fingerprint():
    report_finding = finding()
    report_finding.metadata["consolidation"] = {
        "alternative_evidence": [{"path": "routes/admin.js", "start_line": 8, "end_line": 11}]
    }
    result = ScanResult(
        codebase="org/repo",
        revision="deadbeef",
        mode=ScanMode.DEEP,
        findings=[report_finding],
        policy=PolicyResult(PolicyDecision.BLOCK, ["reason"]),
        metrics={},
    )
    sarif = to_sarif(result)
    entry = sarif["runs"][0]["results"][0]
    assert entry["partialFingerprints"]["plaidnoxFingerprint"] == "abc"
    assert entry["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == "[secret value redacted]"
    assert entry["locations"][1]["physicalLocation"]["artifactLocation"]["uri"] == "routes/admin.js"


def test_markdown_report_is_human_readable_and_redacted(tmp_path):
    report_finding = finding()
    report_finding.metadata["consolidation"] = {
        "alternative_evidence": [{"path": "routes/admin.js", "start_line": 8, "end_line": 11}]
    }
    result = ScanResult(
        codebase="org/repo",
        revision="deadbeef",
        mode=ScanMode.DEEP,
        findings=[report_finding],
        policy=PolicyResult(PolicyDecision.BLOCK, ["reason"]),
        metrics={"target_code_executed": False},
    )
    destination = tmp_path / "report.md"
    write_markdown(result, destination)
    report = destination.read_text()
    assert "Policy decision:** **BLOCK" in report
    assert "[secret value redacted]" in report
    assert "Target Code Executed:** False" in report
    assert "Related evidence locations" in report
    assert "routes/admin.js:8-11" in report
