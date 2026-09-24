from plaidnox_sast.config import PolicyConfig
from plaidnox_sast.models import (
    Evidence,
    Finding,
    FindingState,
    PolicyDecision,
    PolicyResult,
    ScanMode,
    ScanResult,
    ScanStatus,
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
    assert "Scan status:** **SUCCESSFUL" in report
    assert "Verified findings: **1**" in report
    assert "Policy decision" not in report
    assert "[secret value redacted]" in report
    assert "Target Code Executed:** False" in report
    assert "Related evidence locations" in report
    assert "routes/admin.js:8-11" in report


def test_scan_status_is_independent_of_findings_and_policy():
    result = ScanResult(
        codebase="org/repo",
        revision="deadbeef",
        mode=ScanMode.DEEP,
        findings=[finding()],
        policy=PolicyResult(PolicyDecision.BLOCK, ["merge policy reason"]),
        metrics={"ai_scan_incomplete": False},
    )

    assert result.scan_status is ScanStatus.SUCCESSFUL
    serialized = result.to_dict()
    assert serialized["scan_status"] == "SUCCESSFUL"
    assert serialized["findings_summary"] == {
        "total": 1,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert "policy" not in serialized


def test_required_failed_work_makes_scan_unsuccessful():
    result = ScanResult(
        codebase="org/repo",
        revision="deadbeef",
        mode=ScanMode.DEEP,
        findings=[finding()],
        policy=PolicyResult(PolicyDecision.BLOCK, ["merge policy reason"]),
        metrics={"ai_review_failures": 1},
    )

    assert result.scan_status is ScanStatus.UNSUCCESSFUL


def test_reconciled_supporting_obligations_do_not_fail_scan_health():
    result = ScanResult(
        codebase="org/repo",
        revision="deadbeef",
        mode=ScanMode.DEEP,
        findings=[],
        policy=PolicyResult(PolicyDecision.PASS, []),
        metrics={
            "ai_scan_incomplete": False,
            "ai_discovery_unresolved_obligations": 27,
            "ai_required_coverage_unresolved": 0,
        },
    )

    assert result.scan_status is ScanStatus.SUCCESSFUL


def test_unresolved_required_canonical_coverage_fails_scan_health():
    result = ScanResult(
        codebase="org/repo",
        revision="deadbeef",
        mode=ScanMode.DEEP,
        findings=[],
        policy=PolicyResult(PolicyDecision.PASS, []),
        metrics={
            "ai_scan_incomplete": False,
            "ai_discovery_unresolved_obligations": 1,
            "ai_required_coverage_unresolved": 1,
        },
    )

    assert result.scan_status is ScanStatus.UNSUCCESSFUL
