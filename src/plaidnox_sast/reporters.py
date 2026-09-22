from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult, Severity

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def write_json(result: ScanResult, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")


def write_repository_context(result: ScanResult, destination: Path) -> None:
    """Persist first-scan architecture context separately for workflow reuse."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result.repository_context, indent=2) + "\n", encoding="utf-8")


def to_sarif(result: ScanResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    entries: list[dict[str, Any]] = []
    for finding in result.findings:
        classifications = _classification_references(finding)
        classification_tags = [
            str(reference["identifier"])
            for reference in classifications
            if reference.get("identifier")
        ]
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title.replace(" ", ""),
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
                "properties": {
                    "tags": list(dict.fromkeys([finding.vulnerability_class, *classification_tags, "security"])),
                    "classifications": classifications,
                },
            },
        )
        region: dict[str, Any] = {
            "startLine": finding.evidence.start_line,
            "endLine": finding.evidence.end_line,
        }
        if finding.evidence.snippet:
            region["snippet"] = {"text": finding.evidence.snippet}
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.evidence.path},
                    "region": region,
                }
            }
        ]
        for alternative in _alternative_evidence(finding):
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": alternative["path"]},
                        "region": {
                            "startLine": alternative["start_line"],
                            "endLine": alternative["end_line"],
                        },
                    }
                }
            )
        entries.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": finding.message},
                "locations": locations,
                "partialFingerprints": {"plaidnoxFingerprint": finding.fingerprint},
                "properties": {
                    "confidence": finding.confidence,
                    "priorityScore": finding.priority_score,
                    "validator": finding.validator,
                    "contextProfile": finding.metadata.get("context_profile"),
                    "jevModelTier": finding.metadata.get("jev_model_tier"),
                    "jevNeedsDeepHunt": finding.metadata.get("jev_needs_deep_hunt"),
                    "classifications": classifications,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PlaidNox SAST Agent",
                        "semanticVersion": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": f"{result.codebase}/{result.revision}"},
                "results": entries,
            }
        ],
    }


def write_sarif(result: ScanResult, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(to_sarif(result), indent=2) + "\n", encoding="utf-8")


def write_markdown(result: ScanResult, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    counts = {severity.value: 0 for severity in Severity}
    for finding in result.findings:
        counts[finding.severity.value] += 1
    lines = [
        "# PlaidNox source code security assessment",
        "",
        f"**Codebase:** `{result.codebase}`  ",
        f"**Revision:** `{result.revision}`  ",
        f"**Mode:** {result.mode.value}  ",
        f"**Policy decision:** **{result.policy.decision.value.upper()}**  ",
        "**Execution:** Static analysis only; target code and dependencies were not executed.",
        "",
        "## Summary",
        "",
        f"Validated findings: **{len(result.findings)}** — "
        f"{counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low.",
        "",
    ]
    if result.repository_context.get("architecture"):
        lines.extend(
            [
                "## Repository context",
                "",
                _markdown_text(str(result.repository_context["architecture"])),
                "",
            ]
        )
    source_tree = result.repository_context.get("source_tree")
    if isinstance(source_tree, list) and source_tree:
        lines.extend(
            [
                "## Readable source tree",
                "",
                "```text",
                *[str(path) for path in source_tree[:200]],
                "```",
                "",
            ]
        )
    lines.extend(
        [
            "## Validated findings",
            "",
            "| Priority | Severity | Finding | Evidence |",
            "|---:|---|---|---|",
        ]
    )
    for finding in result.findings:
        location = f"`{finding.evidence.path}:{finding.evidence.start_line}`"
        alternative_count = len(_alternative_evidence(finding))
        if alternative_count:
            location += f" (+{alternative_count})"
        lines.append(
            f"| {finding.priority_score} | {finding.severity.value.upper()} | "
            f"{_markdown_text(finding.title)} | {location} |"
        )
    for index, finding in enumerate(result.findings, 1):
        lines.extend(
            [
                "",
                f"## {index}. {_markdown_text(finding.title)}",
                "",
                f"**Severity:** {finding.severity.value.upper()}  ",
                f"**Confidence:** {finding.confidence:.0%}  ",
                f"**Classification:** {_markdown_text(finding.vulnerability_class)}  ",
                f"**Location:** `{finding.evidence.path}:{finding.evidence.start_line}`  ",
                f"**Fingerprint:** `{finding.fingerprint}`  ",
                f"**Validation:** {finding.validator}",
                "",
                _markdown_text(finding.message),
                "",
                f"**Impact.** {_markdown_text(finding.impact)}",
                "",
                f"**Remediation.** {_markdown_text(finding.remediation)}",
                "",
                "**Evidence path**",
                "",
                " -> ".join(f"`{_markdown_text(node)}`" for node in finding.evidence.graph_path),
            ]
        )
        if finding.evidence.snippet:
            lines.extend(["", "**Code evidence**", "", "    " + finding.evidence.snippet.replace("\n", "\n    ")])
        alternatives = _alternative_evidence(finding)
        if alternatives:
            lines.extend(["", "**Related evidence locations**", ""])
            lines.extend(
                f"- `{item['path']}:{item['start_line']}-{item['end_line']}`"
                for item in alternatives
            )
        classifications = _classification_references(finding)
        if classifications:
            lines.extend(["", "**Classification references**", ""])
            lines.extend(
                f"- {_markdown_text(str(item.get('namespace', '')))}: "
                f"{_markdown_text(str(item.get('identifier', '')))}"
                + (
                    f" — {_markdown_text(str(item.get('name', '')))}"
                    if item.get("name")
                    else ""
                )
                for item in classifications
            )
    lines.extend(
        [
            "",
            "## Scan metrics",
            "",
            *[f"- **{key.replace('_', ' ').title()}:** {value}" for key, value in result.metrics.items()],
            "",
        ]
    )
    destination.write_text("\n".join(lines), encoding="utf-8")


def _markdown_text(value: str) -> str:
    return value.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def _alternative_evidence(finding: Finding) -> list[dict[str, Any]]:
    consolidation = finding.metadata.get("consolidation", {})
    values = consolidation.get("alternative_evidence", [])
    if not isinstance(values, list):
        return []
    return [
        {
            "path": str(item["path"]),
            "start_line": int(item["start_line"]),
            "end_line": int(item["end_line"]),
        }
        for item in values
        if isinstance(item, dict)
        and {"path", "start_line", "end_line"}.issubset(item)
    ]


def _classification_references(finding: Finding) -> list[dict[str, str]]:
    values = finding.metadata.get("classification_references", [])
    if not isinstance(values, list):
        return []
    return [
        {
            "namespace": str(item.get("namespace", "")),
            "identifier": str(item.get("identifier", "")),
            "name": str(item.get("name", "")),
            "source_url": str(item.get("source_url", "")),
        }
        for item in values
        if isinstance(item, dict) and item.get("identifier")
    ]
