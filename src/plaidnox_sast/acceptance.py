"""Repeatable acceptance evaluation over immutable Code Scanning reports."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .assets import load_json


class AcceptanceConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AcceptanceResult:
    passed: bool
    true_positives: int
    false_positives: int
    false_negatives: int
    duplicates: int
    recall: float
    precision: float
    duplicate_rate: float
    incomplete_scans: int
    prompt_cache_input_tokens: int
    prompt_cache_cached_tokens: int
    model_input_tokens: int
    model_output_tokens: int
    model_cost_usd: float
    case_results: list[dict[str, Any]]
    failures: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_acceptance_manifest(path: Path) -> AcceptanceResult:
    manifest = _load_json_object(path)
    errors = sorted(
        Draft202012Validator(load_json("schemas/acceptance_manifest.json")).iter_errors(manifest),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        details = "; ".join(error.message for error in errors[:5])
        raise AcceptanceConfigurationError(f"acceptance manifest is invalid: {details}")

    totals = {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "duplicates": 0,
        "findings": 0,
        "incomplete": 0,
        "cache_input": 0,
        "cache_hit": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cost": 0.0,
    }
    case_results: list[dict[str, Any]] = []
    base = path.resolve().parent
    for case in manifest["cases"]:
        report_path = _bounded_report_path(base, str(case["report_path"]))
        report = _load_json_object(report_path)
        findings = list(report.get("findings") or [])
        expected = list(case["expected_findings"])
        matches, unmatched_expected, unmatched_findings = _match_findings(expected, findings)
        fingerprints = [str(item.get("fingerprint", "")) for item in findings if item.get("fingerprint")]
        duplicates = len(fingerprints) - len(set(fingerprints))
        metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
        incomplete = bool(metrics.get("ai_scan_incomplete")) or str(
            (report.get("policy") or {}).get("decision", "")
        ).lower() == "incomplete"
        totals["tp"] += len(matches)
        totals["fp"] += len(unmatched_findings)
        totals["fn"] += len(unmatched_expected)
        totals["duplicates"] += duplicates
        totals["findings"] += len(findings)
        totals["incomplete"] += int(incomplete)
        totals["cache_input"] += int(metrics.get("prompt_cache_input_tokens", 0) or 0)
        totals["cache_hit"] += int(metrics.get("prompt_cache_cached_tokens", 0) or 0)
        totals["input_tokens"] += int(metrics.get("model_budget_input_tokens", 0) or 0)
        totals["output_tokens"] += int(metrics.get("model_budget_output_tokens", 0) or 0)
        totals["cost"] += float(metrics.get("model_budget_cost_usd", 0.0) or 0.0)
        case_results.append(
            {
                "case_id": str(case["case_id"]),
                "report_path": str(report_path),
                "true_positives": len(matches),
                "false_positives": len(unmatched_findings),
                "false_negatives": len(unmatched_expected),
                "duplicates": duplicates,
                "incomplete": incomplete,
                "matched_expectations": sorted(matches),
                "missed_expectations": sorted(unmatched_expected),
                "unexpected_fingerprints": sorted(
                    str(item.get("fingerprint", "<missing>")) for item in unmatched_findings
                ),
            }
        )

    recall = _ratio(totals["tp"], totals["tp"] + totals["fn"], empty=1.0)
    precision = _ratio(totals["tp"], totals["tp"] + totals["fp"], empty=1.0)
    duplicate_rate = _ratio(totals["duplicates"], totals["findings"], empty=0.0)
    thresholds = manifest["thresholds"]
    failures: list[str] = []
    if recall < float(thresholds["minimum_recall"]):
        failures.append(f"recall {recall:.4f} is below {float(thresholds['minimum_recall']):.4f}")
    if precision < float(thresholds["minimum_precision"]):
        failures.append(f"precision {precision:.4f} is below {float(thresholds['minimum_precision']):.4f}")
    if duplicate_rate > float(thresholds["maximum_duplicate_rate"]):
        failures.append(
            f"duplicate rate {duplicate_rate:.4f} exceeds {float(thresholds['maximum_duplicate_rate']):.4f}"
        )
    if bool(thresholds["require_complete_scans"]) and totals["incomplete"]:
        failures.append(f"{totals['incomplete']} acceptance scan(s) were incomplete")
    return AcceptanceResult(
        passed=not failures,
        true_positives=totals["tp"],
        false_positives=totals["fp"],
        false_negatives=totals["fn"],
        duplicates=totals["duplicates"],
        recall=round(recall, 4),
        precision=round(precision, 4),
        duplicate_rate=round(duplicate_rate, 4),
        incomplete_scans=totals["incomplete"],
        prompt_cache_input_tokens=totals["cache_input"],
        prompt_cache_cached_tokens=totals["cache_hit"],
        model_input_tokens=totals["input_tokens"],
        model_output_tokens=totals["output_tokens"],
        model_cost_usd=round(totals["cost"], 8),
        case_results=case_results,
        failures=failures,
    )


def write_acceptance_result(result: AcceptanceResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _match_findings(
    expected: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> tuple[set[str], set[str], list[dict[str, Any]]]:
    remaining = list(range(len(findings)))
    matched: set[str] = set()
    missed: set[str] = set()
    for expectation in expected:
        match = next((index for index in remaining if _matches(expectation, findings[index])), None)
        expectation_id = str(expectation["expectation_id"])
        if match is None:
            missed.add(expectation_id)
            continue
        remaining.remove(match)
        matched.add(expectation_id)
    return matched, missed, [findings[index] for index in remaining]


def _matches(expectation: dict[str, Any], finding: dict[str, Any]) -> bool:
    evidence = finding.get("evidence") or {}
    if str(evidence.get("path", "")) != str(expectation["path"]):
        return False
    vulnerability_class = str(expectation.get("vulnerability_class", "")).strip().lower()
    if vulnerability_class and str(finding.get("vulnerability_class", "")).strip().lower() != vulnerability_class:
        return False
    expected_start = expectation.get("start_line")
    expected_end = expectation.get("end_line", expected_start)
    if expected_start is None:
        return True
    actual_start = int(evidence.get("start_line", 0) or 0)
    actual_end = int(evidence.get("end_line", actual_start) or actual_start)
    return actual_start <= int(expected_end) and actual_end >= int(expected_start)


def _bounded_report_path(base: Path, configured: str) -> Path:
    path = (base / configured).resolve()
    if path != base and base not in path.parents:
        raise AcceptanceConfigurationError("acceptance report path escapes the manifest directory")
    return path


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceptanceConfigurationError(f"unable to load JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise AcceptanceConfigurationError(f"JSON document must be an object: {path}")
    return value


def _ratio(numerator: int, denominator: int, *, empty: float) -> float:
    return numerator / denominator if denominator else empty
