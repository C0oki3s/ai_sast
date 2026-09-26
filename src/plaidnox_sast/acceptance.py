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
    comparison_findings_preserved: int
    comparison_findings_lost: int
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
        "comparison_preserved": 0,
        "comparison_lost": 0,
    }
    case_results: list[dict[str, Any]] = []
    engineering_failures: list[str] = []
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
        incomplete = (
            bool(metrics.get("ai_scan_incomplete"))
            or str(report.get("scan_status", "")).upper() == "UNSUCCESSFUL"
            or str(
            (report.get("policy") or {}).get("decision", "")
            ).lower() == "incomplete"
        )
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
        case_metric_failures = _discovery_metric_failures(
            str(case["case_id"]),
            metrics,
            manifest["thresholds"],
        )
        engineering_failures.extend(case_metric_failures)
        comparison = _compare_prior_findings(base, case, findings)
        if comparison is not None:
            totals["comparison_preserved"] += comparison["preserved"]
            totals["comparison_lost"] += len(comparison["lost_fingerprints"])
            if comparison["lost_fingerprints"]:
                engineering_failures.append(
                    f"{case['case_id']}: {len(comparison['lost_fingerprints'])} prior finding(s) were not preserved"
                )
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
                "discovery_metric_failures": case_metric_failures,
                "prior_findings_comparison": comparison,
            }
        )

    recall = _ratio(totals["tp"], totals["tp"] + totals["fn"], empty=1.0)
    precision = _ratio(totals["tp"], totals["tp"] + totals["fp"], empty=1.0)
    duplicate_rate = _ratio(totals["duplicates"], totals["findings"], empty=0.0)
    thresholds = manifest["thresholds"]
    failures: list[str] = list(engineering_failures)
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
        comparison_findings_preserved=totals["comparison_preserved"],
        comparison_findings_lost=totals["comparison_lost"],
        case_results=case_results,
        failures=failures,
    )


def _compare_prior_findings(
    base: Path, case: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any] | None:
    configured = case.get("comparison_report_path")
    if not configured:
        return None
    previous = _load_json_object(_bounded_report_path(base, str(configured)))
    remaining = list(findings)
    preserved = 0
    lost: list[str] = []
    for old in previous.get("findings", []) or []:
        match = next((item for item in remaining if _equivalent_finding(old, item)), None)
        if match is None:
            lost.append(str(old.get("fingerprint", old.get("finding_id", "<missing>"))))
        else:
            remaining.remove(match)
            preserved += 1
    return {
        "baseline_report_path": str(_bounded_report_path(base, str(configured))),
        "baseline_findings": preserved + len(lost),
        "preserved": preserved,
        "lost_fingerprints": sorted(lost),
    }


def _equivalent_finding(previous: dict[str, Any], current: dict[str, Any]) -> bool:
    old_fingerprint = str(previous.get("fingerprint", previous.get("finding_id", "")))
    if old_fingerprint and old_fingerprint == str(current.get("fingerprint", current.get("finding_id", ""))):
        return True
    old_evidence = previous.get("evidence") if isinstance(previous.get("evidence"), dict) else {}
    new_evidence = current.get("evidence") if isinstance(current.get("evidence"), dict) else {}
    if not old_evidence or not new_evidence:
        return False
    if str(old_evidence.get("path", "")) != str(new_evidence.get("path", "")):
        return False
    if str(previous.get("vulnerability_class", "")).casefold() != str(current.get("vulnerability_class", "")).casefold():
        return False
    old_start = int(old_evidence.get("start_line", 0) or 0)
    old_end = int(old_evidence.get("end_line", old_start) or old_start)
    new_start = int(new_evidence.get("start_line", 0) or 0)
    new_end = int(new_evidence.get("end_line", new_start) or new_start)
    return bool(old_start and new_start and old_start <= new_end and new_start <= old_end)


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
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    packet = metadata.get("evidence_packet") if isinstance(metadata.get("evidence_packet"), dict) else {}
    deep_hunt = metadata.get("deep_hunt") if isinstance(metadata.get("deep_hunt"), dict) else {}
    semantic_expectations = (
        ("root_cause_contains", json.dumps(packet.get("root_cause", {}), sort_keys=True)),
        ("invariant_contains", str(packet.get("invariant") or deep_hunt.get("security_invariant", ""))),
        (
            "capability_contains",
            " ".join(str(item) for item in packet.get("gained_capabilities", []))
            or str(deep_hunt.get("gained_capability", "")),
        ),
    )
    for field, actual in semantic_expectations:
        expected = str(expectation.get(field, "")).strip().casefold()
        if expected and expected not in actual.casefold():
            return False
    expected_start = expectation.get("start_line")
    expected_end = expectation.get("end_line", expected_start)
    if expected_start is None:
        return True
    actual_start = int(evidence.get("start_line", 0) or 0)
    actual_end = int(evidence.get("end_line", actual_start) or actual_start)
    return actual_start <= int(expected_end) and actual_end >= int(expected_start)


def _discovery_metric_failures(
    case_id: str,
    metrics: dict[str, Any],
    thresholds: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    checks = (
        ("maximum_discovery_calls", "discovery_model_calls", "discovery calls"),
        ("maximum_calls_per_region", "discovery_model_calls_per_unique_region", "calls per region"),
        ("maximum_continuations", "continuations_executed", "executed continuations"),
        ("maximum_raw_candidates", "candidates_raw", "raw candidates"),
        ("maximum_discovery_failures", "ai_discovery_failures", "discovery failures"),
        ("maximum_rate_limit_waits", "rate_limit_waits", "rate-limit waits"),
    )
    for threshold_name, metric_name, label in checks:
        if threshold_name not in thresholds:
            continue
        actual = float(metrics.get(metric_name, 0) or 0)
        maximum = float(thresholds[threshold_name])
        if actual > maximum:
            failures.append(f"{case_id}: {label} {actual:g} exceeds {maximum:g}")
    if "maximum_candidate_duplicate_ratio" in thresholds:
        raw = int(metrics.get("candidates_raw", 0) or 0)
        unique = int(metrics.get("candidates_semantic_unique", 0) or 0)
        duplicate_ratio = _ratio(max(0, raw - unique), raw, empty=0.0)
        maximum = float(thresholds["maximum_candidate_duplicate_ratio"])
        if duplicate_ratio > maximum:
            failures.append(
                f"{case_id}: candidate duplicate ratio {duplicate_ratio:.4f} exceeds {maximum:.4f}"
            )
    return failures


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
