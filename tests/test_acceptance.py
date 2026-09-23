import json

import pytest

from plaidnox_sast.acceptance import AcceptanceConfigurationError, evaluate_acceptance_manifest


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def _report(findings, *, incomplete=False):
    return {
        "codebase": "fixture/service",
        "revision": "revision-1",
        "findings": findings,
        "policy": {"decision": "incomplete" if incomplete else "block", "reasons": []},
        "metrics": {
            "ai_scan_incomplete": incomplete,
            "prompt_cache_input_tokens": 100,
            "prompt_cache_cached_tokens": 75,
            "model_budget_input_tokens": 40,
            "model_budget_output_tokens": 10,
            "model_budget_cost_usd": 0.25,
        },
    }


def _finding(fingerprint="finding-1", path="app.py", vulnerability_class="CWE-639"):
    return {
        "fingerprint": fingerprint,
        "vulnerability_class": vulnerability_class,
        "evidence": {"path": path, "start_line": 10, "end_line": 12},
    }


def _manifest(report_path="report.json", *, recall=1.0, precision=1.0):
    return {
        "version": 1,
        "cases": [
            {
                "case_id": "authorization-positive",
                "report_path": report_path,
                "expected_findings": [
                    {
                        "expectation_id": "idor",
                        "path": "app.py",
                        "vulnerability_class": "CWE-639",
                        "start_line": 9,
                        "end_line": 14,
                    }
                ],
            }
        ],
        "thresholds": {
            "minimum_recall": recall,
            "minimum_precision": precision,
            "maximum_duplicate_rate": 0.0,
            "require_complete_scans": True,
        },
    }


def test_acceptance_evaluator_matches_expected_findings_and_aggregates_cost(tmp_path) -> None:
    _write(tmp_path / "report.json", _report([_finding()]))
    _write(tmp_path / "manifest.json", _manifest())

    result = evaluate_acceptance_manifest(tmp_path / "manifest.json")

    assert result.passed
    assert result.true_positives == 1
    assert result.recall == 1.0
    assert result.precision == 1.0
    assert result.prompt_cache_cached_tokens == 75
    assert result.model_cost_usd == 0.25


def test_acceptance_evaluator_fails_incomplete_and_unexpected_findings(tmp_path) -> None:
    _write(tmp_path / "report.json", _report([_finding(), _finding("unexpected", "other.py")], incomplete=True))
    _write(tmp_path / "manifest.json", _manifest(precision=0.75))

    result = evaluate_acceptance_manifest(tmp_path / "manifest.json")

    assert not result.passed
    assert result.false_positives == 1
    assert result.incomplete_scans == 1
    assert any("precision" in item for item in result.failures)
    assert any("incomplete" in item for item in result.failures)


def test_acceptance_manifest_rejects_report_path_escape(tmp_path) -> None:
    _write(tmp_path / "manifest.json", _manifest("../outside.json"))

    with pytest.raises(AcceptanceConfigurationError, match="escapes"):
        evaluate_acceptance_manifest(tmp_path / "manifest.json")


def test_acceptance_manifest_is_schema_validated(tmp_path) -> None:
    _write(tmp_path / "manifest.json", {"version": 1, "cases": []})

    with pytest.raises(AcceptanceConfigurationError, match="invalid"):
        evaluate_acceptance_manifest(tmp_path / "manifest.json")
