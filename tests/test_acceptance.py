import json

import pytest

from plaidnox_sast.acceptance import AcceptanceConfigurationError, evaluate_acceptance_manifest


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def _report(findings, *, incomplete=False, discovery_metrics=None):
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
            **(discovery_metrics or {}),
        },
    }


def _finding(fingerprint="finding-1", path="app.py", vulnerability_class="CWE-639"):
    return {
        "fingerprint": fingerprint,
        "vulnerability_class": vulnerability_class,
        "evidence": {"path": path, "start_line": 10, "end_line": 12},
        "metadata": {
            "evidence_packet": {
                "root_cause": {"symbol": "authCheck", "security_control": "identity integrity"},
                "invariant": "Verified identity cannot be overwritten.",
                "gained_capabilities": ["Select another user's identity-bound resources."],
            }
        },
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


def test_acceptance_evaluator_fails_when_graphify_run_loses_a_prior_finding(tmp_path) -> None:
    _write(tmp_path / "report.json", _report([_finding("new-fingerprint", path="other.py")]))
    _write(tmp_path / "baseline.json", _report([_finding("baseline-fingerprint")]))
    manifest = _manifest()
    manifest["cases"][0]["comparison_report_path"] = "baseline.json"
    _write(tmp_path / "manifest.json", manifest)

    result = evaluate_acceptance_manifest(tmp_path / "manifest.json")

    assert not result.passed
    assert result.comparison_findings_preserved == 0
    assert result.comparison_findings_lost == 1
    assert any("prior finding" in failure for failure in result.failures)


def test_acceptance_evaluator_preserves_findings_by_grounded_location_when_fingerprint_changes(tmp_path) -> None:
    current = _finding("new-fingerprint")
    _write(tmp_path / "report.json", _report([current]))
    _write(tmp_path / "baseline.json", _report([_finding("baseline-fingerprint")]))
    manifest = _manifest()
    manifest["cases"][0]["comparison_report_path"] = "baseline.json"
    _write(tmp_path / "manifest.json", manifest)

    result = evaluate_acceptance_manifest(tmp_path / "manifest.json")

    assert result.passed
    assert result.comparison_findings_preserved == 1
    assert result.comparison_findings_lost == 0


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


def test_acceptance_evaluator_enforces_scan20_discovery_and_semantic_gates(tmp_path) -> None:
    report = _report(
        [_finding()],
        discovery_metrics={
            "discovery_model_calls": 41,
            "discovery_model_calls_per_unique_region": 1.6,
            "continuations_executed": 16,
            "candidates_raw": 20,
            "candidates_semantic_unique": 10,
            "ai_discovery_failures": 0,
            "rate_limit_waits": 0,
        },
    )
    manifest = _manifest()
    expectation = manifest["cases"][0]["expected_findings"][0]
    expectation.update(
        {
            "root_cause_contains": "authCheck",
            "invariant_contains": "cannot be overwritten",
            "capability_contains": "identity-bound resources",
        }
    )
    manifest["thresholds"].update(
        {
            "maximum_discovery_calls": 40,
            "maximum_calls_per_region": 1.5,
            "maximum_continuations": 15,
            "maximum_raw_candidates": 40,
            "maximum_candidate_duplicate_ratio": 0.4,
            "maximum_discovery_failures": 0,
            "maximum_rate_limit_waits": 0,
        }
    )
    _write(tmp_path / "report.json", report)
    _write(tmp_path / "manifest.json", manifest)

    result = evaluate_acceptance_manifest(tmp_path / "manifest.json")

    assert result.true_positives == 1
    assert not result.passed
    assert any("discovery calls" in item for item in result.failures)
    assert any("calls per region" in item for item in result.failures)
    assert any("candidate duplicate ratio" in item for item in result.failures)
