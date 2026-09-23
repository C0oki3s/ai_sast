from __future__ import annotations

import json
from pathlib import Path

import pytest

from plaidnox_sast.ai import AIResponseError, DeepHuntResult, _evidence_paths, _validate_deep_hunt_result
from plaidnox_sast.models import Candidate, Evidence, Severity


def _candidate() -> Candidate:
    return Candidate(
        rule_id="r",
        title="t",
        vulnerability_class="idor",
        severity=list(Severity)[0],
        confidence=0.5,
        message="m",
        evidence=Evidence(path="middleware/auth.js", start_line=1, end_line=2),
    )


def _rejected(*locations: dict) -> DeepHuntResult:
    gates = [
        {"gate": gate, "verdict": "fail"}
        for gate in (
            "design_invariant", "reachability", "attacker_control", "effective_defense",
            "new_capability", "falsification", "reproduction", "remediation_invariant",
        )
    ]
    return DeepHuntResult(
        supported=False, confidence=0.4, reasoning="", attack_path="", remediation_note="",
        rejection_reason="no", gate_results=gates, evidence_locations=list(locations),
    )


def test_cross_file_evidence_shown_to_the_verifier_is_accepted(tmp_path: Path) -> None:
    (tmp_path / "middleware").mkdir()
    (tmp_path / "middleware" / "auth.js").write_text("a\nb\n")
    (tmp_path / "app.js").write_text("x\n" * 10)
    shown = json.dumps({"candidate_context_expansion": {"evidence": [{"records": [{"path": "app.js"}]}]}})
    paths = _evidence_paths(_candidate(), [], shown)

    _validate_deep_hunt_result(
        tmp_path, _candidate(), _rejected({"path": "app.js", "start_line": 3, "end_line": 4}), evidence_paths=paths
    )

    with pytest.raises(AIResponseError, match="outside the supplied evidence"):
        _validate_deep_hunt_result(
            tmp_path, _candidate(), _rejected({"path": "other.js", "start_line": 1, "end_line": 1}), evidence_paths=paths
        )
    with pytest.raises(AIResponseError, match="invalid evidence line range"):
        _validate_deep_hunt_result(
            tmp_path, _candidate(), _rejected({"path": "app.js", "start_line": 1, "end_line": 99}), evidence_paths=paths
        )
