from __future__ import annotations

from dataclasses import replace

from plaidnox_sast.models import Depth, ModelTier, RouteDecision
from plaidnox_scm.baseline import classify_against_baseline, prior_findings_from_stored
from plaidnox_scm.dedupe import consolidate_verified, same_issue, signature
from plaidnox_scm.diffing import ChangedFile, Diff
from plaidnox_scm.evidence import build_review_evidence
from plaidnox_scm.context_broker import CandidateContextExpansion
from plaidnox_scm.l1_review import ChangedLines, L1Candidate
from plaidnox_scm.trace import VulnerableSnippet
from plaidnox_scm.verification import CandidateVerification

ROUTE = RouteDecision(depth=Depth.DEEP, reason="test", model_tier=ModelTier.DEEP)
FIX = "Cap concurrent bundle clones per tenant and reject duplicate work."


def _candidate(identifier: str, line: int) -> L1Candidate:
    return L1Candidate(
        candidate_id=identifier, changed_path="src/broker.py", changed_symbol="materialize",
        changed_lines=ChangedLines(line, line), behavior_before="bounded", behavior_after="unbounded",
        security_role="worker isolation", suspected_broken_invariant="bounded work per request",
        provisional_attacker_capability="exhaust workers", context_facts_used=(), context_gaps=(),
        requested_expansion=(),
    )


def _verified(identifier: str, *, title: str = "Bundle clones exhaust workers", severity: str = "medium",
              cwe: str = "CWE-400", code: str = "git clone bundle") -> CandidateVerification:
    return CandidateVerification(
        candidate_id=identifier, state="verified", confidence=0.9, title=title,
        vulnerability_class="resource exhaustion", severity=severity, message="m", business_impact="i",
        remediation=FIX, reasoning="r", attack_path="a", security_invariant="bounded clone work per request",
        gained_capability=f"model wording {identifier}", rejection_reason="", evidence_locations=(),
        classification_references=({"namespace": "CWE", "identifier": cwe},), evidence_gaps=(), route=ROUTE,
        vulnerable_snippet=VulnerableSnippet("src/broker.py", 10, 10, code),
    )


def _diff() -> Diff:
    return Diff("base", "head", (ChangedFile(path="src/broker.py", status="modified", old_path=None, hunks=()),))


def test_verified_duplicate_merges_and_strongest_wins() -> None:
    candidates = (_candidate("one", 10), _candidate("two", 11))
    reviews = (_verified("one"), _verified("two", title="Worker exhaustion by repeated bundle clones", severity="high"))
    result = consolidate_verified(candidates, reviews)
    assert [item.candidate_id for item in result.verifications] == ["two"]
    assert result.merged_into == {"one": "two"}


def test_different_cwe_and_distinct_source_stay_separate() -> None:
    candidates = (_candidate("ssrf", 10), _candidate("dos", 10))
    reviews = (_verified("ssrf", cwe="CWE-918", code="fetch url"), _verified("dos"))
    assert len(consolidate_verified(candidates, reviews).verifications) == 2
    left = signature(path="a.py", symbol="handler", start_line=10, end_line=10,
                     title="SQL injection at query one", vulnerability_class="SQL injection", root_code="execute(a)")
    right = replace(left, root_hash="other-source")
    assert not same_issue(replace(left, start=100, end=100), right)


def test_same_cwe_at_one_line_with_different_security_invariants_stays_separate() -> None:
    candidates = (_candidate("disk", 10), _candidate("cpu", 10))
    disk = _verified("disk")
    cpu = replace(_verified("cpu"), security_invariant="limit CPU time for each clone")
    result = consolidate_verified(candidates, (disk, cpu))
    assert len(result.verifications) == 2
    classifications = classify_against_baseline(
        "repo", _diff(), candidates, result.verifications, (), (), coverage_complete=True
    )
    assert len({item.finding_fingerprint for item in classifications}) == 2


def test_same_bug_on_later_commit_reuses_id_only_with_unchanged_evidence() -> None:
    candidate = _candidate("first", 10)
    first = classify_against_baseline("repo", _diff(), (candidate,), (_verified("first"),), (), (), coverage_complete=True)[0]
    stored = [{
        "finding_id": first.finding_fingerprint, "root_cause_fingerprint": first.root_cause_fingerprint,
        "root_cause_path": "src/broker.py", "root_cause_symbol": "materialize",
        "root_cause_start_line": 10, "root_cause_end_line": 10,
        "title": "Bundle clones exhaust workers", "category": "resource exhaustion",
        "remediation": FIX, "security_invariant": "bounded clone work per request",
        "classification_references": [{"namespace": "CWE", "identifier": "CWE-400"}],
        "vulnerable_snippet": {"code": "git clone bundle"},
    }]
    next_candidate = _candidate("next", 11)
    unchanged = classify_against_baseline(
        "repo", _diff(), (next_candidate,), (_verified("next", title="Worker exhaustion by bundle clones"),),
        (), (), coverage_complete=True, prior_findings=prior_findings_from_stored(stored),
    )[0]
    changed = classify_against_baseline(
        "repo", _diff(), (next_candidate,), (_verified("next", code="git clone another_bundle"),),
        (), (), coverage_complete=True, prior_findings=prior_findings_from_stored(stored),
    )[0]
    assert unchanged.finding_fingerprint == first.finding_fingerprint
    assert changed.finding_fingerprint != first.finding_fingerprint


def test_legacy_finding_without_source_does_not_inherit_closed_triage() -> None:
    old = [{"finding_id": "old-fp", "root_cause_fingerprint": "old-root", "root_cause_path": "src/broker.py",
            "root_cause_symbol": "materialize", "root_cause_start_line": 10,
            "title": "Bundle clones exhaust workers", "category": "resource exhaustion", "remediation": FIX}]
    current = classify_against_baseline(
        "repo", _diff(), (_candidate("new", 10),), (_verified("new"),), (), (),
        coverage_complete=True, prior_findings=prior_findings_from_stored(old),
    )[0]
    assert current.finding_fingerprint != "old-fp"


def test_deep_hunt_location_summary_is_kept_for_trace_steps() -> None:
    evidence = build_review_evidence(
        _candidate("c", 10), CandidateContextExpansion("c", ()),
        [{"path": "src/broker.py", "start_line": 10, "end_line": 10,
          "role": "effect", "summary": "The clone consumes a worker slot."}],
    )
    assert evidence[-1].summary == "The clone consumes a worker slot."
