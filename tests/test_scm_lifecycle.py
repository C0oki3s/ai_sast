"""Finding lifecycle across runs and pull requests (the scenarios users asked about)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from test_scm_review import _ContextBuilder, _factory, _git, _init_repo

from plaidnox_sast.models import Depth, ModelTier, RouteDecision
from plaidnox_scm import occurrences, triage
from plaidnox_scm.diffing import DiffHunk
from plaidnox_scm.l1_review import ChangedLines, L1ReviewBatch
from plaidnox_scm.lifecycle import RECHECK_PREFIX, KnownFinding, map_lines
from plaidnox_scm.review import review_pull_request
from plaidnox_scm.verification import CandidateVerification

ROUTE = RouteDecision(depth=Depth.DEEP, reason="test", model_tier=ModelTier.DEEP)
CODEBASE = "github:repository:1"
TENANT = "tenant-a"


class _NoNewCandidates:
    """L1 proposes nothing new, the usual LLM non-determinism case."""

    def review(self, repo_path, diff, relevance, application_context):
        return L1ReviewBatch((), tuple(file.path for file in diff.files), True, (), 1)


class _Rechecker:
    """Answers a re-check per finding id: verified / rejected / unresolved."""

    def __init__(self, answers: dict[str, str]):
        self.answers = answers
        self.asked: list[str] = []

    def verify(self, repo_path, head_revision, repository_name, application_context, candidates, minimum_depth):
        results = []
        for candidate in candidates:
            finding_id = candidate.candidate_id.removeprefix(RECHECK_PREFIX)
            self.asked.append(finding_id)
            state = self.answers.get(finding_id, "unresolved")
            results.append(CandidateVerification(
                candidate_id=candidate.candidate_id, state=state, confidence=0.9 if state == "verified" else 0.0,
                title=f"Still present {finding_id}" if state == "verified" else "",
                vulnerability_class="resource exhaustion" if state == "verified" else "", severity="high",
                message="m", business_impact="i", remediation="Cap concurrent clones.", reasoning="r", attack_path="a",
                security_invariant="s", gained_capability="exhaust workers",
                rejection_reason="Clone count is now capped per installation." if state == "rejected" else "",
                evidence_locations=(), classification_references=(), evidence_gaps=(), route=ROUTE,
            ))
        return tuple(results)


def _repo(tmp_path: Path, files: dict[str, str]) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "base.txt").write_text("base\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, files)
    return repo, base


def _commit(repo: Path, files: dict[str, str | None]) -> str:
    for path, content in files.items():
        target = repo / path
        if content is None:
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "change")
    return _git(repo, "rev-parse", "HEAD")


CODE = "".join(f"line {n}\n" for n in range(1, 41))


def _known(finding_id: str, path: str, head: str, *, line: int = 10, scope: str = "pr") -> KnownFinding:
    return KnownFinding(scope, {  # type: ignore[arg-type]
        "finding_id": finding_id, "root_cause_fingerprint": f"root-{finding_id}", "root_cause_path": path,
        "root_cause_symbol": "handler", "root_cause_start_line": line, "root_cause_end_line": line + 1,
        "title": f"Finding {finding_id}", "severity": "high", "confidence": 0.95, "category": "resource exhaustion",
        "description": "d", "root_cause_changed_in_pr": True, "baseline_relationship": "introduced",
        "tenant_id": TENANT, "repository_id": 1, "base_revision": "a" * 40, "head_revision": head,
        "verified_at": datetime(2026, 10, 7, tzinfo=UTC).isoformat(),
    }, head)


def _run(repo: Path, base: str, head: str, known, answers: dict[str, str], factory=None):
    verifier = _Rechecker(answers)
    result = review_pull_request(
        repo, base, head, CODEBASE, TENANT, factory or _factory(),
        context_builder=_ContextBuilder(), l1_reviewer=_NoNewCandidates(), candidate_verifier=verifier,
        known_findings=tuple(known),
    )
    return result, {item.finding_id: item.outcome for item in result.known_outcomes}, verifier


def test_unchanged_file_keeps_the_finding_open_and_blocking_even_if_the_model_does_not_report_it(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"app.py": CODE, "other.py": "x\n"})
    first_head = _git(repo, "rev-parse", "HEAD")
    head = _commit(repo, {"other.py": "y\n"})  # second commit does not touch app.py

    result, outcomes, verifier = _run(repo, base, head, [_known("A", "app.py", first_head)], {})

    assert outcomes == {"A": "carried_unchanged"}
    assert verifier.asked == []  # identical code needs no LLM call
    assert [item.finding_fingerprint for item in result.baseline_classifications] == ["A"]
    assert result.policy.decision == "BLOCK"  # still a live, verified, blocking bug


def test_a_fix_pushed_to_the_same_pr_closes_the_finding_only_after_re_verification(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"app.py": CODE})
    first_head = _git(repo, "rev-parse", "HEAD")
    head = _commit(repo, {"app.py": CODE.replace("line 10\n", "line 10 fixed\n")})

    result, outcomes, verifier = _run(repo, base, head, [_known("A", "app.py", first_head)], {"A": "rejected"})

    assert verifier.asked == ["A"]
    assert outcomes == {"A": "fixed_verified"}
    assert result.baseline_classifications == ()
    assert result.policy.decision == "PASS"
    assert result.counters.fixed == 1


def test_three_findings_one_fixed_one_untouched_one_changed_but_still_present(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"a.py": CODE, "b.py": CODE, "c.py": CODE})
    first_head = _git(repo, "rev-parse", "HEAD")
    head = _commit(repo, {"a.py": CODE.replace("line 10\n", "fixed\n"), "c.py": CODE.replace("line 30\n", "edit\n")})
    known = [_known("A", "a.py", first_head), _known("B", "b.py", first_head), _known("C", "c.py", first_head)]

    result, outcomes, _ = _run(repo, base, head, known, {"A": "rejected", "C": "verified"})

    assert outcomes == {"A": "fixed_verified", "B": "carried_unchanged", "C": "reobserved"}
    open_ids = sorted(item.finding_fingerprint for item in result.baseline_classifications)
    assert open_ids == ["B", "C"]  # one finding each, same ids as before, no duplicates
    assert result.policy.blocking_count == 2


def test_inconclusive_re_verification_and_incomplete_runs_never_close_a_finding(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"a.py": CODE})
    first_head = _git(repo, "rev-parse", "HEAD")
    head = _commit(repo, {"a.py": CODE.replace("line 10\n", "edit\n")})

    _, outcomes, _ = _run(repo, base, head, [_known("A", "a.py", first_head)], {"A": "unresolved"})

    assert outcomes == {"A": "recheck_unresolved"}


def test_deleting_the_root_cause_file_fixes_the_finding(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"a.py": CODE, "keep.py": "x\n"})
    first_head = _git(repo, "rev-parse", "HEAD")
    head = _commit(repo, {"a.py": None})

    _, outcomes, verifier = _run(repo, base, head, [_known("A", "a.py", first_head)], {})

    assert outcomes == {"A": "fixed_removed"}
    assert verifier.asked == []


def test_force_pushed_history_falls_back_to_re_verification(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"a.py": CODE})
    head = _git(repo, "rev-parse", "HEAD")

    _, outcomes, verifier = _run(repo, base, head, [_known("A", "a.py", "f" * 40)], {"A": "verified"})

    assert verifier.asked == ["A"] and outcomes == {"A": "reobserved"}


def test_default_branch_finding_fixed_in_a_later_pr_is_resolved_for_that_pr(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"a.py": CODE})
    head = _commit(repo, {"a.py": CODE.replace("line 10\n", "fixed\n")})
    branch = _known("M", "a.py", base, scope="branch")

    result, outcomes, _ = _run(repo, base, head, [branch], {"M": "rejected"})

    assert outcomes == {"M": "fixed_verified"}
    [classification] = result.baseline_classifications
    assert (classification.finding_fingerprint, classification.relationship) == ("M", "RESOLVED")
    assert result.policy.decision == "PASS"


def test_default_branch_finding_in_an_untouched_file_is_existing_debt_not_rechecked(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"other.py": "x\n"})
    head = _git(repo, "rev-parse", "HEAD")
    branch = _known("M", "a.py", base, scope="branch")

    result, outcomes, verifier = _run(repo, base, head, [branch], {})

    assert verifier.asked == [] and outcomes == {}
    [classification] = result.baseline_classifications
    assert classification.relationship == "EXISTING"
    assert result.policy.decision == "PASS"


def test_line_mapping_follows_code_that_moved() -> None:
    inserted_above = (DiffHunk(old_start=3, old_lines=0, new_start=4, new_lines=5, header=""),)
    edited_inside = (DiffHunk(old_start=10, old_lines=2, new_start=10, new_lines=4, header=""),)

    assert map_lines(inserted_above, 10, 11) == ChangedLines(15, 16)
    assert map_lines(edited_inside, 10, 11) == ChangedLines(10, 13)
    assert map_lines(edited_inside, 20, 20) == ChangedLines(22, 22)


def _occurrence_factory():
    return _factory()


def _finding(finding_id: str) -> dict:
    return {"finding_id": finding_id, "root_cause_fingerprint": f"root-{finding_id}", "root_cause_path": "a.py",
            "title": finding_id}


def test_fixed_then_reintroduced_finding_is_reopened() -> None:
    factory = _occurrence_factory()
    from plaidnox_scm.lifecycle import KnownOutcome

    with occurrences.unit_of_work(factory, TENANT) as repository:
        repository.record_run(CODEBASE, 9, review_id="r1", head="h1", observed=[_finding("A")], outcomes=())
    with occurrences.unit_of_work(factory, TENANT) as repository:
        repository.record_run(CODEBASE, 9, review_id="r2", head="h2", observed=[],
                              outcomes=[KnownOutcome("A", "pr", "fixed_verified", "gone", _finding("A"))])
        assert repository.known(CODEBASE, "pr:9") == ()
    with occurrences.unit_of_work(factory, TENANT) as repository:
        repository.record_run(CODEBASE, 9, review_id="r3", head="h3", observed=[_finding("A")], outcomes=())
        [known] = repository.known(CODEBASE, "pr:9")
    assert known.last_seen_head == "h3"
    with factory() as session:
        from plaidnox_scm.models import FindingOccurrenceRecord
        row = session.get(FindingOccurrenceRecord, (TENANT, CODEBASE, "pr:9", "A"))
        assert (row.status, row.reopened_count, row.fixed_reason) == ("open", 1, None)


def test_merge_moves_open_findings_to_the_branch_and_closing_unmerged_retires_them() -> None:
    factory = _occurrence_factory()
    with occurrences.unit_of_work(factory, TENANT) as repository:
        repository.record_run(CODEBASE, 1, review_id="r1", head="h1", observed=[_finding("A"), _finding("B")], outcomes=())
        repository.record_run(CODEBASE, 2, review_id="r2", head="h2", observed=[_finding("B")], outcomes=())

    with occurrences.unit_of_work(factory, TENANT) as repository:
        merged = repository.close_pull_request(CODEBASE, 1, merged=True, head="m1")
        closed = repository.close_pull_request(CODEBASE, 2, merged=False, head="h2")
        branch = {item.finding_id for item in repository.known(CODEBASE, occurrences.BRANCH)}

    assert set(merged.promoted) == {"A", "B"}
    assert closed.closed == ("B",)
    assert branch == {"A", "B"}  # closing PR 2 does not touch what PR 1 merged


def test_same_bug_in_two_open_prs_fixed_in_one_stays_open_in_the_other() -> None:
    factory = _occurrence_factory()
    from plaidnox_scm.lifecycle import KnownOutcome

    with occurrences.unit_of_work(factory, TENANT) as repository:
        repository.record_run(CODEBASE, 1, review_id="r1", head="h1", observed=[_finding("A")], outcomes=())
        repository.record_run(CODEBASE, 2, review_id="r2", head="h2", observed=[_finding("A")], outcomes=())
        repository.record_run(CODEBASE, 1, review_id="r3", head="h3", observed=[],
                              outcomes=[KnownOutcome("A", "pr", "fixed_verified", "gone", _finding("A"))])
        assert repository.known(CODEBASE, "pr:1") == ()
        assert [item.finding_id for item in repository.known(CODEBASE, "pr:2")] == ["A"]


def test_merging_a_pr_that_fixed_a_branch_finding_resolves_it_everywhere(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from plaidnox_scm.api_service import ReviewService
    from plaidnox_scm.lifecycle import KnownOutcome
    from plaidnox_scm.source_broker import RepositoryMirrorBroker

    factory = _occurrence_factory()
    service = ReviewService(RepositoryMirrorBroker(tmp_path), factory, lambda: None)
    with occurrences.unit_of_work(factory, TENANT) as repository:
        repository.record_run(CODEBASE, 1, review_id="r1", head="h1", observed=[_finding("M")], outcomes=())
        repository.close_pull_request(CODEBASE, 1, merged=True, head="m1")  # M is now on main
    fixed = SimpleNamespace(
        baseline_classifications=(),
        known_outcomes=(KnownOutcome("M", "branch", "fixed_verified", "capped", _finding("M")),),
    )
    service._record_occurrences(TENANT, CODEBASE, SimpleNamespace(review_number=2, head_sha="h2"), "r2",
                                SimpleNamespace(findings=[]), fixed)

    with triage.unit_of_work(factory, TENANT) as repository:
        assert repository.get("M") is None  # not resolved while the fix is only on the PR branch
    service.close_pull_request(TENANT, CODEBASE, 2, merged=True, head_sha="m2")

    with occurrences.unit_of_work(factory, TENANT) as repository:
        assert repository.known(CODEBASE, occurrences.BRANCH) == ()
    with triage.unit_of_work(factory, TENANT) as repository:
        # Nobody claimed it with !fixed: triage stays untouched, the fix lives in the
        # per-scope status (branch row "fixed"), so a later regression reopens cleanly.
        assert repository.get("M") is None
    from plaidnox_scm.models import FindingOccurrenceRecord
    with factory() as session:
        branch = session.get(FindingOccurrenceRecord, (TENANT, CODEBASE, occurrences.BRANCH, "M"))
        assert branch.status == "fixed" and "PR #2" in branch.fixed_reason


def test_a_false_positive_verdict_survives_re_observation(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"app.py": CODE, "other.py": "x\n"})
    first_head = _git(repo, "rev-parse", "HEAD")
    head = _commit(repo, {"other.py": "y\n"})
    factory = _factory()
    with triage.unit_of_work(factory, TENANT) as repository:
        repository.apply_command("A", "r1", "fp", actor="reviewer", reason="not reachable")

    result, outcomes, _ = _run(repo, base, head, [_known("A", "app.py", first_head)], {}, factory)

    assert outcomes == {"A": "carried_unchanged"}
    assert result.policy.decision == "PASS"  # still listed, but the human verdict is honoured


def test_three_pushes_to_one_pr_through_the_review_api(tmp_path: Path) -> None:
    """Push 1 introduces a bug, push 2 touches another file, push 3 fixes it."""

    from test_scm_api import _factory as _api_factory

    from plaidnox_scm.api_models import ReviewRequest
    from plaidnox_scm.api_service import ReviewService
    from plaidnox_scm.l1_review import L1Candidate
    from plaidnox_scm.models import FindingOccurrenceRecord
    from plaidnox_scm.production import ReviewDependencies
    from plaidnox_scm.source_broker import RepositoryMirrorBroker

    mirror = tmp_path / "mirrors" / "github" / "899377752"
    mirror.mkdir(parents=True)
    _git(mirror, "init", "-b", "main")
    _git(mirror, "config", "user.email", "t@plaidnox.local")
    _git(mirror, "config", "user.name", "t")
    base = _commit(mirror, {"README.md": "# app\n"})
    vulnerable = "".join(f"// {n}\n" for n in range(1, 10)) + "const claims = jwt.decode(token);\n"
    head1 = _commit(mirror, {"middleware/auth.js": vulnerable, "lib/util.js": "x\n"})
    head2 = _commit(mirror, {"lib/util.js": "y\n"})
    head3 = _commit(mirror, {"middleware/auth.js": vulnerable.replace("jwt.decode", "verifier.verify")})

    class L1:
        def __init__(self):
            self.first = True

        def review(self, repo_path, diff, relevance, application_context):
            candidates = ()
            if self.first:
                self.first = False
                candidates = (L1Candidate(
                    candidate_id="jwt", changed_path="middleware/auth.js", changed_symbol="auth",
                    changed_lines=__import__("plaidnox_scm.l1_review", fromlist=["ChangedLines"]).ChangedLines(10, 10),
                    behavior_before="verified", behavior_after="decoded", security_role="authentication",
                    suspected_broken_invariant="authentic tokens only", provisional_attacker_capability="forge identity",
                    context_facts_used=(), context_gaps=(), requested_expansion=(),
                ),)
            return L1ReviewBatch(candidates, tuple(file.path for file in diff.files), True, (), 1)

    class Verifier:
        def verify(self, repo_path, head_revision, repository_name, application_context, candidates, minimum_depth):
            out = []
            for candidate in candidates:
                fixed = head_revision == head3
                out.append(CandidateVerification(
                    candidate_id=candidate.candidate_id, state="rejected" if fixed else "verified", confidence=0.97,
                    title="JWT claims accepted without signature verification", vulnerability_class="CWE-347",
                    severity="high", message="Unsigned claims become identity.", business_impact="impersonation",
                    remediation="Verify the JWT signature.", reasoning="r", attack_path="token -> decode -> identity",
                    security_invariant="signed claims only", gained_capability="impersonate any user",
                    rejection_reason="Signature is verified again." if fixed else "",
                    evidence_locations=(), classification_references=({"namespace": "CWE", "identifier": "CWE-347"},),
                    evidence_gaps=(), route=ROUTE,
                ))
            return tuple(out)

    l1 = L1()
    factory = _api_factory()
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        factory,
        lambda: ReviewDependencies(context_builder=_ContextBuilder(), l1_reviewer=l1, candidate_verifier=Verifier()),
    )

    def run(head: str, delivery: str):
        return service.run(ReviewRequest(
            provider="github", installation_id=12345, repository_full_name="C0oki3s/NSTCTF", repository_id=899377752,
            review_number=7, base_sha=base, head_sha=head, base_ref="main", head_ref="feature", delivery_id=delivery,
        ))

    first = run(head1, "d1")
    second = run(head2, "d2")
    third = run(head3, "d3")

    [found] = first.findings
    [carried] = second.findings
    assert carried.finding_id == found.finding_id  # one bug, one id, no duplicate
    assert carried.lifecycle == "carried_forward"
    assert second.action.value == "block"  # unchanged code: still blocking
    assert third.findings == [] and third.action.value == "allow"

    with factory() as session:
        row = session.get(FindingOccurrenceRecord, ("test-tenant", "github:repository:899377752", "pr:7", found.finding_id))
        assert (row.status, row.fixed_head, row.first_seen_review_id) == ("fixed", head3, first.review_id)
    with triage.unit_of_work(factory, "test-tenant") as repository:
        assert repository.get(found.finding_id) is None  # fix shown by the PR's occurrence status


def test_merge_webhook_moves_the_prs_open_findings_onto_the_default_branch(tmp_path: Path) -> None:
    from test_scm_api import _factory as _api_factory

    from plaidnox_scm.api_service import ReviewService
    from plaidnox_scm.source_broker import RepositoryMirrorBroker

    factory = _api_factory()
    codebase = "github:repository:899377752"
    with occurrences.unit_of_work(factory, "test-tenant") as repository:
        repository.record_run(codebase, 7, review_id="r1", head="h1", observed=[_finding("A")], outcomes=())
    service = ReviewService(RepositoryMirrorBroker(tmp_path), factory, lambda: None)

    accepted, _ = service.claim_webhook_delivery(
        delivery_id="merge-1", provider="github", installation_id=12345, repository_id=899377752,
        event_name="pull_request", action="merged", pull_number=7, head_sha="m" * 40,
    )
    service.claim_webhook_delivery(  # a redelivery of the same webhook changes nothing
        delivery_id="merge-1", provider="github", installation_id=12345, repository_id=899377752,
        event_name="pull_request", action="merged", pull_number=7, head_sha="m" * 40,
    )

    assert accepted
    with occurrences.unit_of_work(factory, "test-tenant") as repository:
        [branch] = repository.known(codebase, occurrences.BRANCH)
        assert repository.known(codebase, "pr:7") == ()
    assert (branch.finding_id, branch.last_seen_head) == ("A", "m" * 40)


def test_a_claimed_fix_is_resolved_only_by_proof_and_a_regression_reopens_it(tmp_path: Path, monkeypatch) -> None:
    from plaidnox_scm import api_service
    from plaidnox_scm.api_service import ReviewService
    from plaidnox_scm.lifecycle import KnownOutcome
    from plaidnox_scm.source_broker import RepositoryMirrorBroker

    factory = _occurrence_factory()
    service = ReviewService(RepositoryMirrorBroker(tmp_path), factory, lambda: None)
    with triage.unit_of_work(factory, TENANT) as repository:
        repository.apply_command("A", "r1", "fixed", actor="dev", reason=None)
        repository.apply_command("FP", "r1", "fp", actor="dev", reason="constant input")
    fixed = SimpleNamespace(
        baseline_classifications=(),
        known_outcomes=(KnownOutcome("A", "pr", "fixed_verified", "gone", _finding("A")),),
    )
    service._record_occurrences(TENANT, CODEBASE, SimpleNamespace(review_number=3, head_sha="h2"), "r2",
                                SimpleNamespace(findings=[]), fixed)
    with triage.unit_of_work(factory, TENANT) as repository:
        assert repository.get("A").state == "resolved"
        assert repository.list_events("A")[-1].command == "fix_validated"

    again = SimpleNamespace(baseline_classifications=(), known_outcomes=())
    monkeypatch.setattr(api_service, "_stored_finding", lambda item: _finding(item.finding_id))
    reported = SimpleNamespace(findings=[SimpleNamespace(finding_id="A"), SimpleNamespace(finding_id="FP")])
    service._record_occurrences(TENANT, CODEBASE, SimpleNamespace(review_number=5, head_sha="h5"), "r5",
                                reported, again)
    with triage.unit_of_work(factory, TENANT) as repository:
        assert repository.get("A").state == "open"
        assert repository.list_events("A")[-1].command == "fix_regressed"
        assert repository.get("FP").state == "false_positive"  # human verdicts survive


def _transactional_factory():
    """SQLite with real transactions (SQLAlchemy's pysqlite recipe), so savepoints behave as on PostgreSQL.

    By default the sqlite3 driver commits when the outermost SAVEPOINT is released, which
    would hide a rollback of the webhook delivery claim.
    """

    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from plaidnox_scm.models import Base, InstallationTenantRecord

    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def _no_driver_transactions(dbapi_connection, _record):
        dbapi_connection.isolation_level = None

    @event.listens_for(engine, "begin")
    def _begin(connection):
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory.begin() as session:
        session.add(InstallationTenantRecord(provider="github", installation_id=12345, tenant_id="test-tenant", active=True))
    return factory


def _jwt_service(tmp_path: Path):
    """A ReviewService over a real mirror: push 1 adds a JWT bug, push 2 fixes it."""

    from test_scm_api import _factory as _api_factory

    from plaidnox_scm.api_models import ReviewRequest
    from plaidnox_scm.api_service import ReviewService
    from plaidnox_scm.l1_review import ChangedLines, L1Candidate
    from plaidnox_scm.production import ReviewDependencies
    from plaidnox_scm.source_broker import RepositoryMirrorBroker

    mirror = tmp_path / "mirrors" / "github" / "899377752"
    mirror.mkdir(parents=True)
    _git(mirror, "init", "-b", "main")
    _git(mirror, "config", "user.email", "t@plaidnox.local")
    _git(mirror, "config", "user.name", "t")
    base = _commit(mirror, {"README.md": "# app\n"})
    vulnerable = "".join(f"// {n}\n" for n in range(1, 10)) + "const claims = jwt.decode(token);\n"
    head1 = _commit(mirror, {"middleware/auth.js": vulnerable})

    class L1:
        def review(self, repo_path, diff, relevance, application_context):
            candidate = L1Candidate(
                candidate_id="jwt", changed_path="middleware/auth.js", changed_symbol="auth",
                changed_lines=ChangedLines(10, 10), behavior_before="verified", behavior_after="decoded",
                security_role="authentication", suspected_broken_invariant="authentic tokens only",
                provisional_attacker_capability="forge identity", context_facts_used=(), context_gaps=(),
                requested_expansion=(),
            )
            return L1ReviewBatch((candidate,), tuple(file.path for file in diff.files), True, (), 1)

    class Verifier:
        def verify(self, repo_path, head_revision, repository_name, application_context, candidates, minimum_depth):
            return tuple(CandidateVerification(
                candidate_id=candidate.candidate_id, state="verified", confidence=0.97,
                title="JWT claims accepted without signature verification", vulnerability_class="CWE-347",
                severity="high", message="m", business_impact="impersonation", remediation="Verify the JWT signature.",
                reasoning="r", attack_path="token -> decode -> identity", security_invariant="signed claims only",
                gained_capability="impersonate any user", rejection_reason="", evidence_locations=(),
                classification_references=({"namespace": "CWE", "identifier": "CWE-347"},), evidence_gaps=(),
                route=ROUTE,
            ) for candidate in candidates)

    factory = _api_factory()
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        factory,
        lambda: ReviewDependencies(context_builder=_ContextBuilder(), l1_reviewer=L1(), candidate_verifier=Verifier()),
    )
    request = ReviewRequest(
        provider="github", installation_id=12345, repository_full_name="C0oki3s/NSTCTF", repository_id=899377752,
        review_number=7, base_sha=base, head_sha=head1, base_ref="main", head_ref="feature", delivery_id="d1",
    )
    return service, factory, request


def test_a_failed_status_write_leaves_the_review_unfinished_and_a_retry_writes_both(tmp_path: Path, monkeypatch) -> None:
    import pytest

    from plaidnox_scm import attempts
    from plaidnox_scm.models import FindingOccurrenceRecord, ReviewAttemptRecord

    service, factory, request = _jwt_service(tmp_path)
    original = occurrences.FindingOccurrenceRepository.record_run
    calls = {"n": 0}

    def flaky(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database went away")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(occurrences.FindingOccurrenceRepository, "record_run", flaky)

    with pytest.raises(RuntimeError):
        service.run(request)
    with factory() as session:
        [attempt] = session.query(ReviewAttemptRecord).all()
        assert attempt.state == "failed"  # never "completed" without its statuses
        assert attempt.findings in (None, [])
        assert session.query(FindingOccurrenceRecord).count() == 0

    retried = service.run(request)  # the same delivery retried

    [finding] = retried.findings
    with factory() as session:
        row = session.get(FindingOccurrenceRecord, ("test-tenant", "github:repository:899377752", "pr:7", finding.finding_id))
        assert row is not None and row.status == "open"
    with attempts.unit_of_work(factory, "test-tenant") as repository:
        assert repository.get(retried.review_id).state == "completed"


def test_a_failed_merge_update_is_not_recorded_so_redelivery_applies_it(tmp_path: Path, monkeypatch) -> None:
    import pytest

    from plaidnox_scm.api_service import ReviewService
    from plaidnox_scm.models import WebhookDeliveryRecord
    from plaidnox_scm.source_broker import RepositoryMirrorBroker

    factory = _transactional_factory()
    codebase = "github:repository:899377752"
    with occurrences.unit_of_work(factory, "test-tenant") as repository:
        repository.record_run(codebase, 7, review_id="r1", head="h1", observed=[_finding("A")], outcomes=())
    service = ReviewService(RepositoryMirrorBroker(tmp_path), factory, lambda: None)
    original = occurrences.FindingOccurrenceRepository.close_pull_request

    def broken(self, *args, **kwargs):
        raise RuntimeError("database went away")

    def deliver():
        return service.claim_webhook_delivery(
            delivery_id="merge-1", provider="github", installation_id=12345, repository_id=899377752,
            event_name="pull_request", action="merged", pull_number=7, head_sha="m" * 40,
        )

    monkeypatch.setattr(occurrences.FindingOccurrenceRepository, "close_pull_request", broken)
    with pytest.raises(RuntimeError):
        deliver()
    with factory() as session:
        assert session.get(WebhookDeliveryRecord, "merge-1") is None  # not accepted, so GitHub can redeliver

    monkeypatch.setattr(occurrences.FindingOccurrenceRepository, "close_pull_request", original)
    accepted, _ = deliver()

    assert accepted
    with occurrences.unit_of_work(factory, "test-tenant") as repository:
        [branch] = repository.known(codebase, occurrences.BRANCH)
    assert branch.finding_id == "A"


def test_an_incomplete_run_never_marks_a_finding_fixed_even_if_its_file_was_deleted(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"app.py": CODE, "other.py": "x\n"})
    first_head = _git(repo, "rev-parse", "HEAD")
    head = _commit(repo, {"app.py": None})

    # No review dependencies configured: the run is incomplete and cannot verify anything.
    result = review_pull_request(
        repo, base, head, CODEBASE, TENANT, _factory(), known_findings=(_known("A", "app.py", first_head),),
    )

    assert {item.finding_id: item.outcome for item in result.known_outcomes} == {"A": "carried_incomplete"}
    assert "incomplete" in result.known_outcomes[0].reason


def test_a_complete_run_marks_a_deleted_files_finding_fixed(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"app.py": CODE, "other.py": "x\n"})
    first_head = _git(repo, "rev-parse", "HEAD")
    head = _commit(repo, {"app.py": None, "other.py": "y\n"})

    _, outcomes, verifier = _run(repo, base, head, [_known("A", "app.py", first_head)], {})

    assert outcomes == {"A": "fixed_removed"}
    assert verifier.asked == []
