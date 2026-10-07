"""Finding lifecycle across review runs: carry forward, re-check, fix and reopen.

Industry trackers (GitHub code scanning, SonarQube, Semgrep) agree on the model:

* a finding has one stable identity, independent of line numbers and wording;
* *fixed* is per branch/PR: a finding is fixed where a later scan of that same
  branch no longer has it, and only becomes fixed on the default branch once the
  fix is merged;
* a fixed finding that shows up again is reopened; a human dismissal
  (false positive / accepted risk) survives later scans.

An LLM reviewer adds one twist: *not reporting* a finding is not evidence that it
is gone, because the model is non-deterministic. So a finding is only marked
fixed with evidence:

* its root-cause file was deleted, or
* the file changed and an explicit re-verification of that finding at the new
  commit rejected it.

If the file did not change, the code is identical and the finding is carried
forward. If the run was incomplete or re-verification was inconclusive, the
finding stays open.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .baseline import prior_findings_from_stored
from .dedupe import IssueSignature, signature
from .diffing import DiffError, DiffHunk, compute_diff
from .l1_review import ChangedLines, L1Candidate

KnownScope = Literal["pr", "branch"]
KnownOutcomeKind = Literal[
    "reobserved",          # reported again by this run (same identity)
    "carried_unchanged",   # root-cause file identical since it was last verified
    "carried_incomplete",  # this run could not cover it; stays open, unchanged
    "recheck_unresolved",  # file changed, re-verification was inconclusive; stays open
    "fixed_removed",       # root-cause file deleted
    "fixed_verified",      # file changed and re-verification rejected the finding
    "duplicate",           # the same bug as another tracked finding (e.g. legacy ids)
]
FIXED_OUTCOMES = frozenset({"fixed_removed", "fixed_verified"})
CARRIED_OUTCOMES = frozenset({"carried_unchanged", "carried_incomplete", "recheck_unresolved"})

RECHECK_PREFIX = "recheck:"


@dataclass(frozen=True, slots=True)
class KnownFinding:
    """A still-open finding from an earlier run of this PR, or from the default branch."""

    scope: KnownScope
    finding: dict[str, Any]
    # Commit at which the finding was last verified present (PR scope), or the
    # PR's base commit (branch scope).
    last_seen_head: str

    @property
    def finding_id(self) -> str:
        return str(self.finding["finding_id"])

    @property
    def root_cause_fingerprint(self) -> str:
        return str(self.finding.get("root_cause_fingerprint") or "")

    @property
    def path(self) -> str:
        return str(self.finding.get("root_cause_path") or "")

    @property
    def signature(self) -> IssueSignature:
        # Built exactly like a stored prior finding, so matching uses one rule everywhere.
        stored = {**self.finding, "root_cause_fingerprint": self.root_cause_fingerprint or "unknown"}
        prior = prior_findings_from_stored([stored])
        if prior:
            return prior[0].signature
        return signature(path=self.path, symbol="", start_line=1, end_line=1, title="", vulnerability_class="")


@dataclass(frozen=True, slots=True)
class KnownOutcome:
    finding_id: str
    scope: KnownScope
    outcome: KnownOutcomeKind
    reason: str
    finding: dict[str, Any]


@dataclass(frozen=True, slots=True)
class FileChange:
    status: Literal["unchanged", "modified", "renamed", "deleted", "unknown"]
    path: str
    lines: ChangedLines


def file_change(repo_path: Path, old: str, new: str, known: KnownFinding) -> FileChange:
    """Where the finding's root-cause lines are at ``new``, and whether that file changed."""

    start = int(known.finding.get("root_cause_start_line") or 1)
    end = max(start, int(known.finding.get("root_cause_end_line") or start))
    stored = ChangedLines(start, end)
    if not old or old == new:
        return FileChange("unchanged", known.path, stored)
    try:
        diff = compute_diff(repo_path, old, new)
    except DiffError:
        # The earlier commit is gone (force-push) or unreachable: we cannot prove the
        # file is identical, so treat it as changed and re-verify at the stored lines.
        return FileChange("unknown", known.path, stored)
    for item in diff.files:
        if item.path == known.path or item.old_path == known.path:
            if item.status == "deleted":
                return FileChange("deleted", known.path, stored)
            mapped = map_lines(item.hunks, start, end)
            status = "renamed" if item.status == "renamed" and item.old_path == known.path else "modified"
            return FileChange(status, item.path, mapped)
    return FileChange("unchanged", known.path, stored)


def map_lines(hunks: tuple[DiffHunk, ...], start: int, end: int) -> ChangedLines:
    """Translate an old-side line range to the new side; edited lines map to their hunk."""

    first, first_touched = _map_line(hunks, start)
    last, last_touched = _map_line(hunks, end)
    new_start = first[0]
    new_end = max(last[1] if last_touched else last[0], new_start)
    if first_touched:
        new_end = max(new_end, first[1])
    return ChangedLines(max(1, new_start), max(1, new_end))


def _map_line(hunks: tuple[DiffHunk, ...], line: int) -> tuple[tuple[int, int], bool]:
    delta = 0
    for hunk in sorted(hunks, key=lambda item: item.old_start):
        old_end = hunk.old_start + hunk.old_lines - 1
        if hunk.old_lines > 0 and hunk.old_start <= line <= old_end:
            new_start = hunk.new_start if hunk.new_lines > 0 else max(1, hunk.new_start)
            return (new_start, new_start + max(hunk.new_lines, 1) - 1), True
        if (hunk.old_lines > 0 and line > old_end) or (hunk.old_lines == 0 and line > hunk.old_start):
            delta += hunk.new_lines - hunk.old_lines
    return (line + delta, line + delta), False


def recheck_candidate(known: KnownFinding, change: FileChange) -> L1Candidate:
    """A verification hypothesis that asks: is this previously verified bug still here?"""

    finding = known.finding
    title = str(finding.get("title") or "previously verified finding")
    capability = str(
        finding.get("gained_capability")
        or next(iter(finding.get("capabilities") or []), "")
        or title
    )
    return L1Candidate(
        candidate_id=f"{RECHECK_PREFIX}{known.finding_id}",
        changed_path=change.path,
        changed_symbol=str(finding.get("root_cause_symbol") or ""),
        changed_lines=change.lines,
        behavior_before=f"Previously verified at {known.last_seen_head[:12]}: {title}",
        behavior_after="The root-cause code changed since; confirm whether the vulnerability is still present.",
        security_role=str(finding.get("security_boundary") or finding.get("category") or "security control"),
        suspected_broken_invariant=str(finding.get("remediation_invariant") or title),
        provisional_attacker_capability=capability,
        context_facts_used=tuple(str(item) for item in finding.get("context_facts") or [])[:8],
        context_gaps=(),
        requested_expansion=(),
    )


def known_from_stored(
    scope: KnownScope,
    findings: list[tuple[str, dict[str, Any]]],
) -> tuple[KnownFinding, ...]:
    """(last_seen_head, stored finding) pairs, newest first, one entry per finding id."""

    seen: set[str] = set()
    known: list[KnownFinding] = []
    for head, finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("finding_id") or "")
        if not finding_id or not finding.get("root_cause_path") or finding_id in seen:
            continue
        seen.add(finding_id)
        known.append(KnownFinding(scope, finding, head))
    return tuple(known)
