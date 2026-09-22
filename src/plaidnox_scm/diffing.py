"""SCM-agnostic base..head diff computation.

Shells out to the local `git` checkout only -- no GitHub/GitLab API
involved. Provider webhook verification/normalization is a separate,
deferred concern (see docs/PRODUCT_WORKSTREAMS.md's SCM Integration
section); this module works against any local git repository.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


class DiffError(RuntimeError):
    """Raised when git diff computation fails against the local repository."""


@dataclass(frozen=True, slots=True)
class DiffHunk:
    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    header: str
    added_lines: tuple[str, ...] = ()
    removed_lines: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ChangedFile:
    path: str
    status: str  # "added" | "modified" | "deleted" | "renamed" | "copied"
    old_path: str | None
    hunks: tuple[DiffHunk, ...]


@dataclass(frozen=True, slots=True)
class Diff:
    base_ref: str
    head_ref: str
    files: tuple[ChangedFile, ...]


_DIFF_GIT_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


def compute_diff(repo_path: Path, base_ref: str, head_ref: str) -> Diff:
    range_spec = f"{base_ref}..{head_ref}"
    status_output = _run_git(repo_path, ["diff", "--name-status", "-M", range_spec])
    hunk_output = _run_git(repo_path, ["diff", "-U0", range_spec])
    statuses = _parse_name_status(status_output)
    hunks_by_path = _parse_hunks(hunk_output)
    files = tuple(
        ChangedFile(
            path=path,
            status=status,
            old_path=old_path,
            hunks=tuple(hunks_by_path.get(path, [])),
        )
        for path, (status, old_path) in sorted(statuses.items())
    )
    return Diff(base_ref=base_ref, head_ref=head_ref, files=files)


def _run_git(repo_path: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise DiffError(f"git diff failed for {repo_path}: {exc}") from exc
    return result.stdout


def _parse_name_status(output: str) -> dict[str, tuple[str, str | None]]:
    statuses: dict[str, tuple[str, str | None]] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        code = parts[0]
        if code.startswith("R"):
            statuses[parts[2]] = ("renamed", parts[1])
        elif code.startswith("C"):
            statuses[parts[2]] = ("copied", parts[1])
        elif code.startswith("A"):
            statuses[parts[1]] = ("added", None)
        elif code.startswith("D"):
            statuses[parts[1]] = ("deleted", None)
        else:
            statuses[parts[1]] = ("modified", None)
    return statuses


def _parse_hunks(output: str) -> dict[str, list[DiffHunk]]:
    hunks_by_path: dict[str, list[DiffHunk]] = {}
    current_path: str | None = None
    current_hunk: dict[str, object] | None = None
    added: list[str] = []
    removed: list[str] = []

    def flush() -> None:
        nonlocal current_hunk, added, removed
        if current_path is not None and current_hunk is not None:
            hunks_by_path.setdefault(current_path, []).append(
                DiffHunk(
                    old_start=current_hunk["old_start"],  # type: ignore[arg-type]
                    old_lines=current_hunk["old_lines"],  # type: ignore[arg-type]
                    new_start=current_hunk["new_start"],  # type: ignore[arg-type]
                    new_lines=current_hunk["new_lines"],  # type: ignore[arg-type]
                    header=current_hunk["header"],  # type: ignore[arg-type]
                    added_lines=tuple(added),
                    removed_lines=tuple(removed),
                )
            )
        current_hunk = None
        added = []
        removed = []

    for line in output.splitlines():
        if _DIFF_GIT_RE.match(line):
            flush()
            current_path = None
            continue
        if line.startswith("+++ "):
            flush()
            candidate = line[4:]
            current_path = None if candidate == "/dev/null" else candidate.removeprefix("b/")
            continue
        if line.startswith("--- "):
            candidate = line[4:]
            if current_path is None and candidate != "/dev/null":
                current_path = candidate.removeprefix("a/")
            continue
        hunk_match = _HUNK_RE.match(line)
        if hunk_match:
            flush()
            old_start, old_lines, new_start, new_lines, header = hunk_match.groups()
            current_hunk = {
                "old_start": int(old_start),
                "old_lines": int(old_lines) if old_lines else 1,
                "new_start": int(new_start),
                "new_lines": int(new_lines) if new_lines else 1,
                "header": (header or "").strip(),
            }
            continue
        if current_hunk is not None:
            if line.startswith("+") and not line.startswith("+++"):
                added.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                removed.append(line[1:])
    flush()
    return hunks_by_path
