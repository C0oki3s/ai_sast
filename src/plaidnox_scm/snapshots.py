"""Safe, read-only access to immutable git revisions for PR review."""

from __future__ import annotations

import io
import subprocess
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath


class SnapshotError(RuntimeError):
    """Raised when an immutable git snapshot cannot be read."""


def resolve_revision(repo_path: Path, revision: str) -> str:
    return _run_git(repo_path, ["rev-parse", "--verify", f"{revision}^{{commit}}"], text=True).strip()


def tree_hash(repo_path: Path, revision: str) -> str:
    return _run_git(repo_path, ["rev-parse", "--verify", f"{revision}^{{tree}}"], text=True).strip()


def read_blob(repo_path: Path, revision: str, relative_path: str, maximum_bytes: int) -> str | None:
    """Read one bounded file from a revision without checking it out."""

    if not _safe_relative_path(relative_path):
        raise SnapshotError(f"Unsafe repository path: {relative_path!r}")
    try:
        data = _run_git(repo_path, ["show", f"{revision}:{relative_path}"], text=False)
    except SnapshotError:
        return None
    if len(data) > maximum_bytes:
        data = data[:maximum_bytes]
    return data.decode("utf-8", errors="replace")


@contextmanager
def materialize_revision(repo_path: Path, revision: str) -> Iterator[Path]:
    """Extract a git archive into a temporary directory without running target code."""

    archive = _run_git(repo_path, ["archive", "--format=tar", revision], text=False)
    with tempfile.TemporaryDirectory(prefix="plaidnox-scm-") as directory:
        root = Path(directory).resolve()
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            safe_members: list[tarfile.TarInfo] = []
            for member in bundle.getmembers():
                if not _safe_relative_path(member.name):
                    raise SnapshotError(f"Unsafe path in git archive: {member.name!r}")
                destination = (root / member.name).resolve()
                if root != destination and root not in destination.parents:
                    raise SnapshotError(f"Git archive path escapes snapshot: {member.name!r}")
                if member.isdir() or member.isfile():
                    safe_members.append(member)
            bundle.extractall(root, members=safe_members, filter="data")
        yield root


def _safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts


def _run_git(repo_path: Path, args: list[str], *, text: bool) -> str | bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            capture_output=True,
            text=text,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SnapshotError(f"git {' '.join(args[:2])} failed for {repo_path}") from exc
    return result.stdout
