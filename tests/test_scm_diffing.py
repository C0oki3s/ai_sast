from __future__ import annotations

import subprocess
from pathlib import Path

from plaidnox_scm.diffing import compute_diff


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def _init_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "tests@plaidnox.local")
    _git(repo, "config", "user.name", "PlaidNox Tests")


def test_compute_diff_detects_added_modified_deleted_and_renamed_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)

    (repo / "keep.py").write_text("def handler():\n    return 1\n")
    (repo / "drop.py").write_text("def old():\n    return 2\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    (repo / "keep.py").write_text("def handler():\n    return 42\n")
    (repo / "drop.py").unlink()
    (repo / "new.py").write_text("def created():\n    return 3\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")

    diff = compute_diff(repo, base, head)
    statuses = {file.path: file.status for file in diff.files}

    assert statuses == {"keep.py": "modified", "drop.py": "deleted", "new.py": "added"}
    modified = next(file for file in diff.files if file.path == "keep.py")
    assert len(modified.hunks) == 1
    assert modified.hunks[0].added_lines == ("    return 42",)
    assert modified.hunks[0].removed_lines == ("    return 1",)


def test_compute_diff_detects_renames(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)

    (repo / "old_name.py").write_text("def handler():\n    return 1\n" * 5)
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    _git(repo, "mv", "old_name.py", "new_name.py")
    _git(repo, "commit", "-m", "rename")
    head = _git(repo, "rev-parse", "HEAD")

    diff = compute_diff(repo, base, head)

    assert len(diff.files) == 1
    assert diff.files[0].path == "new_name.py"
    assert diff.files[0].status == "renamed"
    assert diff.files[0].old_path == "old_name.py"


def test_compute_diff_is_empty_when_nothing_changed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "app.py").write_text("x = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    head = _git(repo, "rev-parse", "HEAD")

    diff = compute_diff(repo, head, head)

    assert diff.files == ()
