from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=True
    )
    return result.stdout.strip()


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "tests@plaidnox.local")
    git(repo, "config", "user.name", "PlaidNox Tests")
    (repo / ".plaidnox").mkdir()
    (repo / ".plaidnox" / "config.yaml").write_text(
        """version: 1
policy:
  block_severities: [critical, high]
  warn_severities: [medium]
  minimum_confidence: 0.7
"""
    )
    (repo / ".plaidnox" / "security.md").write_text("# Security Context\nAuthentication uses signed tokens.\n")
    (repo / "app.js").write_text(
        """const jwt = require("jsonwebtoken");
const express = require("express");
const app = express();
app.post("/signin", async (req, res) => {
  const identity = jwt.decode(req.body.token);
  res.cookie("idToken", req.body.token, { httpOnly: true });
  return res.json({ identity });
});
"""
    )
    (repo / ".env").write_text("TEST_PLACEHOLDER=true\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "fixture")
    return repo
