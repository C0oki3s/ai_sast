"""Wave 12: finding triage lifecycle (`!valid`/`!fp`/`!accepted_risk`/`!fixed`).

Covers only the persistence + state-machine half of docs/PRODUCT_WORKSTREAMS.md's
"Triage commands" section -- webhook verification, comment parsing, and actor
authorization are the bot's job and are exercised nowhere in this repo.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from plaidnox_scm.api import create_app
from plaidnox_scm.api_service import ReviewService
from plaidnox_scm.models import Base
from plaidnox_scm.source_broker import RepositoryMirrorBroker


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def _repository(repo: Path) -> tuple[str, str]:
    repo.mkdir(parents=True)
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.name", "PlaidNox Tests")
    _git(repo, "config", "user.email", "tests@plaidnox.local")
    (repo / "README.md").write_text("# Fixture\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text("# Fixture\n\nDocumentation.\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "docs")
    return base, _git(repo, "rev-parse", "HEAD")


def _request(base: str, head: str) -> dict[str, object]:
    return {
        "provider": "github",
        "installation_id": 12345,
        "repository_full_name": "C0oki3s/NSTCTF",
        "repository_id": 899377752,
        "review_number": 7,
        "base_sha": base,
        "head_sha": head,
        "base_ref": "main",
        "head_ref": "feature/security-test",
        "delivery_id": "delivery-1",
    }


def _factory():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _client(tmp_path: Path) -> tuple[TestClient, str]:
    """Boots a running review (so a real `review_id`/tenant exists) and returns
    `(client, review_id)`; the fixture PR carries no findings of its own --
    triage is exercised against a synthetic `finding_id` unrelated to it,
    proving triage never requires the finding to appear in that review's
    own persisted findings list (see `ReviewService.apply_triage_command`).
    """

    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        _factory(),
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    client = TestClient(create_app(service, api_token="scanner-token"))
    review_id = client.post(
        "/v1/reviews", headers={"Authorization": "Bearer scanner-token"}, json=_request(base, head)
    ).json()["review_id"]
    return client, review_id


def _triage(client: TestClient, review_id: str, finding_id: str, command: str, **kwargs: object):
    return client.post(
        f"/v1/reviews/{review_id}/findings/{finding_id}/triage",
        headers={"Authorization": "Bearer scanner-token"},
        json={"command": command, "actor": "octocat", **kwargs},
    )


def test_triage_status_defaults_to_open_before_any_command(tmp_path: Path) -> None:
    client, review_id = _client(tmp_path)

    response = client.get(
        f"/v1/reviews/{review_id}/findings/finding-1/triage",
        headers={"Authorization": "Bearer scanner-token"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "finding_id": "finding-1",
        "review_id": review_id,
        "state": "open",
        "actor": None,
        "reason": None,
        "updated_at": None,
    }


def test_valid_command_confirms_a_fresh_open_finding(tmp_path: Path) -> None:
    client, review_id = _client(tmp_path)

    response = _triage(client, review_id, "finding-1", "valid")

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "confirmed"
    assert body["previous_state"] == "open"
    assert body["applied"] is True
    assert body["actor"] == "octocat"


def test_fp_command_without_a_reason_is_rejected(tmp_path: Path) -> None:
    client, review_id = _client(tmp_path)

    response = _triage(client, review_id, "finding-1", "fp")

    assert response.status_code == 422


def test_fp_command_with_a_reason_marks_false_positive(tmp_path: Path) -> None:
    client, review_id = _client(tmp_path)

    response = _triage(client, review_id, "finding-1", "fp", reason="Sanitized upstream, verifier missed it.")

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "false_positive"
    assert body["reason"] == "Sanitized upstream, verifier missed it."


def test_accepted_risk_command_without_a_reason_is_rejected(tmp_path: Path) -> None:
    client, review_id = _client(tmp_path)

    response = _triage(client, review_id, "finding-1", "accepted_risk")

    assert response.status_code == 422


def test_accepted_risk_command_with_a_reason_succeeds(tmp_path: Path) -> None:
    client, review_id = _client(tmp_path)

    response = _triage(client, review_id, "finding-1", "accepted_risk", reason="Internal-only endpoint, low risk.")

    assert response.status_code == 200
    assert response.json()["state"] == "accepted_risk"


def test_fixed_command_from_confirmed_moves_to_fix_pending_not_resolved(tmp_path: Path) -> None:
    client, review_id = _client(tmp_path)
    _triage(client, review_id, "finding-1", "valid")

    response = _triage(client, review_id, "finding-1", "fixed")

    assert response.status_code == 200
    body = response.json()
    assert body["previous_state"] == "confirmed"
    assert body["state"] == "fix_pending"


def test_replayed_valid_command_is_an_idempotent_no_op(tmp_path: Path) -> None:
    client, review_id = _client(tmp_path)
    first = _triage(client, review_id, "finding-1", "valid")
    assert first.json()["applied"] is True

    second = _triage(client, review_id, "finding-1", "valid")

    assert second.status_code == 200
    body = second.json()
    assert body["state"] == "confirmed"
    assert body["previous_state"] == "confirmed"
    assert body["applied"] is False


def test_valid_command_conflicts_once_already_false_positive(tmp_path: Path) -> None:
    client, review_id = _client(tmp_path)
    _triage(client, review_id, "finding-1", "fp", reason="Not reachable from any entry point.")

    response = _triage(client, review_id, "finding-1", "valid")

    assert response.status_code == 409


def test_triage_command_rejects_an_unknown_review_id(tmp_path: Path) -> None:
    client, _ = _client(tmp_path)

    response = _triage(client, "review_does-not-exist", "finding-1", "valid")

    assert response.status_code == 404
