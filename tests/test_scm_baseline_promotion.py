"""Wave 10: promoting a merged review's findings into the persistent baseline.

`review.py`'s baseline classification reads `list_baseline_findings(codebase_id,
base_revision)` to tell an `INTRODUCED` finding from an `EXISTING` one, but
nothing ever wrote a row forward once a PR carrying an `INTRODUCED` finding
actually merged -- so the very next PR against the new `main` would see the
same finding as newly introduced all over again. `POST
/v1/reviews/{review_id}/promote` closes that gap.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from plaidnox_scm import context_store
from plaidnox_scm.api import create_app
from plaidnox_scm.api_models import ReviewRequest
from plaidnox_scm.api_service import ReviewService, _review_id
from plaidnox_scm.attempts import unit_of_work as attempts_unit_of_work
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


def _verified_finding_result() -> SimpleNamespace:
    candidate = SimpleNamespace(
        candidate_id="candidate-1",
        changed_lines=SimpleNamespace(start=12, end=12),
        context_facts_used=(),
        provisional_attacker_capability="Forge an unsigned session claim.",
    )
    verification = SimpleNamespace(
        candidate_id="candidate-1",
        message="Unsigned claims become trusted identity.",
        business_impact="An attacker can impersonate a manager.",
        remediation="Restore cryptographic JWT verification.",
        security_invariant="Only cryptographically signed claims may authenticate a request.",
        gained_capability="Forge an unsigned session claim.",
        proof_plan="",
        regression_test="",
        evidence_gaps=(),
        evidence=(),
    )
    classification = SimpleNamespace(
        verification_state="verified",
        candidate_id="candidate-1",
        finding_fingerprint="finding-1",
        root_cause_fingerprint="root-cause-1",
        title="Protected routes accept unsigned JWT claims",
        severity="High",
        confidence=0.99,
        root_cause_path="middleware/ValidateToken.js",
        root_cause_symbol="ValidateToken.middleware",
        root_cause_changed_in_review=True,
        vulnerability_class="CWE-347",
        relationship="INTRODUCED",
    )
    return SimpleNamespace(
        outcome="findings_verified",
        policy=SimpleNamespace(decision="BLOCK", reasons=()),
        counters=SimpleNamespace(blocking=1, in_triage=1),
        candidates=(candidate,),
        verifications=(verification,),
        baseline_classifications=(classification,),
        coverage_gaps=(),
        detail="verified",
    )


def test_promote_endpoint_writes_completed_findings_into_the_new_baseline(monkeypatch, tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    monkeypatch.setattr(
        "plaidnox_scm.api_service.review_pull_request", lambda *args, **kwargs: _verified_finding_result()
    )
    factory = _factory()
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        factory,
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    client = TestClient(create_app(service, api_token="scanner-token"))
    request_body = _request(base, head)
    review_response = client.post(
        "/v1/reviews", headers={"Authorization": "Bearer scanner-token"}, json=request_body
    )
    assert review_response.status_code == 200
    review_id = review_response.json()["review_id"]
    merge_revision = "f" * 40

    promote_response = client.post(
        f"/v1/reviews/{review_id}/promote",
        headers={"Authorization": "Bearer scanner-token"},
        json={"merge_revision": merge_revision},
    )

    assert promote_response.status_code == 200
    assert promote_response.json() == {
        "review_id": review_id,
        "codebase_id": "github:repository:899377752",
        "baseline_revision": merge_revision,
        "promoted_count": 1,
    }
    with context_store.unit_of_work(factory, "github:installation:12345") as repository:
        baseline = repository.list_baseline_findings("github:repository:899377752", merge_revision)
    assert len(baseline) == 1
    assert baseline[0].root_cause_fingerprint == "root-cause-1"
    assert baseline[0].finding_fingerprint == "finding-1"
    assert baseline[0].lifecycle_state == "open"
    assert baseline[0].root_cause_path == "middleware/ValidateToken.js"
    assert baseline[0].root_cause_symbol == "ValidateToken.middleware"
    assert baseline[0].vulnerability_class == "CWE-347"
    assert baseline[0].title == "Protected routes accept unsigned JWT claims"
    assert baseline[0].severity == "high"
    assert baseline[0].confidence == 0.99


def test_promote_endpoint_is_idempotent_under_a_replayed_merge_webhook(monkeypatch, tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    monkeypatch.setattr(
        "plaidnox_scm.api_service.review_pull_request", lambda *args, **kwargs: _verified_finding_result()
    )
    factory = _factory()
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        factory,
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    client = TestClient(create_app(service, api_token="scanner-token"))
    review_id = client.post(
        "/v1/reviews", headers={"Authorization": "Bearer scanner-token"}, json=_request(base, head)
    ).json()["review_id"]
    merge_revision = "e" * 40

    for _ in range(2):
        response = client.post(
            f"/v1/reviews/{review_id}/promote",
            headers={"Authorization": "Bearer scanner-token"},
            json={"merge_revision": merge_revision},
        )
        assert response.status_code == 200

    with context_store.unit_of_work(factory, "github:installation:12345") as repository:
        baseline = repository.list_baseline_findings("github:repository:899377752", merge_revision)
    assert len(baseline) == 1


def test_promote_endpoint_rejects_unknown_review_id(tmp_path: Path) -> None:
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        _factory(),
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    client = TestClient(create_app(service, api_token="scanner-token"))

    response = client.post(
        "/v1/reviews/review_does-not-exist/promote",
        headers={"Authorization": "Bearer scanner-token"},
        json={"merge_revision": "a" * 40},
    )

    assert response.status_code == 404


def test_promote_endpoint_rejects_a_review_that_has_not_completed_yet(tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    factory = _factory()
    request = ReviewRequest.model_validate(_request(base, head))
    review_id = _review_id(request)
    with attempts_unit_of_work(factory, f"{request.provider}:installation:{request.installation_id}") as repository:
        repository.claim(
            review_id,
            f"{request.provider}:repository:{request.repository_id}",
            provider=request.provider,
            repository_id=request.repository_id,
            review_number=request.review_number,
            base_sha=request.base_sha,
            head_sha=request.head_sha,
            delivery_id=request.delivery_id,
            lease_owner="another-worker",
            lease_seconds=600,
            max_attempts=3,
        )
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        factory,
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    client = TestClient(create_app(service, api_token="scanner-token"))

    response = client.post(
        f"/v1/reviews/{review_id}/promote",
        headers={"Authorization": "Bearer scanner-token"},
        json={"merge_revision": "a" * 40},
    )

    assert response.status_code == 409
