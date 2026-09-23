"""Privacy tests for review-attempt persistence (priority item 12).

Everything a review attempt persists -- a failure's `error_message`, and a
completed attempt's stored `findings`/`summary` that a duplicate delivery
later replays -- must never carry a raw secret past `plaidnox_sast.redaction`,
since this table is durable and outlives the single HTTP response that
`redact()` already protects.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from plaidnox_scm import attempts
from plaidnox_scm.api_models import ReviewRequest
from plaidnox_scm.api_service import ReviewService, _review_id
from plaidnox_scm.models import Base
from plaidnox_scm.source_broker import RepositoryMirrorBroker

_LEAKED_MONGO_URI = "mongodb://scanner:s3cr3t@internal-db.plaidnox.local/reviews"
_LEAKED_API_KEY = "sk-aaaaaaaaaaaaaaaaaaaaaaaa"


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


def test_failed_review_persists_a_redacted_error_message(monkeypatch, tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)

    def fake_review_pull_request(*args: object, **kwargs: object) -> None:
        raise RuntimeError(
            f"upstream call failed: uri={_LEAKED_MONGO_URI} key={_LEAKED_API_KEY}"
        )

    monkeypatch.setattr("plaidnox_scm.api_service.review_pull_request", fake_review_pull_request)
    factory = _factory()
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        factory,
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    request = ReviewRequest.model_validate(_request(base, head))

    try:
        service.run(request)
        raise AssertionError("expected the injected RuntimeError to propagate")
    except RuntimeError:
        pass

    tenant_id = f"{request.provider}:installation:{request.installation_id}"
    with attempts.unit_of_work(factory, tenant_id) as repository:
        attempt = repository.get(_review_id(request))

    assert attempt is not None
    assert attempt.state == "failed"
    assert attempt.error_message is not None
    assert _LEAKED_MONGO_URI not in attempt.error_message
    assert _LEAKED_API_KEY not in attempt.error_message
    assert "<redacted-mongodb-uri>" in attempt.error_message
    assert "<redacted-api-key>" in attempt.error_message


def test_replayed_duplicate_delivery_does_not_resurface_a_raw_secret(monkeypatch, tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    candidate = SimpleNamespace(candidate_id="candidate-1", changed_lines=SimpleNamespace(start=12, end=12))
    verification = SimpleNamespace(
        candidate_id="candidate-1",
        message=f"Leaked key {_LEAKED_API_KEY} observed in logs.",
        business_impact="",
        remediation="Rotate the key.",
    )
    classification = SimpleNamespace(
        verification_state="verified",
        candidate_id="candidate-1",
        finding_fingerprint="finding-1",
        title="Secret leaked to logs",
        severity="High",
        confidence=0.9,
        root_cause_path="app.py",
        root_cause_changed_in_review=True,
        vulnerability_class="CWE-532",
        relationship="INTRODUCED",
    )
    result = SimpleNamespace(
        outcome="findings_verified",
        policy=SimpleNamespace(decision="BLOCK", reasons=()),
        counters=SimpleNamespace(blocking=1, in_triage=1),
        candidates=(candidate,),
        verifications=(verification,),
        baseline_classifications=(classification,),
        coverage_gaps=(),
        detail="verified",
    )
    monkeypatch.setattr("plaidnox_scm.api_service.review_pull_request", lambda *args, **kwargs: result)
    factory = _factory()
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        factory,
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    request = ReviewRequest.model_validate(_request(base, head))

    first_response = service.run(request)
    second_response = service.run(request)

    assert first_response.findings[0].description == second_response.findings[0].description
    for response in (first_response, second_response):
        assert _LEAKED_API_KEY not in response.findings[0].description
        assert "<redacted-api-key>" in response.findings[0].description

    tenant_id = f"{request.provider}:installation:{request.installation_id}"
    with attempts.unit_of_work(factory, tenant_id) as repository:
        attempt = repository.get(_review_id(request))
    assert attempt is not None
    assert _LEAKED_API_KEY not in str(attempt.findings)
