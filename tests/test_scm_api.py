from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from plaidnox_scm.api import create_app
from plaidnox_scm.api_models import ReviewRequest
from plaidnox_scm.api_service import ReviewService, _review_id
from plaidnox_scm.attempts import unit_of_work as attempts_unit_of_work
from plaidnox_scm.evidence import EvidenceRole
from plaidnox_scm.models import Base
from plaidnox_scm.source_broker import RepositoryMirrorBroker, RepositorySource, SourceBrokerError


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


def test_review_endpoint_matches_bot_contract_and_skips_ai_for_docs(tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    dependency_calls = 0

    def dependencies():
        nonlocal dependency_calls
        dependency_calls += 1
        raise AssertionError("docs-only review must not construct AI dependencies")

    service = ReviewService(RepositoryMirrorBroker(tmp_path / "mirrors"), _factory(), dependencies)
    client = TestClient(create_app(service, api_token="scanner-token"))

    unauthorized = client.post("/v1/reviews", json=_request(base, head))
    response = client.post(
        "/v1/reviews",
        headers={"Authorization": "Bearer scanner-token"},
        json=_request(base, head),
    )

    assert unauthorized.status_code == 401
    assert response.status_code == 200
    assert response.json() == {
        "review_id": response.json()["review_id"],
        "head_sha": head,
        "action": "allow",
        "summary": "No security findings found.",
        "findings": [],
        "incomplete_reason": None,
        "counters": response.json()["counters"],
    }
    assert response.json()["review_id"].startswith("review_")
    assert dependency_calls == 0


def test_review_endpoint_returns_verified_changed_root_finding(monkeypatch, tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    candidate = SimpleNamespace(
        candidate_id="candidate-1",
        changed_lines=SimpleNamespace(start=12, end=12),
        context_facts_used=("Token middleware guards every protected route.",),
        provisional_attacker_capability="Forge an unsigned session claim.",
    )
    verification = SimpleNamespace(
        candidate_id="candidate-1",
        message="Unsigned claims become trusted identity. Observed sk-aaaaaaaaaaaa must not leave the scanner.",
        business_impact="An attacker can impersonate a manager.",
        remediation="Restore cryptographic JWT verification.",
        security_invariant="Only cryptographically signed claims may authenticate a request.",
        gained_capability="Forge an unsigned session claim.",
        proof_plan="Send a request with an unsigned JWT and observe it is accepted.",
        regression_test="Reject any request whose JWT signature does not verify.",
        evidence_gaps=(),
        evidence=(
            SimpleNamespace(
                role=EvidenceRole.ATTACKER_ORIGIN,
                source="deep_hunt",
                path="middleware/ValidateToken.js",
                start_line=12,
                end_line=12,
                summary="Deep Hunt ATTACKER_ORIGIN evidence",
            ),
        ),
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
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        _factory(),
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    response = TestClient(create_app(service, api_token="scanner-token")).post(
        "/v1/reviews",
        headers={"Authorization": "Bearer scanner-token"},
        json=_request(base, head),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["head_sha"] == head
    assert body["action"] == "block"
    assert body["counters"]["blocking"] == 1
    assert body["counters"]["in_triage"] == 1
    [finding] = body["findings"]
    verified_at = finding.pop("verified_at")
    assert verified_at is not None
    assert finding == {
        "finding_id": "finding-1",
        "root_cause_fingerprint": "root-cause-1",
        "title": "Protected routes accept unsigned JWT claims",
        "severity": "high",
        "confidence": 0.99,
        "description": (
            "Unsigned claims become trusted identity. Observed <redacted-api-key> "
            "must not leave the scanner."
        ),
        "impact": "An attacker can impersonate a manager.",
        "root_cause_path": "middleware/ValidateToken.js",
        "root_cause_symbol": "ValidateToken.middleware",
        "root_cause_start_line": 12,
        "root_cause_end_line": 12,
        "root_cause_changed_in_pr": True,
        "proof_of_concept": None,
        "remediation": "Restore cryptographic JWT verification.",
        "remediation_invariant": "Only cryptographically signed claims may authenticate a request.",
        "proof_plan": "Send a request with an unsigned JWT and observe it is accepted.",
        "regression_test_expectation": "Reject any request whose JWT signature does not verify.",
        "category": "CWE-347",
        "baseline_relationship": "introduced",
        "tenant_id": "github:installation:12345",
        "repository_id": 899377752,
        "base_revision": base,
        "head_revision": head,
        "attacker_origin": "Deep Hunt ATTACKER_ORIGIN evidence",
        "security_boundary": None,
        "defense_removed_or_bypassed": None,
        "downstream_trust": None,
        "sensitive_effects": [],
        "capabilities": ["Forge an unsigned session claim."],
        "evidence": [
            {
                "role": "ATTACKER_ORIGIN",
                "source": "deep_hunt",
                "path": "middleware/ValidateToken.js",
                "start_line": 12,
                "end_line": 12,
                "summary": "Deep Hunt ATTACKER_ORIGIN evidence",
            }
        ],
        "context_facts": ["Token middleware guards every protected route."],
        "evidence_gaps": [],
    }


def test_repository_mirror_broker_requires_exact_requested_revisions(tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    request = ReviewRequest.model_validate(_request(base, head))

    with RepositoryMirrorBroker(tmp_path / "mirrors").materialize(request) as source:
        assert source == RepositorySource(mirror.resolve(), base, head)


def test_repository_mirror_broker_retries_a_not_yet_synced_mirror(monkeypatch, tmp_path: Path) -> None:
    """Wave 11: tolerates the race between webhook delivery and mirror sync.

    The mirror directory doesn't exist yet when `materialize()` is first
    called -- it only appears partway through the retry budget, standing in
    for an out-of-band sync that is still in flight. `time.sleep` is
    monkeypatched so the test doesn't actually wait, and its call count
    doubles as proof of exactly how many attempts were needed.
    """

    staging = tmp_path / "staging"
    base, head = _repository(staging)
    request = ReviewRequest.model_validate(_request(base, head))
    mirrors_root = tmp_path / "mirrors"
    provider_dir = mirrors_root / "github" / "899377752"
    sleep_calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)
        if len(sleep_calls) == 2:
            provider_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(staging, provider_dir)

    monkeypatch.setattr("plaidnox_scm.source_broker.time.sleep", fake_sleep)
    broker = RepositoryMirrorBroker(mirrors_root, sync_retry_attempts=5, sync_retry_interval_seconds=0.01)

    with broker.materialize(request) as source:
        assert source == RepositorySource(provider_dir.resolve(), base, head)
    assert len(sleep_calls) == 2


def test_repository_mirror_broker_gives_up_after_the_retry_budget(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("plaidnox_scm.source_broker.time.sleep", lambda seconds: None)
    request = ReviewRequest.model_validate(_request("a" * 40, "b" * 40))
    broker = RepositoryMirrorBroker(tmp_path / "mirrors", sync_retry_attempts=3, sync_retry_interval_seconds=0.01)

    with pytest.raises(SourceBrokerError):
        with broker.materialize(request):
            pass


def test_review_endpoint_rejects_unknown_contract_fields(tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        _factory(),
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    payload = _request(base, head)
    payload["github_access_token"] = "must-not-cross-this-boundary"

    response = TestClient(create_app(service, api_token="scanner-token")).post(
        "/v1/reviews",
        headers={"Authorization": "Bearer scanner-token"},
        json=payload,
    )

    assert response.status_code == 422


def test_duplicate_delivery_replays_completed_review_without_rerunning(monkeypatch, tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    call_count = 0

    def fake_review_pull_request(*args: object, **kwargs: object) -> SimpleNamespace:
        nonlocal call_count
        call_count += 1
        return SimpleNamespace(
            outcome="pass_no_verified_finding",
            policy=SimpleNamespace(decision="PASS", reasons=()),
            counters=SimpleNamespace(blocking=0, in_triage=0),
            candidates=(),
            verifications=(),
            baseline_classifications=(),
            coverage_gaps=(),
            detail="ok",
        )

    monkeypatch.setattr("plaidnox_scm.api_service.review_pull_request", fake_review_pull_request)
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        _factory(),
        lambda: (_ for _ in ()).throw(AssertionError("dependencies must not be requested")),
    )
    client = TestClient(create_app(service, api_token="scanner-token"))
    payload = _request(base, head)

    first = client.post("/v1/reviews", headers={"Authorization": "Bearer scanner-token"}, json=payload)
    second = client.post("/v1/reviews", headers={"Authorization": "Bearer scanner-token"}, json=payload)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    assert call_count == 1


def test_post_returns_409_when_lease_is_already_running(tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    factory = _factory()
    payload = _request(base, head)
    request = ReviewRequest.model_validate(payload)
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
        lambda: (_ for _ in ()).throw(AssertionError("must not run while lease is held")),
    )
    response = TestClient(create_app(service, api_token="scanner-token")).post(
        "/v1/reviews",
        headers={"Authorization": "Bearer scanner-token"},
        json=payload,
    )

    assert response.status_code == 409


def test_status_endpoint_returns_completed_state_then_404_for_unknown_id(tmp_path: Path) -> None:
    mirror = tmp_path / "mirrors" / "github" / "899377752"
    base, head = _repository(mirror)
    service = ReviewService(
        RepositoryMirrorBroker(tmp_path / "mirrors"),
        _factory(),
        lambda: (_ for _ in ()).throw(AssertionError("docs-only review must not construct AI dependencies")),
    )
    client = TestClient(create_app(service, api_token="scanner-token"))
    payload = _request(base, head)

    posted = client.post("/v1/reviews", headers={"Authorization": "Bearer scanner-token"}, json=payload)
    review_id = posted.json()["review_id"]

    status_response = client.get(f"/v1/reviews/{review_id}", headers={"Authorization": "Bearer scanner-token"})
    missing_response = client.get(
        "/v1/reviews/review_0000000000000000000000",
        headers={"Authorization": "Bearer scanner-token"},
    )

    assert status_response.status_code == 200
    body = status_response.json()
    assert body["review_id"] == review_id
    assert body["state"] == "completed"
    assert body["action"] == "allow"

    assert missing_response.status_code == 404
