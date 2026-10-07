"""Authenticated HTTP API consumed by provider webhook adapters."""

from __future__ import annotations

import hmac

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.concurrency import run_in_threadpool

from .api_models import (
    InstallationStatusUpdate,
    PromoteBaselineRequest,
    PromoteBaselineResponse,
    ReviewAttemptStatus,
    ReviewRequest,
    ReviewResponse,
    ReviewSupersededRequest,
    TriageRequest,
    TriageResponse,
    TriageStatus,
    WebhookDeliveryClaim,
)
from .api_service import ReviewNotCompletedError, ReviewService
from .attempts import ReviewAttemptConflictError, ReviewAttemptExhaustedError
from .source_broker import SourceBrokerError
from .triage import TriageConflictError, TriageReasonRequiredError


def create_app(service: ReviewService, *, api_token: str) -> FastAPI:
    expected_token = api_token.strip()
    if not expected_token:
        raise ValueError("A non-empty API token is required")

    app = FastAPI(title="PlaidNox SCM Review API", version="1.0.0")

    def authenticate(authorization: str | None = Header(default=None)) -> None:
        prefix = "Bearer "
        if authorization is None or not authorization.startswith(prefix):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token")
        supplied = authorization[len(prefix) :]
        if not hmac.compare_digest(supplied.encode(), expected_token.encode()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/webhook-deliveries/claim", dependencies=[Depends(authenticate)])
    async def claim_webhook_delivery(request: WebhookDeliveryClaim) -> dict[str, object]:
        try:
            accepted, tenant_id = await run_in_threadpool(
                service.claim_webhook_delivery,
                delivery_id=request.delivery_id,
                provider=request.provider,
                installation_id=request.installation_id,
                repository_id=request.repository_id,
                event_name=request.event_name,
                action=request.action,
                pull_number=request.pull_number,
                head_sha=request.head_sha,
            )
        except PermissionError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return {"accepted": accepted, "tenant_id": tenant_id}

    @app.post("/v1/webhook-deliveries/{delivery_id}/queued", dependencies=[Depends(authenticate)])
    async def mark_webhook_delivery_queued(delivery_id: str) -> dict[str, bool]:
        queued = await run_in_threadpool(service.mark_webhook_delivery_queued, delivery_id)
        if not queued:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="unknown delivery_id")
        return {"queued": True}

    @app.post("/v1/installations/status", dependencies=[Depends(authenticate)])
    async def update_installation_status(request: InstallationStatusUpdate) -> dict[str, bool]:
        updated = await run_in_threadpool(
            service.update_installation_status,
            provider=request.provider,
            installation_id=request.installation_id,
            active=request.active,
        )
        if not updated:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="unknown installation mapping")
        return {"updated": True}

    @app.post("/v1/reviews/superseded", dependencies=[Depends(authenticate)])
    async def record_review_superseded(request: ReviewSupersededRequest) -> dict[str, bool]:
        await run_in_threadpool(
            service.record_review_superseded,
            provider=request.provider,
            installation_id=request.installation_id,
            repository_id=request.repository_id,
            review_number=request.review_number,
            review_id=request.review_id,
            head_sha=request.head_sha,
        )
        return {"recorded": True}

    @app.post("/v1/reviews/failed", dependencies=[Depends(authenticate)])
    async def record_review_failed(request: ReviewRequest) -> dict[str, bool]:
        try:
            await run_in_threadpool(service.record_review_failed, request)
        except PermissionError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return {"recorded": True}

    @app.post(
        "/v1/reviews",
        response_model=ReviewResponse,
        dependencies=[Depends(authenticate)],
    )
    async def review(request: ReviewRequest) -> ReviewResponse:
        try:
            return await run_in_threadpool(service.run, request)
        except PermissionError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except SourceBrokerError as exc:
            raise HTTPException(status_code=status.HTTP_424_FAILED_DEPENDENCY, detail=str(exc)) from exc
        except (ReviewAttemptConflictError, ReviewAttemptExhaustedError) as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    @app.get(
        "/v1/reviews/{review_id}",
        response_model=ReviewAttemptStatus,
        dependencies=[Depends(authenticate)],
    )
    async def review_status(review_id: str) -> ReviewAttemptStatus:
        attempt_status = await run_in_threadpool(service.get_status, review_id)
        if attempt_status is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown review_id")
        return attempt_status

    @app.post(
        "/v1/reviews/{review_id}/promote",
        response_model=PromoteBaselineResponse,
        dependencies=[Depends(authenticate)],
    )
    async def promote_review(review_id: str, request: PromoteBaselineRequest) -> PromoteBaselineResponse:
        try:
            result = await run_in_threadpool(service.promote_to_baseline, review_id, request.merge_revision)
        except ReviewNotCompletedError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown review_id")
        return result

    @app.post(
        "/v1/reviews/{review_id}/findings/{finding_id}/triage",
        response_model=TriageResponse,
        dependencies=[Depends(authenticate)],
    )
    async def triage_finding(review_id: str, finding_id: str, request: TriageRequest) -> TriageResponse:
        try:
            result = await run_in_threadpool(
                service.apply_triage_command,
                review_id,
                finding_id,
                request.command,
                actor=request.actor,
                reason=request.reason,
            )
        except TriageReasonRequiredError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        except TriageConflictError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown review_id")
        return result

    @app.get(
        "/v1/reviews/{review_id}/findings/{finding_id}/triage",
        response_model=TriageStatus,
        dependencies=[Depends(authenticate)],
    )
    async def triage_status(review_id: str, finding_id: str) -> TriageStatus:
        result = await run_in_threadpool(service.get_triage, review_id, finding_id)
        if result is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown review_id")
        return result

    return app
