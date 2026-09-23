"""Authenticated HTTP API consumed by provider webhook adapters."""

from __future__ import annotations

import hmac

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.concurrency import run_in_threadpool

from .api_models import (
    PromoteBaselineRequest,
    PromoteBaselineResponse,
    ReviewAttemptStatus,
    ReviewRequest,
    ReviewResponse,
)
from .api_service import ReviewNotCompletedError, ReviewService
from .attempts import ReviewAttemptConflictError, ReviewAttemptExhaustedError
from .source_broker import SourceBrokerError


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

    @app.post(
        "/v1/reviews",
        response_model=ReviewResponse,
        dependencies=[Depends(authenticate)],
    )
    async def review(request: ReviewRequest) -> ReviewResponse:
        try:
            return await run_in_threadpool(service.run, request)
        except SourceBrokerError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
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

    return app
