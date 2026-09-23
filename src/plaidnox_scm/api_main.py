"""Production entrypoint for the provider-neutral SCM Review API."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from sqlalchemy.orm import Session, sessionmaker

from plaidnox_sast.persistence import DatabaseSettings

from .api import create_app
from .api_service import ReviewService
from .assets import load_json
from .production import dependencies_from_environment
from .source_broker import RepositoryMirrorBroker


def build_app():
    api_token = _required_environment("PLAIDNOX_SCM_API_TOKEN")
    mirror_root = Path(_required_environment("PLAIDNOX_SCM_REPOSITORY_ROOT"))
    database = DatabaseSettings.from_environment()
    factory = sessionmaker(
        bind=database.create_engine(),
        class_=Session,
        expire_on_commit=False,
        autoflush=False,
    )
    runtime = load_json("runtime/review.json")
    service = ReviewService(
        source_broker=RepositoryMirrorBroker(
            mirror_root,
            sync_retry_attempts=int(runtime["mirror_sync_retry_attempts"]),
            sync_retry_interval_seconds=float(runtime["mirror_sync_retry_interval_seconds"]),
        ),
        session_factory=factory,
        dependencies_factory=dependencies_from_environment,
    )
    return create_app(service, api_token=api_token)


def main() -> None:
    uvicorn.run(
        build_app(),
        host=os.environ.get("PLAIDNOX_SCM_API_HOST", "0.0.0.0"),
        port=int(os.environ.get("PLAIDNOX_SCM_API_PORT", "9000")),
        proxy_headers=True,
    )


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


if __name__ == "__main__":
    main()
