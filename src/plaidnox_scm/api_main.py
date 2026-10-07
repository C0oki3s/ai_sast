"""Production entrypoint for the provider-neutral SCM Review API."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from sqlalchemy.orm import Session, sessionmaker

from plaidnox_sast.persistence import DatabaseSettings

from .api import create_app
from .api_service import ReviewService
from .assets import load_json, load_text
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
            source_bundle_bucket=os.environ.get("PLAIDNOX_SCM_BUNDLE_BUCKET") or None,
            source_bundle_region=os.environ.get("PLAIDNOX_SCM_BUNDLE_REGION", os.environ.get("AWS_REGION", "us-east-1")),
        ),
        session_factory=factory,
        dependencies_factory=dependencies_from_environment,
    )
    return create_app(service, api_token=api_token)


def main() -> None:
    if os.environ.get("PLAIDNOX_SCM_MIGRATE_ONLY", "").strip().lower() == "true":
        _apply_deployment_migrations()
        return

    uvicorn.run(
        build_app(),
        host=os.environ.get("PLAIDNOX_SCM_API_HOST", "0.0.0.0"),
        port=int(os.environ.get("PLAIDNOX_SCM_API_PORT", "9000")),
        proxy_headers=True,
    )


# Idempotent SCM migrations applied by the one-off deployment task, in order.
DEPLOYMENT_MIGRATIONS = (
    "0008_scm_review_attempt_pr_metadata",
    "0009_scm_finding_occurrences",
)


def _apply_deployment_migrations() -> None:
    """Apply the pending idempotent SCM schema migrations in a one-off ECS task."""
    engine = DatabaseSettings.from_environment().create_engine()
    for name in DEPLOYMENT_MIGRATIONS:
        migration = load_text(f"migrations/postgresql/{name}.sql")
        with engine.begin() as connection:
            connection.exec_driver_sql(migration)
        print(f"Applied SCM migration {name}", flush=True)


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


if __name__ == "__main__":
    main()
