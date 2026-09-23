"""SQLAlchemy engine and session configuration for Code Scanning."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from sqlalchemy import URL, Engine, create_engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from ..assets import load_json


class DatabaseConfigurationError(RuntimeError):
    """Raised when the production database configuration is missing or unsafe."""


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    url: URL
    pool_size: int
    max_overflow: int
    pool_timeout_seconds: int
    pool_recycle_seconds: int
    statement_timeout_milliseconds: int
    application_name: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> DatabaseSettings:
        runtime = load_json("runtime/database.json")
        values = environment if environment is not None else os.environ
        variable = str(runtime["url_environment_variable"])
        raw_url = values.get(variable, "").strip()
        if not raw_url:
            raise DatabaseConfigurationError(f"{variable} is required for production persistence")
        url = make_url(raw_url)
        allowed = {str(driver) for driver in runtime["allowed_production_drivers"]}
        if url.drivername not in allowed:
            raise DatabaseConfigurationError(
                f"Unsupported production database driver {url.drivername!r}; expected one of {sorted(allowed)}"
            )
        if not url.database:
            raise DatabaseConfigurationError("The production database URL must name a database")
        production_mode = values.get(str(runtime["production_mode_environment_variable"]), "").strip().lower()
        if production_mode in {"1", "true", "yes", "on"} and bool(runtime["require_tls_in_production"]):
            ssl_mode = str(dict(url.query).get("sslmode", "")).lower()
            accepted = {str(mode) for mode in runtime["accepted_tls_modes"]}
            if ssl_mode not in accepted:
                raise DatabaseConfigurationError(
                    "Production PostgreSQL requires sslmode=require, verify-ca, or verify-full"
                )
        return cls(
            url=url,
            pool_size=int(runtime["pool_size"]),
            max_overflow=int(runtime["max_overflow"]),
            pool_timeout_seconds=int(runtime["pool_timeout_seconds"]),
            pool_recycle_seconds=int(runtime["pool_recycle_seconds"]),
            statement_timeout_milliseconds=int(runtime["statement_timeout_milliseconds"]),
            application_name=str(runtime["application_name"]),
        )

    @property
    def redacted_url(self) -> str:
        return self.url.render_as_string(hide_password=True)

    def create_engine(self) -> Engine:
        connect_args = {
            "options": (
                f"-c statement_timeout={self.statement_timeout_milliseconds} "
                f"-c application_name={self.application_name}"
            )
        }
        return create_engine(
            self.url,
            pool_pre_ping=True,
            pool_size=self.pool_size,
            max_overflow=self.max_overflow,
            pool_timeout=self.pool_timeout_seconds,
            pool_recycle=self.pool_recycle_seconds,
            connect_args=connect_args,
        )


def session_factory(settings: DatabaseSettings) -> sessionmaker[Session]:
    """Create explicit transaction-scoped sessions without global mutable state."""

    return sessionmaker(bind=settings.create_engine(), class_=Session, expire_on_commit=False, autoflush=False)
