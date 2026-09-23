"""Source-materialization boundary for provider-neutral SCM reviews.

The GitHub bot owns installation authentication and webhook processing. This
package consumes repositories already synchronized by an internal source
broker or mirror service and never calls a provider API directly.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .api_models import ReviewRequest
from .snapshots import SnapshotError, resolve_revision


class SourceBrokerError(RuntimeError):
    """Raised when the requested immutable revisions cannot be materialized."""


@dataclass(frozen=True, slots=True)
class RepositorySource:
    repo_path: Path
    base_revision: str
    head_revision: str


class SourceBroker(Protocol):
    def materialize(self, request: ReviewRequest) -> AbstractContextManager[RepositorySource]: ...


class RepositoryMirrorBroker:
    """Read exact revisions from a provider/repository-ID keyed mirror root.

    `sync_retry_attempts` defaults to 1 (no retry) so every existing caller
    that constructs this with just a root keeps its exact prior behavior --
    production wiring opts into retrying by passing a larger budget
    explicitly (see `api_main.py`).
    """

    def __init__(
        self,
        root: Path,
        *,
        sync_retry_attempts: int = 1,
        sync_retry_interval_seconds: float = 1.0,
    ) -> None:
        self._root = root.resolve()
        self._sync_retry_attempts = max(1, sync_retry_attempts)
        self._sync_retry_interval_seconds = sync_retry_interval_seconds

    @contextmanager
    def materialize(self, request: ReviewRequest) -> Iterator[RepositorySource]:
        repository = (self._root / request.provider / str(request.repository_id)).resolve()
        if self._root not in repository.parents:
            raise SourceBrokerError("Repository mirror path escapes the configured root")
        base_revision, head_revision = self._resolve_with_retry(repository, request)
        yield RepositorySource(repository, base_revision, head_revision)

    def _resolve_with_retry(self, repository: Path, request: ReviewRequest) -> tuple[str, str]:
        """Tolerates a race between webhook delivery and out-of-band mirror sync.

        A repository the mirror service has never synced before, or a head
        commit pushed moments before the webhook fired, may not have landed
        on disk yet when this request arrives. This retries the same local
        read a bounded number of times instead of failing the review on the
        very first check -- it never calls a provider API, only re-reads
        the filesystem this broker was already pointed at.
        """

        last_error: SourceBrokerError | None = None
        for attempt in range(self._sync_retry_attempts):
            if attempt:
                time.sleep(self._sync_retry_interval_seconds)
            try:
                return self._resolve_once(repository, request)
            except SourceBrokerError as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def _resolve_once(self, repository: Path, request: ReviewRequest) -> tuple[str, str]:
        if not repository.is_dir():
            raise SourceBrokerError("Repository mirror is not available for this review")
        try:
            base_revision = resolve_revision(repository, request.base_sha)
            head_revision = resolve_revision(repository, request.head_sha)
        except SnapshotError as exc:
            raise SourceBrokerError("Repository mirror does not contain the requested revisions") from exc
        if base_revision.lower() != request.base_sha.lower():
            raise SourceBrokerError("Materialized base revision differs from the requested immutable SHA")
        if head_revision.lower() != request.head_sha.lower():
            raise SourceBrokerError("Materialized head revision differs from the requested immutable SHA")
        return base_revision, head_revision
