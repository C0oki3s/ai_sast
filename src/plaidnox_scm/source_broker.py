"""Source-materialization boundary for provider-neutral SCM reviews.

The GitHub bot owns installation authentication and webhook processing. This
package consumes repositories already synchronized by an internal source
broker or mirror service and never calls a provider API directly.
"""

from __future__ import annotations

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
    """Read exact revisions from a provider/repository-ID keyed mirror root."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    @contextmanager
    def materialize(self, request: ReviewRequest) -> Iterator[RepositorySource]:
        repository = (self._root / request.provider / str(request.repository_id)).resolve()
        if self._root not in repository.parents:
            raise SourceBrokerError("Repository mirror path escapes the configured root")
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
        yield RepositorySource(repository, base_revision, head_revision)
