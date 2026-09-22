from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from .models import Finding, PolicyDecision


class ReviewProvider(StrEnum):
    GITHUB = "github"
    GITLAB = "gitlab"


class ReviewFindingChange(StrEnum):
    INTRODUCED = "introduced"
    REGRESSED = "regressed"
    MODIFIED_EXISTING = "modified_existing"
    EXISTING = "existing"
    RESOLVED = "resolved"


class ReviewDepth(StrEnum):
    L0_DETERMINISTIC = "l0_deterministic"
    L1_CONTEXTUAL = "l1_contextual"
    L2_DEEP = "l2_deep"
    L3_WHITEBOX = "l3_whitebox"


@dataclass(slots=True)
class ChangeSurface:
    changed_paths: list[str] = field(default_factory=list)
    changed_symbols: list[str] = field(default_factory=list)
    affected_callers: list[str] = field(default_factory=list)
    affected_callees: list[str] = field(default_factory=list)
    affected_auth_controls: list[str] = field(default_factory=list)
    affected_authorization_decisions: list[str] = field(default_factory=list)
    affected_store_readers: list[str] = field(default_factory=list)
    affected_store_writers: list[str] = field(default_factory=list)
    affected_sensitive_effects: list[str] = field(default_factory=list)
    affected_trust_boundaries: list[str] = field(default_factory=list)
    sensitive_evidence_refs: list[str] = field(default_factory=list)
    truncated: bool = False
    unresolved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PullRequestReviewRequest:
    tenant_id: str
    provider: ReviewProvider
    repository: str
    repository_id: str
    review_id: str
    base_revision: str
    head_revision: str
    target_branch: str
    source_branch: str = ""
    merge_queue: bool = False

    @property
    def workflow_key(self) -> str:
        """Stable key used for coalescing/superseding older HEAD revisions."""

        return ":".join(
            (
                self.tenant_id,
                self.provider.value,
                self.repository_id,
                self.review_id,
            )
        )


@dataclass(slots=True)
class ReviewFinding:
    finding: Finding
    change: ReviewFindingChange
    introduced_by_paths: list[str] = field(default_factory=list)
    baseline_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding.to_dict(),
            "change": self.change.value,
            "introduced_by_paths": list(self.introduced_by_paths),
            "baseline_fingerprint": self.baseline_fingerprint,
        }


@dataclass(slots=True)
class PullRequestReviewResult:
    request: PullRequestReviewRequest
    depth: ReviewDepth
    change_surface: ChangeSurface
    findings: list[ReviewFinding]
    policy_decision: PolicyDecision
    policy_reasons: list[str]
    baseline_revision: str
    current_head_revision: str
    complete: bool
    incomplete_reasons: list[str] = field(default_factory=list)

    @property
    def publishable(self) -> bool:
        """A stale or incomplete result must never be treated as a clean merge check."""

        return (
            self.complete
            and self.request.head_revision == self.current_head_revision
            and self.policy_decision is not PolicyDecision.INCOMPLETE
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": asdict(self.request),
            "depth": self.depth.value,
            "change_surface": self.change_surface.to_dict(),
            "findings": [item.to_dict() for item in self.findings],
            "policy_decision": self.policy_decision.value,
            "policy_reasons": list(self.policy_reasons),
            "baseline_revision": self.baseline_revision,
            "current_head_revision": self.current_head_revision,
            "complete": self.complete,
            "incomplete_reasons": list(self.incomplete_reasons),
            "publishable": self.publishable,
        }
