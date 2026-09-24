"""Provider-neutral HTTP contract shared with SCM webhook adapters."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PolicyAction(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    INCOMPLETE = "incomplete"


class ReviewRequest(BaseModel):
    """Immutable review identity normalized by a provider adapter."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    provider: str = Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_-]*$")
    installation_id: int = Field(gt=0)
    repository_full_name: str = Field(
        min_length=3,
        max_length=255,
        pattern=r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$",
    )
    repository_id: int = Field(gt=0)
    review_number: int = Field(gt=0)
    base_sha: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")
    head_sha: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")
    base_ref: str = Field(min_length=1, max_length=255, pattern=r"^[^\x00-\x20\x7f]+$")
    head_ref: str = Field(min_length=1, max_length=255, pattern=r"^[^\x00-\x20\x7f]+$")
    delivery_id: str = Field(min_length=1, max_length=255, pattern=r"^[^\x00-\x20\x7f]+$")


class FindingEvidence(BaseModel):
    """One role-tagged piece of evidence backing a verified finding.

    `role` mirrors `plaidnox_scm.evidence.EvidenceRole` as a plain string so
    this HTTP contract does not depend on that internal enum type.
    """

    model_config = ConfigDict(extra="forbid")

    role: str
    source: str
    path: str
    start_line: int | None = None
    end_line: int | None = None
    summary: str


class ReviewFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    root_cause_fingerprint: str
    title: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    description: str
    impact: str | None = None
    root_cause_path: str
    root_cause_symbol: str
    root_cause_start_line: int = Field(gt=0)
    root_cause_end_line: int | None = Field(default=None, gt=0)
    root_cause_changed_in_pr: bool
    proof_of_concept: str | None = None
    remediation: str | None = None
    remediation_invariant: str | None = None
    proof_plan: str | None = None
    regression_test_expectation: str | None = None
    category: str | None = None
    baseline_relationship: str
    tenant_id: str
    repository_id: int
    base_revision: str
    head_revision: str
    attacker_origin: str | None = None
    security_boundary: str | None = None
    defense_removed_or_bypassed: str | None = None
    downstream_trust: str | None = None
    sensitive_effects: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    evidence: list[FindingEvidence] = Field(default_factory=list)
    context_facts: list[str] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    verified_at: datetime


class ReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_id: str
    head_sha: str
    action: PolicyAction
    summary: str
    findings: list[ReviewFinding] = Field(default_factory=list)
    incomplete_reason: str | None = None
    counters: dict[str, int] | None = None


class PromoteBaselineRequest(BaseModel):
    """Promotes a completed review's still-open findings into the persistent
    baseline once its pull/merge request has actually merged, so a later
    review against the new base revision sees them as already `existing`
    instead of re-flagging them as newly `introduced`.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    merge_revision: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")


class PromoteBaselineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_id: str
    codebase_id: str
    baseline_revision: str
    promoted_count: int


class TriageRequest(BaseModel):
    """One `!valid`/`!fp`/`!accepted_risk`/`!fixed` command, already parsed and
    already authorized by the provider bot -- this contract carries only the
    resulting command + actor identity, not the raw comment or webhook.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    command: str = Field(pattern=r"^(valid|fp|accepted_risk|fixed)$")
    actor: str = Field(min_length=1, max_length=255)
    reason: str | None = Field(default=None, max_length=4000)


class TriageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    review_id: str
    state: str
    previous_state: str
    actor: str | None = None
    reason: str | None = None
    applied: bool
    updated_at: datetime
    # The owning review's merge action re-evaluated with this triage applied;
    # absent when the review has not completed or ended INCOMPLETE.
    review_action: PolicyAction | None = None
    review_summary: str | None = None


class TriageStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    review_id: str
    state: str
    actor: str | None = None
    reason: str | None = None
    updated_at: datetime | None = None


class ReviewAttemptStatus(BaseModel):
    """Live status/counters for one review attempt (`GET /v1/reviews/{review_id}`)."""

    model_config = ConfigDict(extra="forbid")

    review_id: str
    state: str
    outcome: str | None = None
    action: str | None = None
    summary: str | None = None
    counters: dict[str, Any] | None = None
    attempt_count: int
    started_at: datetime
    completed_at: datetime | None = None
