"""Provider-neutral HTTP contract shared with SCM webhook adapters."""

from __future__ import annotations

from enum import StrEnum

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


class ReviewFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    description: str
    root_cause_path: str
    root_cause_start_line: int = Field(gt=0)
    root_cause_end_line: int | None = Field(default=None, gt=0)
    root_cause_changed_in_pr: bool
    proof_of_concept: str | None = None
    remediation: str | None = None
    category: str | None = None
    baseline_relationship: str


class ReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_id: str
    head_sha: str
    action: PolicyAction
    summary: str
    findings: list[ReviewFinding] = Field(default_factory=list)
    incomplete_reason: str | None = None
