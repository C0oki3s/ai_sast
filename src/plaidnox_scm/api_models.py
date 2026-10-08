"""Provider-neutral HTTP contract shared with SCM webhook adapters."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_serializer


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
    # Short-lived, installation-scoped S3 URL uploaded by the trusted GitHub bot.
    source_bundle_url: str | None = Field(default=None, max_length=4096)
    # Pull request author (provider login). Optional: stored for the dashboard only.
    author_login: str | None = Field(default=None, min_length=1, max_length=255, pattern=r"^[^\x00-\x20\x7f]+$")


class WebhookDeliveryClaim(BaseModel):
    """Verified GitHub delivery identity forwarded by the webhook adapter."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    delivery_id: str = Field(min_length=1, max_length=255)
    provider: str = Field(default="github", min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_-]*$")
    installation_id: int = Field(gt=0)
    repository_id: int = Field(gt=0)
    event_name: str = Field(min_length=1, max_length=64)
    action: str | None = Field(default=None, max_length=64)
    pull_number: int | None = Field(default=None, gt=0)
    head_sha: str | None = Field(default=None, min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")


class InstallationStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    provider: str = Field(default="github", min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_-]*$")
    installation_id: int = Field(gt=0)
    active: bool


class ReviewSupersededRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    provider: str = Field(default="github", min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_-]*$")
    installation_id: int = Field(gt=0)
    repository_id: int = Field(gt=0)
    review_number: int = Field(gt=0)
    review_id: str = Field(min_length=1, max_length=64)
    head_sha: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")


class FindingEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str
    source: str
    path: str
    start_line: int | None = None
    end_line: int | None = None
    summary: str


class FindingRootCause(BaseModel):
    """Provider-neutral root-cause anchor on the immutable reviewed revision."""

    model_config = ConfigDict(extra="forbid")

    path: str
    symbol: str
    start_line: int = Field(gt=0)
    end_line: int | None = Field(default=None, gt=0)
    changed_in_pr: bool


class VulnerableSnippet(BaseModel):
    """Redacted root-cause code range captured from the reviewed head revision."""

    model_config = ConfigDict(extra="forbid")

    path: str
    start_line: int = Field(gt=0)
    end_line: int = Field(gt=0)
    code: str
    # Kept for one compatibility window with the first trace-contract draft.
    content: str | None = None


class FindingTraceNode(BaseModel):
    """One machine-validated source/propagation/boundary/sink node."""

    model_config = ConfigDict(extra="forbid")

    node_id: str
    role: str
    kind: str
    path: str
    start_line: int | None = None
    end_line: int | None = None
    symbol: str
    expression: str
    label: str
    summary: str
    provenance: str
    # Redacted code window around the node, stored so the trace can be rendered
    # without the repository. Absent on findings verified before it was captured.
    code: str | None = None
    code_start_line: int | None = Field(default=None, gt=0)
    code_end_line: int | None = Field(default=None, gt=0)
    # 1-based position in the attack path; absent on traces built before it existed.
    step: int | None = Field(default=None, gt=0)

    @model_serializer(mode="wrap")
    def _serialize(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        for field_name in ("code", "code_start_line", "code_end_line", "step"):
            if getattr(self, field_name) is None:
                data.pop(field_name, None)
        return data


class FindingTraceEdge(BaseModel):
    """One machine-supported relationship between verified trace nodes."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    relation: str
    via: str


class FindingTrace(BaseModel):
    """Provider-neutral branching taint + trust graph for one verified finding."""

    model_config = ConfigDict(extra="forbid")

    trace_type: str = "taint_and_trust"
    step_count: int = Field(ge=0)
    file_count: int = Field(ge=0)
    nodes: list[FindingTraceNode] = Field(default_factory=list)
    edges: list[FindingTraceEdge] = Field(default_factory=list)
    entry_nodes: list[str] = Field(default_factory=list)
    terminal_nodes: list[str] = Field(default_factory=list)
    attack_path: str
    gained_capability: str
    complete: bool = True
    evidence_gaps: list[str] = Field(default_factory=list)


class FindingReproduction(BaseModel):
    """Verifier-produced proof/remediation expectations; never an invented exploit recipe."""

    model_config = ConfigDict(extra="forbid")

    proof_plan: str | None = None
    regression_test_expectation: str | None = None


class ClassificationReference(BaseModel):
    """CWE / OWASP / CAPEC style reference the verifier attached to the finding."""

    model_config = ConfigDict(extra="forbid")

    namespace: str
    identifier: str
    name: str | None = None
    source_url: str | None = None


class ReviewFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    root_cause_fingerprint: str
    title: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    description: str
    impact: str | None = None

    # Flat fields stay for current bot compatibility. `root_cause` is the
    # canonical grouped representation new consumers should prefer.
    root_cause_path: str
    root_cause_symbol: str
    root_cause_start_line: int = Field(gt=0)
    root_cause_end_line: int | None = Field(default=None, gt=0)
    root_cause_changed_in_pr: bool
    root_cause: FindingRootCause | None = None

    vulnerable_snippet: VulnerableSnippet | None = None
    evidence_trace: FindingTrace | None = None
    attack_path: str | None = None
    security_invariant: str | None = None
    gained_capability: str | None = None
    reproduction: FindingReproduction | None = None

    # Display-ready reproduction: numbered steps plus one runnable script when the
    # verifier produced it. Always present on a verified finding that has a proof plan.
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
    classification_references: list[ClassificationReference] = Field(default_factory=list)
    # "carried_forward": verified on an earlier commit of this PR and its code is unchanged
    # (or could not be re-verified), so it is still reported. Absent for fresh results.
    lifecycle: str | None = None
    verified_at: datetime

    @model_serializer(mode="wrap")
    def _serialize(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        # Old persisted findings and old bot versions remain valid. New grouped
        # fields are emitted only when the verifier actually produced them.
        for field_name in (
            "root_cause",
            "vulnerable_snippet",
            "evidence_trace",
            "attack_path",
            "security_invariant",
            "gained_capability",
            "reproduction",
            "lifecycle",
        ):
            if getattr(self, field_name) is None:
                data.pop(field_name, None)
        if not self.classification_references:
            data.pop("classification_references", None)
        return data


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
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    merge_revision: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")


class PromoteBaselineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_id: str
    codebase_id: str
    baseline_revision: str
    promoted_count: int


class TriageRequest(BaseModel):
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
