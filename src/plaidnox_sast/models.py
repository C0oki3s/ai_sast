from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ScanMode(StrEnum):
    DEEP = "deep"


class Depth(StrEnum):
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


class ModelTier(StrEnum):
    """Stable, provider-independent execution classes selected by the router."""

    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


class FindingState(StrEnum):
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    VERIFIED = "verified"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    DUPLICATE = "duplicate"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyDecision(StrEnum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"
    INCOMPLETE = "incomplete"


class ScanStatus(StrEnum):
    SUCCESSFUL = "SUCCESSFUL"
    UNSUCCESSFUL = "UNSUCCESSFUL"


@dataclass(slots=True)
class Evidence:
    path: str
    start_line: int
    end_line: int
    snippet: str = ""
    source_symbol: str = ""
    sink_symbol: str = ""
    graph_path: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Candidate:
    rule_id: str
    title: str
    vulnerability_class: str
    severity: Severity
    confidence: float
    message: str
    evidence: Evidence
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CandidateEvidencePacket:
    """Canonical, bounded evidence handed from discovery to independent verification."""

    candidate_id: str
    root_cause: dict[str, Any]
    attacker_origins: list[str]
    security_boundary: list[str]
    invariant: str
    downstream_trust: list[dict[str, Any]]
    sensitive_effects: list[str]
    gained_capabilities: list[str]
    trace_nodes: list[str]
    trace_edges: list[dict[str, str]]
    evidence_gaps: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    fingerprint: str
    repository: str
    rule_id: str
    title: str
    vulnerability_class: str
    severity: Severity
    confidence: float
    state: FindingState
    message: str
    impact: str
    remediation: str
    evidence: Evidence
    priority_score: int
    validator: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RouteDecision:
    """The deterministic routing verdict: how deep, and along which independent evidence axes.

    ``needs_*`` fields are NOUL choices (no/unlikely/likely/yes) rather than one
    mutually exclusive profile, since more than one axis is routinely relevant
    at once. ``analysis_complexity`` is a 1-5 score used to scale execution
    budget (context-expansion round size, reasoning effort) independently of
    ``depth``, which only selects the model tier.
    """

    depth: Depth
    reason: str
    task_class: str = "generic"
    model_tier: ModelTier = ModelTier.STANDARD
    needs_validation: bool = True
    needs_deep_hunt: bool = True
    needs_cross_file: str = "unlikely"
    needs_state_reconstruction: str = "unlikely"
    needs_external_semantics: str = "unlikely"
    needs_environment_context: str = "unlikely"
    needs_deep_falsification: str = "unlikely"
    analysis_complexity: int = 2


@dataclass(slots=True)
class PolicyResult:
    decision: PolicyDecision
    reasons: list[str]


@dataclass(slots=True)
class ScanResult:
    codebase: str
    revision: str
    mode: ScanMode
    findings: list[Finding]
    policy: PolicyResult
    metrics: dict[str, Any]
    repository_context: dict[str, Any] = field(default_factory=dict)

    @property
    def scan_status(self) -> ScanStatus:
        required_failures = (
            "ai_context_failures",
            "ai_planning_failures",
            "ai_discovery_failures",
            "ai_review_failures",
            "ai_variant_failures",
            "ai_capability_chain_failures",
            "ai_consolidation_failures",
            "ai_discovery_unresolved_obligations",
            "ai_discovery_contract_failures",
            "ai_search_query_failures",
            "checkpoint_units_pending",
        )
        incomplete = bool(self.metrics.get("ai_scan_incomplete", False))
        incomplete = incomplete or any(int(self.metrics.get(key, 0) or 0) > 0 for key in required_failures)
        return ScanStatus.UNSUCCESSFUL if incomplete else ScanStatus.SUCCESSFUL

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("policy", None)
        value["scan_status"] = self.scan_status.value
        value["findings_summary"] = {
            "total": len(self.findings),
            **{
                severity.value: sum(finding.severity is severity for finding in self.findings)
                for severity in Severity
            },
        }
        return value
