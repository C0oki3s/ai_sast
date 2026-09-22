from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ScanMode(StrEnum):
    DEEP = "deep"
    PULL_REQUEST = "pull_request"
    MERGE_REQUEST = "merge_request"
    BOOTSTRAP = "bootstrap"


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
    depth: Depth
    profile: str
    reason: str
    task_class: str = "generic"
    model_tier: ModelTier = ModelTier.STANDARD
    needs_validation: bool = True
    needs_deep_hunt: bool = True


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
