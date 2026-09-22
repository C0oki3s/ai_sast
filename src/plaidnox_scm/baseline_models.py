"""Provider-neutral baseline finding values owned by SCM Integration."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BaselineFinding:
    """One independently verified finding at an immutable base revision."""

    codebase_id: str
    baseline_revision: str
    root_cause_fingerprint: str
    finding_fingerprint: str
    lifecycle_state: str
    root_cause_path: str
    root_cause_symbol: str
    vulnerability_class: str
    title: str
    severity: str
    confidence: float
