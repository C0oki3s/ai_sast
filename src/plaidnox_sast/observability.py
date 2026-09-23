"""Optional OpenTelemetry boundary with privacy-safe scan attributes."""

from __future__ import annotations

import hashlib
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator


class ObservabilityConfigurationError(RuntimeError):
    pass


@dataclass(slots=True)
class ScanTelemetry:
    enabled: bool
    tracer: Any = None
    meter: Any = None

    @classmethod
    def from_environment(cls) -> ScanTelemetry:
        enabled = os.environ.get("PLAIDNOX_OTEL_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
        if not enabled:
            return cls(False)
        try:
            from opentelemetry import metrics, trace
        except ImportError as exc:
            raise ObservabilityConfigurationError(
                "OpenTelemetry is enabled but the observability extra is not installed"
            ) from exc
        return cls(True, trace.get_tracer("plaidnox.code_scanning"), metrics.get_meter("plaidnox.code_scanning"))

    @contextmanager
    def scan(self, codebase: str, revision: str | None) -> Iterator[None]:
        if not self.enabled:
            yield
            return
        attributes = {
            "plaidnox.codebase_hash": _digest(codebase),
            "plaidnox.revision_hash": _digest(revision or "content-derived"),
        }
        started = time.monotonic()
        with self.tracer.start_as_current_span("code_scanning.scan", attributes=attributes) as span:
            try:
                yield
            except BaseException as exc:
                span.set_attribute("plaidnox.outcome", "error")
                span.set_attribute("error.type", type(exc).__name__)
                raise
            finally:
                duration = time.monotonic() - started
                self.meter.create_histogram("plaidnox.code_scanning.duration", unit="s").record(duration, attributes)

    def record_result(self, result: Any) -> None:
        if not self.enabled:
            return
        attributes = {"plaidnox.decision": str(result.policy.decision)}
        self.meter.create_counter("plaidnox.code_scanning.scans").add(1, attributes)
        self.meter.create_counter("plaidnox.code_scanning.findings").add(len(result.findings), attributes)
        metrics = result.metrics
        self.meter.create_counter("plaidnox.code_scanning.model_input_tokens").add(
            int(metrics.get("model_budget_input_tokens", 0)), attributes
        )
        self.meter.create_counter("plaidnox.code_scanning.model_output_tokens").add(
            int(metrics.get("model_budget_output_tokens", 0)), attributes
        )
        self.meter.create_histogram("plaidnox.code_scanning.model_cost", unit="USD").record(
            float(metrics.get("model_budget_cost_usd", 0.0)), attributes
        )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
