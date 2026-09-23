"""Production runtime limits for generative model execution."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from .assets import load_json
from .errors import AIStageError


class ModelBudgetExceeded(AIStageError):
    """Raised when a scan would exceed an externally versioned model limit."""


@dataclass(frozen=True, slots=True)
class ModelReservation:
    model: str
    input_characters: int
    requested_output_tokens: int


class ModelUsageBudget:
    """Thread-safe scan budget shared by detection, verification, and research."""

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        configured = policy or load_json("runtime/production_controls.json")["model_budget"]
        self.maximum_calls = int(configured["maximum_calls_per_scan"])
        self.maximum_inflight = int(configured["maximum_inflight_calls"])
        self.maximum_input_characters = int(configured["maximum_input_characters_per_scan"])
        self.maximum_requested_output_tokens = int(configured["maximum_requested_output_tokens_per_scan"])
        self.maximum_cost_usd = float(configured["maximum_cost_usd_per_scan"])
        self.maximum_cost_by_model = {
            str(model): float(limit) for model, limit in configured.get("maximum_cost_usd_by_model", {}).items()
        }
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "_lock", threading.Lock()):
            self._calls = 0
            self._inflight = 0
            self._input_characters = 0
            self._requested_output_tokens = 0
            self._input_tokens = 0
            self._output_tokens = 0
            self._cost_usd = 0.0
            self._cost_by_model: dict[str, float] = {}
            self._tokens_by_model: dict[str, tuple[int, int]] = {}

    def reserve(self, model: str, input_characters: int, requested_output_tokens: int | None) -> ModelReservation:
        reservation = ModelReservation(model, max(0, input_characters), max(0, requested_output_tokens or 0))
        with self._lock:
            if self._calls + 1 > self.maximum_calls:
                raise ModelBudgetExceeded("scan model-call limit exceeded")
            if self._inflight + 1 > self.maximum_inflight:
                raise ModelBudgetExceeded("scan concurrent model-call limit exceeded")
            if self._input_characters + reservation.input_characters > self.maximum_input_characters:
                raise ModelBudgetExceeded("scan model-input character limit exceeded")
            if (
                self._requested_output_tokens + reservation.requested_output_tokens
                > self.maximum_requested_output_tokens
            ):
                raise ModelBudgetExceeded("scan requested output-token limit exceeded")
            self._calls += 1
            self._inflight += 1
            self._input_characters += reservation.input_characters
            self._requested_output_tokens += reservation.requested_output_tokens
        return reservation

    def cancel(self, reservation: ModelReservation) -> None:
        with self._lock:
            self._inflight = max(0, self._inflight - 1)

    def complete(self, reservation: ModelReservation, response: Any) -> None:
        input_tokens, output_tokens = _response_tokens(response)
        cost = _response_cost(response)
        with self._lock:
            self._inflight = max(0, self._inflight - 1)
            self._input_tokens += input_tokens
            self._output_tokens += output_tokens
            self._cost_usd += cost
            self._cost_by_model[reservation.model] = self._cost_by_model.get(reservation.model, 0.0) + cost
            prior_input, prior_output = self._tokens_by_model.get(reservation.model, (0, 0))
            self._tokens_by_model[reservation.model] = (prior_input + input_tokens, prior_output + output_tokens)
            total_exceeded = self._cost_usd > self.maximum_cost_usd
            model_limit = self.maximum_cost_by_model.get(reservation.model)
            model_exceeded = model_limit is not None and self._cost_by_model[reservation.model] > model_limit
        if total_exceeded:
            raise ModelBudgetExceeded("scan model-cost limit exceeded")
        if model_exceeded:
            raise ModelBudgetExceeded(f"scan model-cost limit exceeded for {reservation.model}")

    def usage_by_model(self) -> dict[str, tuple[int, int, float]]:
        """(input_tokens, output_tokens, cost_usd) per model, for durable usage records."""

        with self._lock:
            return {
                model: (*self._tokens_by_model.get(model, (0, 0)), cost)
                for model, cost in self._cost_by_model.items()
            }

    def metrics(self) -> dict[str, int | float]:
        with self._lock:
            return {
                "model_budget_calls": self._calls,
                "model_budget_inflight": self._inflight,
                "model_budget_input_characters": self._input_characters,
                "model_budget_requested_output_tokens": self._requested_output_tokens,
                "model_budget_input_tokens": self._input_tokens,
                "model_budget_output_tokens": self._output_tokens,
                "model_budget_cost_usd": round(self._cost_usd, 8),
            }


def _response_tokens(response: Any) -> tuple[int, int]:
    usage = getattr(response, "usage", None) or {}
    return (
        _integer(usage, "input_tokens", "prompt_tokens"),
        _integer(usage, "output_tokens", "completion_tokens"),
    )


def _response_cost(response: Any) -> float:
    containers = [
        getattr(response, "_hidden_params", None),
        getattr(response, "model_extra", None),
        response if isinstance(response, dict) else None,
    ]
    for container in containers:
        if not container:
            continue
        value = container.get("response_cost") if isinstance(container, dict) else None
        if value is None and isinstance(container, dict):
            value = container.get("cost")
        try:
            if value is not None:
                return max(0.0, float(value))
        except (TypeError, ValueError):
            continue
    return 0.0


def _integer(value: Any, *names: str) -> int:
    for name in names:
        raw = value.get(name) if isinstance(value, dict) else getattr(value, name, None)
        try:
            if raw is not None:
                return max(0, int(raw))
        except (TypeError, ValueError):
            continue
    return 0
