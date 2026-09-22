"""Thread-safe telemetry for prompt caching performed by LiteLLM."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Any


@dataclass(frozen=True, slots=True)
class LiteLLMCacheSnapshot:
    requests: int
    provider_cache_hits: int
    input_tokens: int
    cached_input_tokens: int

    def to_metrics(self) -> dict[str, int | float]:
        hit_rate = self.provider_cache_hits / self.requests if self.requests else 0.0
        token_reuse_rate = self.cached_input_tokens / self.input_tokens if self.input_tokens else 0.0
        return {
            "prompt_cache_requests": self.requests,
            "prompt_cache_hits": self.provider_cache_hits,
            "prompt_cache_hit_rate": round(hit_rate, 4),
            "prompt_cache_input_tokens": self.input_tokens,
            "prompt_cache_cached_tokens": self.cached_input_tokens,
            "prompt_cache_token_reuse_rate": round(token_reuse_rate, 4),
        }


class LiteLLMCacheTelemetry:
    """Observe LiteLLM/provider cache use without caching security decisions locally."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._requests = 0
        self._hits = 0
        self._input_tokens = 0
        self._cached_tokens = 0

    def record_response(self, response: Any) -> None:
        usage = getattr(response, "usage", None)
        input_tokens = _integer_attribute(usage, "input_tokens", "prompt_tokens")
        details = getattr(usage, "input_tokens_details", None) if usage is not None else None
        if details is None and isinstance(usage, dict):
            details = usage.get("input_tokens_details")
        cached_tokens = _integer_attribute(details, "cached_tokens", "cache_read_input_tokens")
        with self._lock:
            self._requests += 1
            self._input_tokens += input_tokens
            self._cached_tokens += cached_tokens
            if cached_tokens > 0:
                self._hits += 1

    def snapshot(self) -> LiteLLMCacheSnapshot:
        with self._lock:
            return LiteLLMCacheSnapshot(
                self._requests,
                self._hits,
                self._input_tokens,
                self._cached_tokens,
            )


def _integer_attribute(value: Any, *names: str) -> int:
    if value is None:
        return 0
    for name in names:
        raw = getattr(value, name, None)
        if raw is None and isinstance(value, dict):
            raw = value.get(name)
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                continue
    return 0
