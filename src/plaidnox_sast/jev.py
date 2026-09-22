from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .assets import load_json
from .models import Candidate, Depth, ModelTier, RouteDecision, Severity


class JevError(RuntimeError):
    pass


@dataclass(slots=True)
class JevAnswer:
    choice: str
    confidence: float
    model: str


class JevClient:
    """Client for TypeSafe's System One structured-decision API."""

    def __init__(
        self,
        api_key: str,
        endpoint: str | None = None,
        model: str | None = None,
    ) -> None:
        runtime = load_json("runtime/jev.json")
        self.api_key = api_key
        endpoint_variable = str(runtime["endpoint_environment_variable"])
        self.endpoint = endpoint or os.environ.get(endpoint_variable) or str(runtime["default_endpoint"])
        self.request_timeout_seconds = int(runtime["request_timeout_seconds"])
        self.model = model or str(load_json("runtime/models.json")["jev_default_model"])

    @classmethod
    def from_environment(
        cls,
        model: str | None = None,
    ) -> "JevClient":
        api_key = os.environ.get("JEV_API_KEY")
        if not api_key:
            raise JevError("JEV_API_KEY is required when --jev is enabled")
        return cls(api_key, model=model)

    def decide_questions(self, state: dict[str, Any], routing_asset: str) -> dict[str, JevAnswer]:
        routing = load_json(routing_asset)
        payload = {
            "model": self.model,
            "state": state,
            "questions": routing["questions"],
        }
        data = self._request(payload)
        raw_answers = data.get("answers", {})
        try:
            return {
                name: JevAnswer(
                    str(raw_answers[name]["choice"]),
                    float(raw_answers[name]["confidence"]),
                    str(data.get("model", self.model)),
                )
                for name in routing["questions"]
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise JevError("JEV routing response did not match the expected choice schema") from exc

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.request_timeout_seconds) as response:  # noqa: S310
                data = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise JevError("JEV routing request failed") from exc
        if not isinstance(data, dict):
            raise JevError("JEV routing response was not a JSON object")
        return data

    def decide(self, state: dict[str, Any]) -> tuple[JevAnswer, JevAnswer]:
        answers = self.decide_questions(state, "routing/jev.json")
        return answers["analysis_depth"], answers["context_profile"]


class JevRouter:
    def __init__(self, client: JevClient | None = None, confidence_threshold: float | None = None) -> None:
        self.client = client
        configured = float(load_json("routing/jev.json")["confidence_threshold"])
        self.confidence_threshold = configured if confidence_threshold is None else confidence_threshold

    def classify(self, candidate: Candidate) -> RouteDecision:
        fallback = self._local_classify(candidate)
        if self.client is None or candidate.metadata.get("sensitive_evidence") or candidate.metadata.get("content_read") is False:
            return fallback
        try:
            depth, profile = self.client.decide(_jev_state(candidate))
        except JevError:
            return RouteDecision(fallback.depth, fallback.profile, f"{fallback.reason}; JEV unavailable")
        if min(depth.confidence, profile.confidence) < self.confidence_threshold:
            return RouteDecision(fallback.depth, fallback.profile, f"{fallback.reason}; JEV low confidence")
        try:
            selected_depth = Depth(depth.choice)
        except ValueError:
            return RouteDecision(fallback.depth, fallback.profile, f"{fallback.reason}; JEV unsupported depth")
        model_tier = {
            Depth.FAST: ModelTier.FAST,
            Depth.STANDARD: ModelTier.STANDARD,
            Depth.DEEP: ModelTier.DEEP,
        }[selected_depth]
        task_class = _task_class(profile.choice)
        return RouteDecision(
            selected_depth,
            profile.choice,
            f"JEV {depth.model} confidence {min(depth.confidence, profile.confidence):.2f}",
            task_class,
            model_tier,
            True,
            selected_depth is Depth.DEEP,
        )

    def _local_classify(self, candidate: Candidate) -> RouteDecision:
        category = str(candidate.metadata.get("category", "general"))
        task_class = _task_class(category)
        deep_categories = set(load_json("routing/jev.json")["deep_categories"])
        if category in deep_categories or candidate.severity in {Severity.CRITICAL, Severity.HIGH}:
            return RouteDecision(Depth.DEEP, category, "deep scan escalation", task_class, ModelTier.DEEP, True, True)
        return RouteDecision(Depth.FAST, category, "localized candidate", task_class, ModelTier.FAST, True, False)


def _task_class(category: str) -> str:
    """Collapse scanner-specific labels into the stable Context Fabric vocabulary."""
    category = category.lower()
    return str(load_json("routing/jev.json")["task_classes"].get(category, "generic"))


def _jev_state(candidate: Candidate) -> dict[str, Any]:
    runtime = load_json("runtime/jev.json")
    return {
        "rule_id": candidate.rule_id,
        "title": candidate.title,
        "vulnerability_class": candidate.vulnerability_class,
        "severity": candidate.severity.value,
        "message": candidate.message[: int(runtime["maximum_message_characters"])],
        "path": candidate.evidence.path,
        "graph_path": candidate.evidence.graph_path[: int(runtime["maximum_path_nodes"])],
        "metadata_category": str(candidate.metadata.get("category", "general")),
    }
