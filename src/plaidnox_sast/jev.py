from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .assets import load_json
from .errors import AIStageError
from .models import Candidate, Depth, ModelTier, RouteDecision, Severity
from .redaction import redact_payload


class JevError(AIStageError):
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
    ) -> JevClient:
        api_key = os.environ.get("JEV_API_KEY")
        if not api_key:
            raise JevError("JEV_API_KEY is required when --jev is enabled")
        return cls(api_key, model=model)

    def decide_questions(self, state: dict[str, Any], routing_asset: str) -> dict[str, JevAnswer]:
        routing = load_json(routing_asset)
        payload = {
            "model": self.model,
            "state": redact_payload(state),
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
            with urlopen(request, timeout=self.request_timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise JevError("JEV routing request failed") from exc
        if not isinstance(data, dict):
            raise JevError("JEV routing response was not a JSON object")
        return data


_NOUL_SIGNALS = (
    "needs_cross_file",
    "needs_state_reconstruction",
    "needs_external_semantics",
    "needs_environment_context",
    "needs_deep_falsification",
)


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
            answers = self.client.decide_questions(_jev_state(candidate), "routing/jev.json")
        except JevError:
            return replace(fallback, reason=f"{fallback.reason}; JEV unavailable")
        depth_answer = answers["analysis_depth"]
        complexity_answer = answers["analysis_complexity"]
        confidences = [depth_answer.confidence, complexity_answer.confidence] + [
            answers[name].confidence for name in _NOUL_SIGNALS
        ]
        if min(confidences) < self.confidence_threshold:
            return replace(fallback, reason=f"{fallback.reason}; JEV low confidence")
        try:
            selected_depth = Depth(depth_answer.choice)
        except ValueError:
            return replace(fallback, reason=f"{fallback.reason}; JEV unsupported depth")
        questions = load_json("routing/jev.json")["questions"]
        noul_criteria = set(questions["needs_cross_file"]["criteria"])
        signal_values: dict[str, str] = {}
        for name in _NOUL_SIGNALS:
            choice = answers[name].choice
            if choice not in noul_criteria:
                return replace(fallback, reason=f"{fallback.reason}; JEV unsupported {name}")
            signal_values[name] = choice
        if complexity_answer.choice not in questions["analysis_complexity"]["criteria"]:
            return replace(fallback, reason=f"{fallback.reason}; JEV unsupported analysis_complexity")
        model_tier = {
            Depth.FAST: ModelTier.FAST,
            Depth.STANDARD: ModelTier.STANDARD,
            Depth.DEEP: ModelTier.DEEP,
        }[selected_depth]
        task_class = _task_class(str(candidate.metadata.get("category", "unclassified")))
        return RouteDecision(
            depth=selected_depth,
            reason=f"JEV {depth_answer.model} confidence {min(confidences):.2f}",
            task_class=task_class,
            model_tier=model_tier,
            needs_validation=True,
            needs_deep_hunt=True,
            needs_cross_file=signal_values["needs_cross_file"],
            needs_state_reconstruction=signal_values["needs_state_reconstruction"],
            needs_external_semantics=signal_values["needs_external_semantics"],
            needs_environment_context=signal_values["needs_environment_context"],
            needs_deep_falsification=signal_values["needs_deep_falsification"],
            analysis_complexity=int(complexity_answer.choice),
        )

    def _local_classify(self, candidate: Candidate) -> RouteDecision:
        category = str(candidate.metadata.get("category", "unclassified"))
        task_class = _task_class(category)
        if candidate.severity in {Severity.CRITICAL, Severity.HIGH}:
            return RouteDecision(
                Depth.DEEP,
                "severity-safe routing fallback",
                task_class,
                ModelTier.DEEP,
                needs_cross_file="likely",
                needs_state_reconstruction="likely",
                needs_external_semantics="likely",
                needs_environment_context="likely",
                needs_deep_falsification="likely",
                analysis_complexity=4,
            )
        return RouteDecision(
            Depth.STANDARD,
            "provider-neutral routing fallback",
            task_class,
            ModelTier.STANDARD,
            needs_cross_file="unlikely",
            needs_state_reconstruction="unlikely",
            needs_external_semantics="unlikely",
            needs_environment_context="unlikely",
            needs_deep_falsification="unlikely",
            analysis_complexity=2,
        )


FRONTIER_PRIORITY_WEIGHT = {"low": 0, "standard": 1, "high": 2}


@dataclass(slots=True)
class FrontierDecision:
    priority: str
    reason: str


class JevFrontierRouter:
    """Ranks confirmed gained-capability findings so a bounded pivot search spends
    its budget on the most promising part of the capability-chain frontier first."""

    def __init__(self, client: JevClient | None = None, confidence_threshold: float | None = None) -> None:
        self.client = client
        configured = float(load_json("routing/capability_chain_frontier.json")["confidence_threshold"])
        self.confidence_threshold = configured if confidence_threshold is None else confidence_threshold

    def prioritize(self, finding_facts: dict[str, Any]) -> FrontierDecision:
        fallback = self._local_prioritize(finding_facts)
        if self.client is None:
            return fallback
        try:
            answers = self.client.decide_questions(finding_facts, "routing/capability_chain_frontier.json")
        except JevError:
            return replace(fallback, reason=f"{fallback.reason}; JEV unavailable")
        answer = answers["pivot_priority"]
        if answer.confidence < self.confidence_threshold:
            return replace(fallback, reason=f"{fallback.reason}; JEV low confidence")
        criteria = load_json("routing/capability_chain_frontier.json")["questions"]["pivot_priority"]["criteria"]
        if answer.choice not in criteria:
            return replace(fallback, reason=f"{fallback.reason}; JEV unsupported pivot_priority")
        return FrontierDecision(answer.choice, f"JEV {answer.model} confidence {answer.confidence:.2f}")

    def _local_prioritize(self, finding_facts: dict[str, Any]) -> FrontierDecision:
        if str(finding_facts.get("severity", "medium")) in {"critical", "high"}:
            return FrontierDecision("high", "severity-safe frontier fallback")
        return FrontierDecision("standard", "provider-neutral frontier fallback")


@dataclass(slots=True)
class RetryDecision:
    action: str
    reason: str


class JevRetryRouter:
    """Chooses at most one bounded extra Deep Hunt round after context has already
    been expanded to its normal budget and a genuine evidence gap remains."""

    def __init__(self, client: JevClient | None = None, confidence_threshold: float | None = None) -> None:
        self.client = client
        configured = float(load_json("routing/retry_route.json")["confidence_threshold"])
        self.confidence_threshold = configured if confidence_threshold is None else confidence_threshold

    def decide(self, retry_facts: dict[str, Any]) -> RetryDecision:
        fallback = self._local_decide(retry_facts)
        if self.client is None:
            return fallback
        try:
            answers = self.client.decide_questions(retry_facts, "routing/retry_route.json")
        except JevError:
            return replace(fallback, reason=f"{fallback.reason}; JEV unavailable")
        answer = answers["next_action"]
        if answer.confidence < self.confidence_threshold:
            return replace(fallback, reason=f"{fallback.reason}; JEV low confidence")
        criteria = load_json("routing/retry_route.json")["questions"]["next_action"]["criteria"]
        if answer.choice not in criteria:
            return replace(fallback, reason=f"{fallback.reason}; JEV unsupported next_action")
        return RetryDecision(answer.choice, f"JEV {answer.model} confidence {answer.confidence:.2f}")

    def _local_decide(self, retry_facts: dict[str, Any]) -> RetryDecision:
        if str(retry_facts.get("model_tier", "")) != ModelTier.DEEP.value:
            return RetryDecision("escalate_model", "tier-safe retry fallback")
        if retry_facts.get("context_requests_pending", 0):
            return RetryDecision("expand_context", "unresolved-context retry fallback")
        return RetryDecision("mark_unresolved", "no-further-signal retry fallback")


def _task_class(category: str) -> str:
    """Normalize an open task label without imposing a vulnerability taxonomy."""
    normalized = "".join(character if character.isalnum() else "_" for character in category.lower())
    return normalized.strip("_") or "unclassified"


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
