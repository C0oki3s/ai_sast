"""Durable, provenance-aware security knowledge for PlaidNox hunts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .assets import load_json, load_text
from .cache_telemetry import LiteLLMCacheTelemetry
from .controls import ModelUsageBudget
from .jev import JevClient, JevError
from .prompts import render_operation
from .redaction import redact_payload


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class KnowledgeEntry:
    topic: str
    content: str
    vulnerability_class: str = ""
    ecosystem: str = ""
    framework: str = ""
    source_url: str = ""
    source_title: str = ""
    source_updated_at: str = ""
    provenance: str = "web-research"
    confidence: float = 0.0
    knowledge_id: str = ""
    content_hash: str = ""
    claims: list[str] = field(default_factory=list)

    def normalised(self) -> KnowledgeEntry:
        content_hash = self.content_hash or _digest(
            f"{self.topic.strip()}\n{self.content.strip()}\n{self.source_url.strip()}"
        )
        knowledge_id = self.knowledge_id or f"knw-{content_hash[:16]}"
        runtime = load_json("runtime/agent.json")
        claim_characters = int(runtime["knowledge_claim_characters"])
        max_claims = int(runtime["knowledge_max_claims"])
        claims = [claim.strip()[:claim_characters] for claim in self.claims if claim.strip()][:max_claims]
        return KnowledgeEntry(
            topic=self.topic.strip(),
            content=self.content.strip(),
            vulnerability_class=self.vulnerability_class.strip(),
            ecosystem=self.ecosystem.strip(),
            framework=self.framework.strip(),
            source_url=self.source_url.strip(),
            source_title=self.source_title.strip(),
            source_updated_at=self.source_updated_at.strip(),
            provenance=self.provenance.strip(),
            confidence=max(0.0, min(1.0, float(self.confidence))),
            knowledge_id=knowledge_id,
            content_hash=content_hash,
            claims=claims,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class KnowledgeDecision:
    action: str
    scope: str
    confidence: float
    model: str
    reason: str


class KnowledgeResearchProvider(Protocol):
    def research(self, query: str, context: dict[str, Any]) -> list[KnowledgeEntry]: ...


class SecurityKnowledgeStore(Protocol):
    """Persistence-neutral knowledge and hunt-plan contract."""

    def upsert(self, entry: KnowledgeEntry) -> KnowledgeEntry: ...

    def search(self, query: str, limit: int | None = None) -> list[KnowledgeEntry]: ...

    def record_usage(
        self,
        repository: str,
        scan_id: str,
        task_id: str,
        query: str,
        decision: KnowledgeDecision,
        entries: list[KnowledgeEntry],
    ) -> None: ...

    def save_plan(
        self,
        repository: str,
        commit: str,
        strategy: str,
        tasks: list[dict[str, Any]],
    ) -> str: ...

    def load_plan(self, repository: str, commit: str) -> dict[str, Any] | None: ...


class KnowledgeStore:
    """SQLite adapter with deployable migrations and external SQL statements."""

    def __init__(self, database: Path) -> None:
        self.database = database
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_schema(self) -> None:
        manifest = load_json("migrations/context_fabric.json")
        with self._connect() as connection:
            for migration in manifest["migrations"]:
                connection.executescript(load_text(str(migration)))

    def upsert(self, entry: KnowledgeEntry) -> KnowledgeEntry:
        value = entry.normalised()
        with self._connect() as connection:
            connection.execute(
                load_text("sql/knowledge/upsert.sql"),
                (
                    value.knowledge_id,
                    value.topic,
                    value.vulnerability_class,
                    value.ecosystem,
                    value.framework,
                    value.content,
                    value.source_url,
                    value.source_title,
                    value.source_updated_at,
                    value.provenance,
                    value.confidence,
                    value.content_hash,
                    json.dumps(value.claims, ensure_ascii=False),
                ),
            )
        return value

    def search(self, query: str, limit: int | None = None) -> list[KnowledgeEntry]:
        runtime = load_json("runtime/agent.json")
        result_limit = int(limit or runtime["knowledge_result_limit"])
        minimum_length = int(runtime["knowledge_search_min_token_characters"])
        stop_words = {str(item).lower() for item in runtime["knowledge_search_stop_words"]}
        tokens = [
            token
            for token in re.findall(r"[a-zA-Z0-9_.+-]+", query.lower())
            if len(token) >= minimum_length and token not in stop_words
        ]
        search_values = list(dict.fromkeys([query.strip(), *tokens]))
        rows_by_id: dict[str, sqlite3.Row] = {}
        matches: dict[str, int] = {}
        with self._connect() as connection:
            for value in search_values:
                if not value:
                    continue
                search_term = f"%{value}%"
                rows = connection.execute(
                    load_text("sql/knowledge/search.sql"),
                    (search_term, search_term, search_term, search_term, search_term, result_limit),
                ).fetchall()
                for row in rows:
                    knowledge_id = str(row["knowledge_id"])
                    rows_by_id[knowledge_id] = row
                    matches[knowledge_id] = matches.get(knowledge_id, 0) + 1
        ranked = sorted(
            rows_by_id.values(),
            key=lambda row: (-matches[str(row["knowledge_id"])], -float(row["confidence"]), str(row["topic"])),
        )
        return [_entry_from_row(row) for row in ranked[:result_limit]]

    def record_usage(
        self,
        repository: str,
        scan_id: str,
        task_id: str,
        query: str,
        decision: KnowledgeDecision,
        entries: list[KnowledgeEntry],
    ) -> None:
        selected = entries or [None]
        with self._connect() as connection:
            for index, entry in enumerate(selected):
                knowledge_id = entry.knowledge_id if entry else None
                usage_id = f"use-{_digest(':'.join((repository, scan_id, task_id, query, str(knowledge_id), str(index))))[:16]}"
                connection.execute(
                    load_text("sql/knowledge/record_usage.sql"),
                    (
                        usage_id,
                        repository,
                        scan_id,
                        task_id,
                        query,
                        knowledge_id,
                        decision.action,
                        decision.confidence,
                        decision.reason,
                    ),
                )

    def save_plan(self, repository: str, commit: str, strategy: str, tasks: list[dict[str, Any]]) -> str:
        workflow_version = str(load_json("runtime/agent.json")["workflow_version"])
        context_hash = _digest(workflow_version + ":" + json.dumps(tasks, sort_keys=True, ensure_ascii=False))
        plan_id = f"plan-{_digest(repository + ':' + commit + ':' + context_hash)[:16]}"
        with self._connect() as connection:
            connection.execute(
                load_text("sql/knowledge/save_plan.sql"),
                (plan_id, repository, commit, strategy, context_hash),
            )
            connection.execute(
                load_text("sql/knowledge/save_plan_version.sql"),
                (plan_id, workflow_version),
            )
            for task in tasks:
                connection.execute(
                    load_text("sql/knowledge/save_task.sql"),
                    (
                        plan_id,
                        str(task["task_id"]),
                        str(task["title"]),
                        str(task["objective"]),
                        json.dumps(task, sort_keys=True, ensure_ascii=False),
                    ),
                )
        return plan_id

    def load_plan(self, repository: str, commit: str) -> dict[str, Any] | None:
        workflow_version = str(load_json("runtime/agent.json")["workflow_version"])
        with self._connect() as connection:
            plan = connection.execute(
                load_text("sql/knowledge/load_plan.sql"),
                (repository, commit, workflow_version),
            ).fetchone()
            if plan is None:
                return None
            task_rows = connection.execute(
                load_text("sql/knowledge/load_tasks.sql"),
                (plan["plan_id"],),
            ).fetchall()
        return {
            "plan_id": str(plan["plan_id"]),
            "strategy": str(plan["strategy"]),
            "tasks": [json.loads(str(row["task_json"])) for row in task_rows],
        }


class JevKnowledgeRouter:
    """Uses JEV only for typed knowledge reuse/retrieval/research decisions."""

    def __init__(self, client: JevClient) -> None:
        self.client = client

    def classify(
        self,
        query: str,
        task: dict[str, Any],
        repository_context: dict[str, Any],
        stored: list[KnowledgeEntry],
    ) -> KnowledgeDecision:
        policy = load_json("routing/knowledge_retrieval.json")
        state = {
            "query": query,
            "task": task,
            "repository": {
                "codebase": repository_context.get("codebase"),
                "architecture": repository_context.get("architecture"),
                "applications": repository_context.get("applications"),
            },
            "stored_knowledge": [
                {
                    "knowledge_id": item.knowledge_id,
                    "topic": item.topic,
                    "ecosystem": item.ecosystem,
                    "framework": item.framework,
                    "source_url": item.source_url,
                    "source_updated_at": item.source_updated_at,
                    "confidence": item.confidence,
                    # What the entry actually says, not just its metadata — JEV
                    # cannot judge sufficiency from a title and a source URL alone.
                    "claims": item.claims,
                }
                for item in stored
            ],
        }
        answers = self.client.decide_questions(state, "routing/knowledge_retrieval.json")
        try:
            action = answers["knowledge_action"]
            scope = answers["knowledge_scope"]
        except KeyError as exc:
            raise JevError("JEV knowledge response omitted a required decision") from exc
        confidence = min(action.confidence, scope.confidence)
        if confidence < float(policy["confidence_threshold"]):
            return KnowledgeDecision(
                str(policy["low_confidence_action"]),
                scope.choice,
                confidence,
                action.model,
                "JEV confidence below the knowledge reuse threshold",
            )
        return KnowledgeDecision(action.choice, scope.choice, confidence, action.model, "JEV knowledge decision")


def _joined(values: Any) -> str:
    return " ".join(str(value) for value in values or [] if value)


def _retrieval_terms(scope: str, query: str, task: dict[str, Any], repository_context: dict[str, Any]) -> str:
    """Build a scope-appropriate database search query from already-available task/repository facts.

    `knowledge_scope` only chooses which already-known facts are most likely to retrieve the
    right stored knowledge; it never adds new data collection, so each branch below is built
    only from fields `task`/`repository_context` already carry.
    """
    applications = repository_context.get("applications") or []
    if scope == "repository":
        parts = [
            str(task.get("title", "")),
            _joined(task.get("focus_paths")),
            _joined(task.get("entry_points")),
            _joined(task.get("inventory_refs")),
        ]
    elif scope == "framework":
        parts = [
            str(repository_context.get("architecture", "")),
            _joined(str(app.get("architecture", "")) for app in applications),
            query,
        ]
    elif scope == "business_domain":
        parts = [
            str(repository_context.get("business_context", "")),
            _joined(task.get("business_invariants")),
            _joined(repository_context.get("security_invariants")),
        ]
    elif scope == "vulnerability_class":
        parts = [
            _joined(task.get("vulnerability_themes")),
            _joined(task.get("falsification_requirements")),
            query,
        ]
    elif scope == "advisory":
        parts = [
            query,
            _joined(service for app in applications for service in app.get("external_services", [])),
        ]
    else:
        parts = [
            str(task.get("title", "")),
            str(task.get("objective", "")),
            _joined(task.get("vulnerability_themes")),
        ]
    terms = " ".join(part for part in parts if part).strip()
    return terms or query


class KnowledgeCoordinator:
    """Resolves a task query through durable memory and optional sourced research."""

    def __init__(
        self,
        store: SecurityKnowledgeStore,
        router: JevKnowledgeRouter,
        research_provider: KnowledgeResearchProvider | None = None,
    ) -> None:
        self.store = store
        self.router = router
        self.research_provider = research_provider

    def resolve(
        self,
        repository: str,
        scan_id: str,
        task: dict[str, Any],
        query: str,
        repository_context: dict[str, Any],
    ) -> tuple[KnowledgeDecision, list[KnowledgeEntry]]:
        stored = self.store.search(query)
        decision = self.router.classify(query, task, repository_context, stored)
        entries = stored
        if decision.action == "research_web":
            if self.research_provider is None:
                raise RuntimeError("JEV requested web research but no knowledge research provider is configured")
            researched = self.research_provider.research(
                query,
                {"task": task, "repository_context": repository_context, "stored_knowledge": [item.to_dict() for item in stored]},
            )
            entries = [self.store.upsert(item) for item in researched]
        elif decision.action == "retrieve_database":
            entries = self.store.search(_retrieval_terms(decision.scope, query, task, repository_context))
        self.store.record_usage(repository, scan_id, str(task["task_id"]), query, decision, entries)
        return decision, entries

    def resolve_many(
        self,
        repository: str,
        scan_id: str,
        task: dict[str, Any],
        queries: list[str],
        repository_context: dict[str, Any],
    ) -> list[tuple[str, KnowledgeDecision, list[KnowledgeEntry]]]:
        """Classify each query with JEV, then research each pending query independently.

        Each query gets its own research call so a research result is never attributed
        to a query it wasn't actually answering.
        """
        pending_research: list[tuple[str, KnowledgeDecision, list[KnowledgeEntry]]] = []
        resolved: list[tuple[str, KnowledgeDecision, list[KnowledgeEntry]]] = []
        for query in dict.fromkeys(item.strip() for item in queries if item.strip()):
            stored = self.store.search(query)
            decision = self.router.classify(query, task, repository_context, stored)
            if decision.action == "research_web":
                pending_research.append((query, decision, stored))
                continue
            if decision.action == "retrieve_database":
                stored = self.store.search(_retrieval_terms(decision.scope, query, task, repository_context))
            self.store.record_usage(repository, scan_id, str(task["task_id"]), query, decision, stored)
            resolved.append((query, decision, stored))

        if pending_research:
            if self.research_provider is None:
                raise RuntimeError("JEV requested web research but no knowledge research provider is configured")
            for query, decision, stored in pending_research:
                researched = self.research_provider.research(
                    query,
                    {
                        "task": task,
                        "repository_context": repository_context,
                        "stored_knowledge": [item.to_dict() for item in stored],
                    },
                )
                entries = [self.store.upsert(item) for item in researched]
                self.store.record_usage(repository, scan_id, str(task["task_id"]), query, decision, entries)
                resolved.append((query, decision, entries))
        return resolved


class LiteLLMKnowledgeProvider:
    """Structured, source-validated research routed only through LiteLLM."""

    def __init__(
        self,
        client: Any,
        model: str,
        cache_telemetry: LiteLLMCacheTelemetry,
        model_budget: ModelUsageBudget | None = None,
    ) -> None:
        self.client = client
        self.model = model
        self.cache_telemetry = cache_telemetry
        self.model_budget = model_budget or ModelUsageBudget()
        self.config = load_json("research/providers.json")["providers"]["perplexity_sonar"]

    @classmethod
    def from_environment(
        cls,
        cache_telemetry: LiteLLMCacheTelemetry,
        model_budget: ModelUsageBudget | None = None,
    ) -> LiteLLMKnowledgeProvider:
        from .llm import LiteLLMConfigurationError, LiteLLMResponsesClient

        config = load_json("research/providers.json")["providers"]["perplexity_sonar"]
        selected = os.environ.get(str(config["model_environment"]), str(config["default_model"]))
        prefix = str(config["litellm_model_prefix"])
        model = selected if selected.startswith("perplexity/") else f"{prefix}{selected}"
        try:
            client = LiteLLMResponsesClient.from_environment(model, prefer_direct=True)
        except LiteLLMConfigurationError as exc:
            raise RuntimeError(str(exc)) from exc
        return cls(client, model, cache_telemetry, model_budget)

    def research(self, query: str, context: dict[str, Any]) -> list[KnowledgeEntry]:
        schema = load_json("schemas/knowledge_research.json")
        system_prompt, user_prompt = render_operation(
            "knowledge_research",
            redact_payload({"query": query, "context": context}),
            output_schema=schema,
        )
        maximum_output_tokens = int(load_json("runtime/agent.json")["research_max_output_tokens"])
        reservation = self.model_budget.reserve(
            self.model,
            len(system_prompt) + len(user_prompt),
            maximum_output_tokens,
        )
        try:
            response = self.client.responses.create(
                model=self.model,
                instructions=system_prompt,
                input=user_prompt,
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "plaidnox_security_knowledge",
                        "strict": True,
                        "schema": schema,
                    }
                },
                max_output_tokens=maximum_output_tokens,
            )
        except BaseException:
            self.model_budget.cancel(reservation)
            raise
        self.model_budget.complete(reservation, response)
        self.cache_telemetry.record_response(response)
        if getattr(response, "status", "completed") != "completed":
            raise RuntimeError("LiteLLM security research did not complete")
        content = getattr(response, "output_text", None)
        if not content:
            raise RuntimeError("LiteLLM security research returned no content")
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError("LiteLLM security research did not return structured JSON") from exc
        sources = _response_sources(response)
        if not sources:
            raise RuntimeError("LiteLLM security research returned no cited sources")
        entries = []
        for item in payload["entries"]:
            source_url = str(item["source_url"])
            source = sources.get(_normalise_url(source_url))
            if source is None:
                continue
            entries.append(
                KnowledgeEntry(
                    topic=str(item["topic"]),
                    content=str(item["content"]),
                    vulnerability_class=str(item["vulnerability_class"]),
                    ecosystem=str(item["ecosystem"]),
                    framework=str(item["framework"]),
                    source_url=source_url,
                    source_title=str(source.get("title") or item["source_title"]),
                    source_updated_at=str(
                        source.get("last_updated") or source.get("date") or item["source_updated_at"]
                    ),
                    provenance=f"{self.config['provenance']}:{self.model}",
                    confidence=float(item["confidence"]),
                    claims=[str(claim) for claim in item["claims"]],
                )
            )
        if not entries:
            raise RuntimeError("LiteLLM security research contained no entries backed by returned citations")
        return entries


def research_provider_from_environment(
    cache_telemetry: LiteLLMCacheTelemetry,
    model_budget: ModelUsageBudget | None = None,
) -> KnowledgeResearchProvider:
    providers = load_json("research/providers.json")
    selected = os.environ.get("IFRIT_RESEARCH_PROVIDER", str(providers["default_provider"]))
    if selected == "perplexity_sonar":
        return LiteLLMKnowledgeProvider.from_environment(cache_telemetry, model_budget)
    raise RuntimeError(f"Unsupported IFRIT research provider: {selected}")


def _response_sources(response: Any) -> dict[str, dict[str, Any]]:
    extra = getattr(response, "model_extra", None) or {}
    citations = getattr(response, "citations", None) or extra.get("citations") or []
    search_results = getattr(response, "search_results", None) or extra.get("search_results") or []
    sources: dict[str, dict[str, Any]] = {
        _normalise_url(str(url)): {"url": str(url)} for url in citations if str(url).startswith(("http://", "https://"))
    }
    for raw in search_results:
        value = _object_dict(raw)
        url = str(value.get("url", ""))
        if url.startswith(("http://", "https://")):
            sources[_normalise_url(url)] = value
    for output_item in getattr(response, "output", None) or []:
        item = _object_dict(output_item)
        if item.get("type") == "search_results":
            for raw in item.get("results") or []:
                value = _object_dict(raw)
                url = str(value.get("url", ""))
                if url.startswith(("http://", "https://")):
                    sources[_normalise_url(url)] = value
        if item.get("type") == "message":
            for content in item.get("content") or []:
                for annotation in _object_dict(content).get("annotations") or []:
                    value = _object_dict(annotation)
                    url = str(value.get("url", ""))
                    if url.startswith(("http://", "https://")):
                        sources.setdefault(_normalise_url(url), value)
    return sources


def _object_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return dict(value.model_dump())
    if isinstance(value, dict):
        return value
    raw = getattr(value, "__dict__", None)
    return dict(raw) if isinstance(raw, dict) else {}


def _normalise_url(value: str) -> str:
    return value.strip().rstrip("/")


def _entry_from_row(row: sqlite3.Row) -> KnowledgeEntry:
    return KnowledgeEntry(
        knowledge_id=str(row["knowledge_id"]),
        topic=str(row["topic"]),
        vulnerability_class=str(row["vulnerability_class"]),
        ecosystem=str(row["ecosystem"]),
        framework=str(row["framework"]),
        content=str(row["content"]),
        source_url=str(row["source_url"]),
        source_title=str(row["source_title"]),
        source_updated_at=str(row["source_updated_at"]),
        provenance=str(row["provenance"]),
        confidence=float(row["confidence"]),
        content_hash=str(row["content_hash"]),
        claims=json.loads(str(row["claims"])),
    )
