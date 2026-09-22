from __future__ import annotations

import sqlite3

from plaidnox_sast.jev import JevAnswer
from plaidnox_sast.knowledge import (
    JevKnowledgeRouter,
    KnowledgeCoordinator,
    KnowledgeDecision,
    KnowledgeEntry,
    KnowledgeStore,
    LiteLLMKnowledgeProvider,
)
from plaidnox_sast.cache_telemetry import LiteLLMCacheTelemetry


class FakeJevClient:
    def __init__(self, action: str = "use_database", confidence: float = 0.93):
        self.action = action
        self.confidence = confidence
        self.requests = []

    def decide_questions(self, state, routing_asset):
        self.requests.append((state, routing_asset))
        return {
            "knowledge_action": JevAnswer(self.action, self.confidence, "jev-test"),
            "knowledge_scope": JevAnswer("framework", self.confidence, "jev-test"),
        }


class FakeResearchProvider:
    def __init__(self):
        self.queries = []

    def research(self, query, context):
        self.queries.append((query, context))
        return [
            KnowledgeEntry(
                topic="Express proxy trust boundaries",
                content="Proxy trust configuration changes which forwarding headers are authoritative.",
                vulnerability_class="request-origin trust",
                ecosystem="javascript",
                framework="express",
                source_url="https://expressjs.com/en/guide/behind-proxies.html",
                source_title="Express behind proxies",
                source_updated_at="2026-01-01",
                confidence=0.96,
            )
        ]


def _task():
    return {
        "task_id": "proxy-boundary",
        "title": "Proxy trust review",
        "objective": "Determine whether client-controlled forwarding headers cross a trust boundary.",
        "vulnerability_themes": ["request-origin trust"],
    }


def test_knowledge_store_is_content_addressed_and_searchable(tmp_path):
    store = KnowledgeStore(tmp_path / "context.sqlite")
    first = store.upsert(
        KnowledgeEntry(
            topic="Express proxy trust",
            content="Only trust explicitly configured reverse proxies.",
            framework="express",
            source_url="https://expressjs.com/en/guide/behind-proxies.html",
            source_title="Express behind proxies",
            confidence=0.95,
        )
    )
    second = store.upsert(
        KnowledgeEntry(
            topic="Express proxy trust",
            content="Only trust explicitly configured reverse proxies.",
            framework="express",
            source_url="https://expressjs.com/en/guide/behind-proxies.html",
            source_title="Express behind proxies",
            confidence=0.95,
        )
    )

    assert first.knowledge_id == second.knowledge_id
    assert store.search("Express")[0].source_url.startswith("https://expressjs.com/")
    assert store.search("How should an Express deployment configure trusted proxy headers?")[0].framework == "express"
    with sqlite3.connect(tmp_path / "context.sqlite") as connection:
        assert connection.execute("SELECT COUNT(*) FROM security_knowledge").fetchone()[0] == 1


def test_jev_routes_between_database_reuse_and_web_research(tmp_path):
    store = KnowledgeStore(tmp_path / "context.sqlite")
    stored = store.upsert(
        KnowledgeEntry(
            topic="Express proxy trust",
            content="Stored primary-source guidance.",
            framework="express",
            source_url="https://expressjs.com/en/guide/behind-proxies.html",
            source_title="Express behind proxies",
            confidence=0.95,
        )
    )
    reuse_jev = FakeJevClient("use_database")
    coordinator = KnowledgeCoordinator(store, JevKnowledgeRouter(reuse_jev))
    decision, entries = coordinator.resolve("owner/repo", "scan-1", _task(), "Express proxy trust", {})

    assert decision.action == "use_database"
    assert entries[0].knowledge_id == stored.knowledge_id
    assert reuse_jev.requests[0][1] == "routing/knowledge_retrieval.json"

    provider = FakeResearchProvider()
    research_jev = FakeJevClient("research_web")
    coordinator = KnowledgeCoordinator(store, JevKnowledgeRouter(research_jev), provider)
    decision, entries = coordinator.resolve("owner/repo", "scan-2", _task(), "current proxy behavior", {})

    assert decision.action == "research_web"
    assert provider.queries
    assert entries[0].provenance == "web-research"


def test_low_confidence_jev_decision_uses_external_research_policy():
    router = JevKnowledgeRouter(FakeJevClient("use_database", confidence=0.4))
    decision = router.classify("unknown behavior", _task(), {}, [])

    assert isinstance(decision, KnowledgeDecision)
    assert decision.action == "research_web"


def test_hunt_plan_and_tasks_are_persisted_separately(tmp_path):
    store = KnowledgeStore(tmp_path / "context.sqlite")
    task = _task()
    plan_id = store.save_plan("owner/repo", "a" * 40, "Review proxy boundaries.", [task])

    with sqlite3.connect(tmp_path / "context.sqlite") as connection:
        plan = connection.execute("SELECT repository, commit_sha FROM hunt_plans WHERE plan_id = ?", (plan_id,)).fetchone()
        task_count = connection.execute("SELECT COUNT(*) FROM hunt_tasks WHERE plan_id = ?", (plan_id,)).fetchone()[0]
    assert plan == ("owner/repo", "a" * 40)
    assert task_count == 1
    cached = store.load_plan("owner/repo", "a" * 40)
    assert cached is not None
    assert cached["plan_id"] == plan_id
    assert cached["tasks"][0]["task_id"] == "proxy-boundary"


def test_fresh_research_queries_are_batched_per_hunt_task(tmp_path):
    store = KnowledgeStore(tmp_path / "context.sqlite")
    provider = FakeResearchProvider()
    coordinator = KnowledgeCoordinator(
        store,
        JevKnowledgeRouter(FakeJevClient("research_web")),
        provider,
    )
    resolved = coordinator.resolve_many(
        "owner/repo",
        "scan-batch",
        _task(),
        ["Express proxy trust", "forwarded header spoofing"],
        {"architecture": "Express API"},
    )

    assert len(provider.queries) == 1
    assert len(resolved) == 2
    with sqlite3.connect(tmp_path / "context.sqlite") as connection:
        usage_count = connection.execute(
            "SELECT COUNT(*) FROM knowledge_usage WHERE scan_id = 'scan-batch'"
        ).fetchone()[0]
    assert usage_count == 2


def test_perplexity_sonar_research_keeps_only_returned_citations():
    import json

    payload = {
        "entries": [
            {
                "topic": "Express proxy trust",
                "content": "Express proxy trust changes how request IP information is derived.",
                "vulnerability_class": "request-origin trust",
                "ecosystem": "javascript",
                "framework": "express",
                "source_url": "https://expressjs.com/en/guide/behind-proxies.html",
                "source_title": "Express behind proxies",
                "source_updated_at": "",
                "confidence": 0.96,
            },
            {
                "topic": "Unsupported statement",
                "content": "This source was not returned by Sonar.",
                "vulnerability_class": "generic",
                "ecosystem": "javascript",
                "framework": "express",
                "source_url": "https://invalid.example/research",
                "source_title": "Invalid",
                "source_updated_at": "",
                "confidence": 0.8,
            },
        ]
    }

    class FakeResponses:
        def __init__(self):
            self.request = None

        def create(self, **kwargs):
            self.request = kwargs
            return type(
                "Response",
                (),
                {
                    "status": "completed",
                    "output_text": json.dumps(payload),
                    "usage": {"input_tokens": 100, "input_tokens_details": {"cached_tokens": 20}},
                    "output": [
                        {
                            "type": "search_results",
                            "results": [
                                {
                                    "title": "Express behind proxies",
                                    "url": "https://expressjs.com/en/guide/behind-proxies.html",
                                    "last_updated": "2026-08-01",
                                }
                            ],
                        }
                    ],
                },
            )()

    responses = FakeResponses()
    client = type("Client", (), {"responses": responses})()
    provider = LiteLLMKnowledgeProvider(
        client, "perplexity/perplexity/sonar", LiteLLMCacheTelemetry()
    )

    entries = provider.research("Express trust proxy security", {"architecture": "Express"})

    assert len(entries) == 1
    assert entries[0].provenance == "perplexity-sonar-via-litellm:perplexity/perplexity/sonar"
    assert entries[0].source_updated_at == "2026-08-01"
    assert responses.request["model"] == "perplexity/perplexity/sonar"
    assert responses.request["text"]["format"]["type"] == "json_schema"
    assert "prompt_cache_key" not in responses.request
    assert "primary sources" in responses.request["instructions"]
