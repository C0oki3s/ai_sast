from __future__ import annotations

import sqlite3

import pytest

from plaidnox_sast.knowledge import (
    KnowledgeCoordinator,
    KnowledgeEntry,
    KnowledgeStore,
    PerplexityKnowledgeProvider,
)


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


class QueryAwareResearchProvider:
    """Returns a distinct entry per query so cross-query contamination is detectable."""

    def __init__(self):
        self.queries = []

    def research(self, query, context):
        self.queries.append((query, context))
        return [
            KnowledgeEntry(
                topic=f"Answer for: {query}",
                content=f"Research result specific to '{query}'.",
                source_url=f"https://example.test/{abs(hash(query))}",
                source_title=query,
                confidence=0.9,
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


def test_resolve_reuses_stored_knowledge_before_any_web_research(tmp_path):
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
    provider = FakeResearchProvider()
    coordinator = KnowledgeCoordinator(store, provider)
    decision, entries = coordinator.resolve("owner/repo", "scan-1", _task(), "Express proxy trust", {})

    assert decision.action == "use_database"
    assert entries[0].knowledge_id == stored.knowledge_id
    assert not provider.queries


def test_resolve_researches_the_web_when_local_knowledge_is_absent(tmp_path):
    store = KnowledgeStore(tmp_path / "context.sqlite")
    provider = FakeResearchProvider()
    coordinator = KnowledgeCoordinator(store, provider)
    decision, entries = coordinator.resolve("owner/repo", "scan-2", _task(), "current proxy behavior", {})

    assert decision.action == "research_web"
    assert provider.queries
    assert entries[0].provenance == "web-research"


def test_resolve_fails_typed_when_research_is_needed_but_no_provider_is_configured(tmp_path):
    coordinator = KnowledgeCoordinator(KnowledgeStore(tmp_path / "context.sqlite"))

    with pytest.raises(Exception, match="no knowledge research provider"):
        coordinator.resolve("owner/repo", "scan-3", _task(), "current proxy behavior", {})


def test_infer_scope_follows_the_populated_task_fields():
    from plaidnox_sast.knowledge import _infer_scope

    assert _infer_scope({"vulnerability_themes": ["ssrf"]}) == "vulnerability_class"
    assert _infer_scope({"business_invariants": ["tenant isolation"]}) == "business_domain"
    assert _infer_scope({}) == "repository"


def test_retrieval_terms_uses_repository_scoped_task_facts():
    from plaidnox_sast.knowledge import _retrieval_terms

    task = {
        "title": "Review proxy handling",
        "focus_paths": ["app.js"],
        "entry_points": ["GET /users/:id"],
        "inventory_refs": ["app.js"],
        "objective": "unused for this scope",
        "vulnerability_themes": ["unused for this scope"],
    }

    terms = _retrieval_terms("repository", "proxy trust", task, {})

    assert "app.js" in terms
    assert "GET /users/:id" in terms
    assert "unused for this scope" not in terms


def test_retrieval_terms_uses_framework_scoped_repository_facts():
    from plaidnox_sast.knowledge import _retrieval_terms

    repository_context = {
        "architecture": "Express REST API",
        "applications": [{"architecture": "Express 4 with Passport auth"}],
    }

    terms = _retrieval_terms("framework", "proxy trust", _task(), repository_context)

    assert "Express REST API" in terms
    assert "Passport" in terms


def test_retrieval_terms_uses_business_domain_scoped_facts():
    from plaidnox_sast.knowledge import _retrieval_terms

    task = {**_task(), "business_invariants": ["Only the owning tenant may read its own invoices."]}
    repository_context = {
        "business_context": "Multi-tenant billing platform.",
        "security_invariants": ["Tenant data never crosses tenant boundaries."],
    }

    terms = _retrieval_terms("business_domain", "billing access", task, repository_context)

    assert "Multi-tenant billing platform." in terms
    assert "Only the owning tenant may read its own invoices." in terms
    assert "Tenant data never crosses tenant boundaries." in terms


def test_retrieval_terms_uses_vulnerability_class_scoped_facts():
    from plaidnox_sast.knowledge import _retrieval_terms

    task = {
        **_task(),
        "vulnerability_themes": ["cross-tenant state confusion"],
        "falsification_requirements": ["Prove the identifier is attacker-controlled."],
    }

    terms = _retrieval_terms("vulnerability_class", "tenant isolation bypass", task, {})

    assert "cross-tenant state confusion" in terms
    assert "Prove the identifier is attacker-controlled." in terms
    assert "tenant isolation bypass" in terms


def test_retrieval_terms_uses_advisory_scoped_facts():
    from plaidnox_sast.knowledge import _retrieval_terms

    repository_context = {"applications": [{"external_services": ["stripe-node", "aws-sdk"]}]}

    terms = _retrieval_terms("advisory", "stripe-node vulnerable version", _task(), repository_context)

    assert "stripe-node vulnerable version" in terms
    assert "aws-sdk" in terms


def test_retrieval_terms_falls_back_to_the_query_when_nothing_is_known():
    from plaidnox_sast.knowledge import _retrieval_terms

    task = {"task_id": "t1"}

    terms = _retrieval_terms("framework", "obscure question", task, {})

    assert terms == "obscure question"


def test_resolve_retrieves_with_scope_shaped_terms(tmp_path):
    store = KnowledgeStore(tmp_path / "context.sqlite")
    store.upsert(
        KnowledgeEntry(
            topic="Passport session fixation",
            content="Passport regenerates the session on login unless configured otherwise.",
            framework="passport",
            source_url="https://passportjs.org/docs",
            source_title="Passport docs",
            confidence=0.9,
        )
    )
    provider = FakeResearchProvider()
    coordinator = KnowledgeCoordinator(store, provider)
    task = {**_task(), "vulnerability_themes": ["Passport session fixation"]}

    decision, entries = coordinator.resolve("owner/repo", "scan-1", task, "zzqx unrelated wording", {})

    assert decision.action == "retrieve_database"
    assert decision.scope == "vulnerability_class"
    assert entries[0].framework == "passport"
    assert not provider.queries


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


def test_fresh_research_queries_are_resolved_independently_per_hunt_task(tmp_path):
    store = KnowledgeStore(tmp_path / "context.sqlite")
    provider = FakeResearchProvider()
    coordinator = KnowledgeCoordinator(store, provider)
    resolved = coordinator.resolve_many(
        "owner/repo",
        "scan-batch",
        _task(),
        ["Express proxy trust", "forwarded header spoofing"],
        {"architecture": "Express API"},
    )

    assert len(provider.queries) == 2
    assert len(resolved) == 2
    with sqlite3.connect(tmp_path / "context.sqlite") as connection:
        usage_count = connection.execute(
            "SELECT COUNT(*) FROM knowledge_usage WHERE scan_id = 'scan-batch'"
        ).fetchone()[0]
    assert usage_count == 2


def test_resolve_many_does_not_attribute_one_querys_research_to_another(tmp_path):
    store = KnowledgeStore(tmp_path / "context.sqlite")
    provider = QueryAwareResearchProvider()
    coordinator = KnowledgeCoordinator(store, provider)
    resolved = coordinator.resolve_many(
        "owner/repo",
        "scan-batch",
        _task(),
        ["Express proxy trust", "forwarded header spoofing"],
        {"architecture": "Express API"},
    )

    by_query = {query: entries for query, _decision, entries in resolved}
    assert by_query["Express proxy trust"][0].topic == "Answer for: Express proxy trust"
    assert by_query["forwarded header spoofing"][0].topic == "Answer for: forwarded header spoofing"


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
                "claims": ["Express trust proxy setting changes derived client IP."],
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
                "claims": ["This claim should be dropped along with its entry."],
            },
        ]
    }

    class FakeCompletions:
        def __init__(self):
            self.request = None

        def create(self, **kwargs):
            self.request = kwargs
            return type(
                "Response",
                (),
                {
                    "choices": [
                        type(
                            "Choice",
                            (),
                            {"message": type("Message", (), {"content": json.dumps(payload)})()},
                        )()
                    ],
                    "usage": {"input_tokens": 100, "input_tokens_details": {"cached_tokens": 20}},
                    "search_results": [
                        {
                            "title": "Express behind proxies",
                            "url": "https://expressjs.com/en/guide/behind-proxies.html",
                            "last_updated": "2026-08-01",
                        }
                    ],
                },
            )()

    completions = FakeCompletions()
    client = type(
        "Client",
        (),
        {"chat": type("Chat", (), {"completions": completions})()},
    )()
    provider = PerplexityKnowledgeProvider(client, "sonar")

    entries = provider.research("Express trust proxy security", {"architecture": "Express"})

    assert len(entries) == 1
    assert entries[0].provenance == "perplexity-sonar-direct:sonar"
    assert entries[0].source_updated_at == "2026-08-01"
    assert entries[0].claims == ["Express trust proxy setting changes derived client IP."]
    assert completions.request["model"] == "sonar"
    assert completions.request["response_format"]["type"] == "json_schema"
    assert "primary sources" in completions.request["messages"][0]["content"]


def test_knowledge_entry_normalised_strips_and_caps_claims():
    entry = KnowledgeEntry(
        topic="Express proxy trust",
        content="Only trust explicitly configured reverse proxies.",
        source_url="https://expressjs.com/en/guide/behind-proxies.html",
        claims=["  padded claim  ", "", "x" * 500] + [f"claim {i}" for i in range(10)],
    )

    normalised = entry.normalised()

    assert normalised.claims[0] == "padded claim"
    assert "" not in normalised.claims
    assert len(normalised.claims[1]) == 240
    assert len(normalised.claims) == 6


def test_knowledge_store_round_trips_claims(tmp_path):
    store = KnowledgeStore(tmp_path / "context.sqlite")
    saved = store.upsert(
        KnowledgeEntry(
            topic="Express proxy trust",
            content="Only trust explicitly configured reverse proxies.",
            framework="express",
            source_url="https://expressjs.com/en/guide/behind-proxies.html",
            source_title="Express behind proxies",
            confidence=0.95,
            claims=["Only trust explicitly configured reverse proxies."],
        )
    )

    assert saved.claims == ["Only trust explicitly configured reverse proxies."]
    assert store.search("Express")[0].claims == ["Only trust explicitly configured reverse proxies."]
