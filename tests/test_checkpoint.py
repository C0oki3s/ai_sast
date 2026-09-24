"""Durable resume: work finished before a failure is never redone."""

import json
import os
import sqlite3

from plaidnox_sast.checkpoint import ScanCheckpoint
from plaidnox_sast.ai import PlaidNoxDeepHuntAgent
from plaidnox_sast.assets import load_json
from plaidnox_sast.errors import AIStageError
from plaidnox_sast.pipeline import SastPipeline

from test_pipeline import FakeContextualAI


class CountingAI(FakeContextualAI):
    """Records model-call counts; fails review while `credits` is False."""

    def __init__(self, credits: bool):
        self.credits = credits
        self.discovery_calls = 0
        self.review_calls = 0
        self.checkpoint = None

    def configure_checkpoint(self, checkpoint):
        self.checkpoint = checkpoint

    def discover_candidates(self, root, context, plan=None):
        self.discovery_calls += 1
        return super().discover_candidates(root, context, plan)

    def review(self, root, candidate, finding, security_context, model_tier=None, route=None):
        self.review_calls += 1
        if not self.credits:
            raise AIStageError("credit balance is too low")
        return super().review(root, candidate, finding, security_context, model_tier=model_tier, route=route)


def _scan(repo, tmp_path, agent):
    return SastPipeline(checkpoint_path=tmp_path / "cp.sqlite").scan_snapshot(
        repo, "plaidnox/test-fixture", deep_hunt_agent=agent
    )


def test_failed_reviews_are_retried_and_successes_are_reused(sample_repo, tmp_path):
    first = _scan(sample_repo, tmp_path, CountingAI(credits=False))
    assert first.findings == []
    assert first.metrics["checkpoint_units_saved"] == 0  # failures are never stored

    resumed_agent = CountingAI(credits=True)
    second = _scan(sample_repo, tmp_path, resumed_agent)
    assert second.findings
    assert second.metrics["checkpoint_units_saved"] >= 1

    third_agent = CountingAI(credits=False)  # would fail if it were called
    third = _scan(sample_repo, tmp_path, third_agent)
    assert third_agent.review_calls == 0
    assert third.metrics["checkpoint_units_reused"] >= 1
    assert [f.fingerprint for f in third.findings] == [f.fingerprint for f in second.findings]


def test_changed_scope_discards_stale_checkpoint(tmp_path):
    path = tmp_path / "cp.sqlite"
    store = ScanCheckpoint(path, "repo|rev1|tree|v1")
    store.put("review", "k", {"outcome": "unsupported"})
    store.close()
    fresh = ScanCheckpoint(path, "repo|rev2|tree|v1")
    assert fresh.get("review", "k") is None
    assert fresh.discarded == 1
    fresh.close()


def test_changed_project_security_context_discards_scan_units(sample_repo, tmp_path):
    first = _scan(sample_repo, tmp_path, CountingAI(credits=True))
    assert first.metrics["checkpoint_units_saved"] >= 1

    config_root = sample_repo / ".plaidnox"
    config_root.mkdir(exist_ok=True)
    (config_root / "security.md").write_text(
        "All object reads must enforce tenant ownership.\n",
        encoding="utf-8",
    )
    second = _scan(sample_repo, tmp_path, CountingAI(credits=True))
    assert second.metrics["checkpoint_units_discarded_stale"] >= 1


def test_pending_llm_context_and_execution_survive_restart(tmp_path):
    path = tmp_path / "cp.sqlite"
    context = {
        "schema_name": "hunt_plan",
        "system_prompt": "stable instructions",
        "user_prompt": "snapshot-specific evidence",
        "schema": {"type": "object"},
    }
    execution = {
        "operation": "hunt_plan",
        "model": "kimi-k2.7-code",
        "model_tier": "standard",
        "reasoning_effort": "medium",
    }

    store = ScanCheckpoint(path, "scope")
    store.begin("llm_response", "call-1", context, execution)
    store.fail("llm_response", "call-1", "InsufficientCreditsError")
    store.close()

    resumed = ScanCheckpoint(path, "scope")
    pending = resumed.pending("llm_response", "call-1")
    assert pending is not None
    assert pending["context"] == context
    assert len(pending["context_hash"]) == 64
    assert pending["execution"] == execution
    assert pending["last_error_type"] == "InsufficientCreditsError"
    assert resumed.status_counts() == {"failed_retryable": 1}
    assert resumed.resume_cursor() == {
        "stage": "llm_response",
        "operation": "hunt_plan",
        "last_error_type": "InsufficientCreditsError",
    }
    resumed.close()
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_completed_llm_response_replays_after_restart(tmp_path):
    path = tmp_path / "cp.sqlite"
    store = ScanCheckpoint(path, "scope")
    store.begin("llm_response", "call-1", {"prompt": "context"}, {"model": "first-model"})
    store.complete("llm_response", "call-1", {"structured_payload": {"supported": False}})
    store.close()

    resumed = ScanCheckpoint(path, "scope")
    record = resumed.get_record("llm_response", "call-1")
    assert record is not None
    assert record["payload"] == {"structured_payload": {"supported": False}}
    assert record["context"] == {"prompt": "context"}
    assert record["execution"] == {"model": "first-model"}
    assert resumed.status_counts() == {"completed": 1}
    resumed.close()


def test_existing_checkpoint_schema_is_migrated(tmp_path):
    path = tmp_path / "cp.sqlite"
    database = sqlite3.connect(path)
    database.executescript(
        """
        CREATE TABLE checkpoint_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE checkpoint_units (
            stage TEXT NOT NULL,
            unit_key TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (stage, unit_key)
        );
        INSERT INTO checkpoint_units(stage, unit_key, payload)
        VALUES ('review', 'old-unit', '{"outcome":"unsupported"}');
        """
    )
    database.commit()
    database.close()

    migrated = ScanCheckpoint(path, "scope")
    assert migrated.get("review", "old-unit") == {"outcome": "unsupported"}
    assert migrated.status_counts() == {"completed": 1}
    migrated.close()


class _QueuedResponses:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def create(self, **_kwargs):
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return type(
            "Response",
            (),
            {"status": "completed", "output_text": json.dumps(response), "usage": {}},
        )()


class _QueuedClient:
    def __init__(self, responses):
        self.responses = _QueuedResponses(responses)


def _recon_payload():
    return {
        "strategy": "Inspect the observed entry point.",
        "queries": [
            {
                "query_id": "route-entry",
                "search_terms": ["app.get"],
                "include_globs": ["*.js"],
                "objective": "Locate the observed route registration.",
                "coverage_targets": ["HTTP entry point"],
            }
        ],
        "coverage_notes": "The focused route is owned by this search.",
    }


def _run_recon_call(agent):
    return agent._structured_response(
        "plaidnox_recon_search_plan",
        load_json("schemas/recon_search_plan.json"),
        "recon_search_plan",
        {"source_tree": ["app.js"], "security_ir": []},
    )


def test_llm_failure_resumes_exact_call_then_replays_without_provider_cost(tmp_path):
    path = tmp_path / "cp.sqlite"
    first_store = ScanCheckpoint(path, "scope")
    failing_client = _QueuedClient([RuntimeError("credits exhausted")])
    first_agent = PlaidNoxDeepHuntAgent(failing_client, model="glm-5.3-flash")
    first_agent.configure_checkpoint(first_store)

    try:
        _run_recon_call(first_agent)
    except RuntimeError as exc:
        assert str(exc) == "credits exhausted"
    else:
        raise AssertionError("the provider failure must be surfaced")
    assert first_store.status_counts() == {"failed_retryable": 1}
    first_store.close()

    second_store = ScanCheckpoint(path, "scope")
    successful_client = _QueuedClient([_recon_payload()])
    second_agent = PlaidNoxDeepHuntAgent(successful_client, model="kimi-k2.7-code")
    second_agent.configure_checkpoint(second_store)
    assert json.loads(_run_recon_call(second_agent).output_text) == _recon_payload()
    assert successful_client.responses.calls == 1
    assert second_store.status_counts() == {"completed": 1}
    second_store.close()

    third_store = ScanCheckpoint(path, "scope")
    unused_client = _QueuedClient([RuntimeError("must not be called")])
    third_agent = PlaidNoxDeepHuntAgent(unused_client, model="claude-haiku-4.5")
    third_agent.configure_checkpoint(third_store)
    assert json.loads(_run_recon_call(third_agent).output_text) == _recon_payload()
    assert unused_client.responses.calls == 0
    assert third_store.hits == 1
    third_store.close()


def test_ctrl_c_leaves_the_llm_operation_pending_for_resume(tmp_path):
    store = ScanCheckpoint(tmp_path / "cp.sqlite", "scope")
    client = _QueuedClient([KeyboardInterrupt()])
    agent = PlaidNoxDeepHuntAgent(client, model="glm-5.3-flash")
    agent.configure_checkpoint(store)

    try:
        _run_recon_call(agent)
    except KeyboardInterrupt:
        pass
    else:
        raise AssertionError("Ctrl-C must remain observable to the caller")

    assert store.status_counts() == {"failed_retryable": 1}
    assert store.resume_cursor()["last_error_type"] == "KeyboardInterrupt"
    store.close()


def test_units_move_through_running_retryable_final_and_abandoned_states(tmp_path):
    path = tmp_path / "cp.sqlite"
    store = ScanCheckpoint(path, "scope")
    store.begin("llm_response", "live", {}, {"operation": "a"})
    assert store.status_counts() == {"running": 1}

    store.begin("llm_response", "rate", {}, {"operation": "b"})
    store.fail("llm_response", "rate", "RateLimitError")
    store.begin("llm_response", "bad", {}, {"operation": "c"})
    store.fail("llm_response", "bad", "BadRequestError")
    assert store.status_counts() == {"running": 1, "failed_retryable": 1, "failed_final": 1}
    store.close()

    # A new process cannot still be running the unit: it is recorded as abandoned.
    resumed = ScanCheckpoint(path, "scope")
    assert resumed.status_counts() == {"failed_retryable": 2, "failed_final": 1}
    assert resumed.pending("llm_response", "live")["last_error_type"] == "abandoned"
    assert resumed.pending("llm_response", "rate")["last_error_type"] == "RateLimitError"
    resumed.begin("llm_response", "rate", {}, {"operation": "b"})
    row = resumed._db.execute(
        "SELECT status, attempt_count FROM checkpoint_units WHERE unit_key = 'rate'"
    ).fetchone()
    assert row == ("running", 2)
    resumed.complete("llm_response", "rate", {"ok": True})
    assert resumed.get("llm_response", "rate") == {"ok": True}
    resumed.close()


def test_successful_replacement_supersedes_only_matching_retryable_work(tmp_path):
    from plaidnox_sast.checkpoint import ScanCheckpoint

    store = ScanCheckpoint(tmp_path / "checkpoint.sqlite", "scope")
    store.begin("llm_response", "old-key", {}, {"operation": "security_review", "work_identity": "candidate-a"})
    store.fail("llm_response", "old-key", "incomplete:max_output_tokens")
    store.begin("llm_response", "other-key", {}, {"operation": "security_review", "work_identity": "candidate-b"})
    store.fail("llm_response", "other-key", "TimeoutError")
    store.begin("llm_response", "replacement-key", {}, {"operation": "security_review", "work_identity": "candidate-a"})
    store.complete("llm_response", "replacement-key", {"ok": True})

    assert store.status_counts() == {"completed": 1, "failed_retryable": 1, "superseded": 1}
    assert store.pending("llm_response", "old-key") is None
    assert store.pending("llm_response", "other-key") is not None
    store.close()
