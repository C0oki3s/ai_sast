from types import SimpleNamespace

import pytest

from plaidnox_sast.controls import ModelBudgetExceeded, ModelUsageBudget


def _policy(**overrides):
    values = {
        "maximum_calls_per_scan": 2,
        "maximum_inflight_calls": 2,
        "maximum_input_characters_per_scan": 100,
        "maximum_requested_output_tokens_per_scan": 50,
        "maximum_cost_usd_per_scan": 1.0,
        "maximum_cost_usd_by_model": {"deep": 0.6},
    }
    values.update(overrides)
    return values


def test_model_budget_records_litellm_usage_and_cost() -> None:
    budget = ModelUsageBudget(_policy())
    reservation = budget.reserve("deep", 20, 10)
    response = SimpleNamespace(
        usage=SimpleNamespace(input_tokens=30, output_tokens=7),
        _hidden_params={"response_cost": 0.25},
    )

    budget.complete(reservation, response)

    assert budget.metrics() == {
        "model_budget_calls": 1,
        "model_budget_inflight": 0,
        "model_budget_input_characters": 20,
        "model_budget_requested_output_tokens": 10,
        "model_budget_input_tokens": 30,
        "model_budget_output_tokens": 7,
        "model_budget_cost_usd": 0.25,
    }
    assert budget.usage_by_model() == {"deep": (30, 7, 0.25)}


def test_model_budget_rejects_request_before_exceeding_reserved_limit() -> None:
    budget = ModelUsageBudget(_policy(maximum_requested_output_tokens_per_scan=10))

    first = budget.reserve("fast", 10, 8)
    budget.cancel(first)

    with pytest.raises(ModelBudgetExceeded, match="output-token"):
        budget.reserve("fast", 10, 3)


def test_model_budget_rejects_model_specific_cost_after_recording_usage() -> None:
    budget = ModelUsageBudget(_policy())
    reservation = budget.reserve("deep", 10, 5)

    with pytest.raises(ModelBudgetExceeded, match="for deep"):
        budget.complete(
            reservation,
            SimpleNamespace(usage={}, _hidden_params={"response_cost": 0.7}),
        )

    assert budget.metrics()["model_budget_cost_usd"] == 0.7


def test_model_budget_reset_starts_a_new_scan_scope() -> None:
    budget = ModelUsageBudget(_policy(maximum_calls_per_scan=1))
    reservation = budget.reserve("fast", 10, None)
    budget.cancel(reservation)
    with pytest.raises(ModelBudgetExceeded, match="call limit"):
        budget.reserve("fast", 10, None)

    budget.reset()

    budget.cancel(budget.reserve("fast", 10, None))
