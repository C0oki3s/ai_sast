from plaidnox_sast.cache_telemetry import LiteLLMCacheTelemetry


def test_prompt_cache_records_provider_token_reuse():
    cache = LiteLLMCacheTelemetry()
    details = type("Details", (), {"cached_tokens": 800})()
    usage = type("Usage", (), {"input_tokens": 1000, "input_tokens_details": details})()
    response = type("Response", (), {"usage": usage})()

    cache.record_response(response)

    metrics = cache.snapshot().to_metrics()
    assert metrics["prompt_cache_requests"] == 1
    assert metrics["prompt_cache_hits"] == 1
    assert metrics["prompt_cache_token_reuse_rate"] == 0.8


def test_prompt_cache_normalises_perplexity_cache_read_tokens():
    cache = LiteLLMCacheTelemetry()
    details = {"cache_read_input_tokens": 450}
    usage = {"input_tokens": 900, "input_tokens_details": details}
    response = type("Response", (), {"usage": usage})()

    cache.record_response(response)

    metrics = cache.snapshot().to_metrics()
    assert metrics["prompt_cache_hits"] == 1
    assert metrics["prompt_cache_cached_tokens"] == 450


def test_application_does_not_expose_local_prompt_or_decision_cache_methods():
    cache = LiteLLMCacheTelemetry()

    assert not hasattr(cache, "request_cache_fields")
    assert not hasattr(cache, "get_exact_decision")
