from plaidnox_sast.observability import ScanTelemetry


def test_observability_is_disabled_without_explicit_configuration(monkeypatch) -> None:
    monkeypatch.delenv("PLAIDNOX_OTEL_ENABLED", raising=False)

    telemetry = ScanTelemetry.from_environment()

    assert not telemetry.enabled
    with telemetry.scan("owner/service", "revision"):
        pass
