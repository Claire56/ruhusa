from ruhusa.health import HealthCheckResult, HealthRegistry, HealthStatus


def test_health_registry_and_sanitized_failure() -> None:
    registry = HealthRegistry()
    registry.register("ok", lambda: True)
    registry.register("bad", lambda: False)

    def secret_failure() -> bool:
        raise RuntimeError("postgresql://user:secret@host/db")

    registry.register("error", secret_failure)
    report = registry.check()

    assert report.healthy is False
    assert report.checks[0].healthy is True
    assert report.checks[1].healthy is False
    assert report.checks[2].detail == "probe raised RuntimeError"
    assert "secret" not in report.checks[2].detail


def test_empty_registry_is_not_healthy() -> None:
    assert HealthRegistry().check().healthy is False


def test_named_result_uses_registered_name() -> None:
    registry = HealthRegistry()
    registry.register("canonical", lambda: HealthCheckResult("other", HealthStatus.HEALTHY, "ok"))
    assert registry.check().checks[0].name == "canonical"
