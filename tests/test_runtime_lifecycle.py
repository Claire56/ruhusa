from __future__ import annotations

import pytest

from ruhusa.config import RuntimeConfig
from ruhusa.errors import ConfigurationError, InvalidStateTransitionError
from ruhusa.health import HealthRegistry
from ruhusa.runtime import (
    ResourceClosedError,
    RuhusaRuntime,
    RuntimeState,
    ShutdownError,
    StartupError,
)


def test_startup_order_and_reverse_shutdown_order() -> None:
    events: list[str] = []
    runtime = RuhusaRuntime()
    runtime.register(
        "database",
        start=lambda: events.append("start:database"),
        close=lambda: events.append("close:database"),
    )
    runtime.register(
        "worker",
        start=lambda: events.append("start:worker"),
        close=lambda: events.append("close:worker"),
    )

    runtime.start()
    runtime.close()

    assert runtime.state is RuntimeState.CLOSED
    assert events == [
        "start:database",
        "start:worker",
        "close:worker",
        "close:database",
    ]


def test_start_and_close_are_idempotent() -> None:
    events: list[str] = []
    runtime = RuhusaRuntime()
    runtime.register(
        "resource",
        start=lambda: events.append("start"),
        close=lambda: events.append("close"),
    )
    runtime.start()
    runtime.start()
    runtime.close()
    runtime.close()
    assert events == ["start", "close"]


def test_register_after_start_is_rejected() -> None:
    runtime = RuhusaRuntime()
    runtime.start()
    with pytest.raises(InvalidStateTransitionError):
        runtime.register("late")


def test_start_after_close_is_rejected() -> None:
    runtime = RuhusaRuntime()
    runtime.close()
    with pytest.raises(ResourceClosedError):
        runtime.start()


def test_duplicate_resource_name_is_rejected() -> None:
    runtime = RuhusaRuntime()
    runtime.register("database")
    with pytest.raises(ConfigurationError, match="already registered"):
        runtime.register("database")


def test_startup_failure_rolls_back_and_closes_runtime() -> None:
    events: list[str] = []
    runtime = RuhusaRuntime()
    runtime.register(
        "database",
        start=lambda: events.append("start:database"),
        close=lambda: events.append("close:database"),
    )

    def fail_worker_start() -> None:
        events.append("start:worker")
        raise RuntimeError("sensitive backend failure")

    runtime.register(
        "worker",
        start=fail_worker_start,
        close=lambda: events.append("close:worker"),
    )

    with pytest.raises(StartupError) as exc_info:
        runtime.start()

    assert exc_info.value.resource == "worker"
    assert "sensitive backend failure" not in str(exc_info.value)
    assert runtime.state is RuntimeState.CLOSED
    assert events == [
        "start:database",
        "start:worker",
        "close:worker",
        "close:database",
    ]


def test_require_healthy_startup_requires_registry() -> None:
    with pytest.raises(ConfigurationError, match="requires a health registry"):
        RuhusaRuntime(config=RuntimeConfig(require_healthy_startup=True))


def test_unhealthy_startup_rolls_back_resources() -> None:
    events: list[str] = []
    health = HealthRegistry()
    health.register("database", lambda: False)
    runtime = RuhusaRuntime(
        config=RuntimeConfig(require_healthy_startup=True),
        health_registry=health,
    )
    runtime.register(
        "database",
        start=lambda: events.append("start"),
        close=lambda: events.append("close"),
    )

    with pytest.raises(StartupError, match="health check failed") as exc_info:
        runtime.start()

    assert exc_info.value.resource == "health"
    assert runtime.state is RuntimeState.CLOSED
    assert events == ["start", "close"]


def test_shutdown_attempts_every_resource_then_raises_sanitized_error() -> None:
    events: list[str] = []
    runtime = RuhusaRuntime()
    runtime.register("database", close=lambda: events.append("close:database"))

    def fail_worker_close() -> None:
        events.append("close:worker")
        raise RuntimeError("postgresql://user:secret@database")

    runtime.register("worker", close=fail_worker_close)
    runtime.start()

    with pytest.raises(ShutdownError) as exc_info:
        runtime.close()

    assert runtime.state is RuntimeState.CLOSED
    assert events == ["close:worker", "close:database"]
    assert exc_info.value.resources == ("worker",)
    assert "secret" not in str(exc_info.value)


def test_shutdown_errors_can_be_best_effort() -> None:
    runtime = RuhusaRuntime(config=RuntimeConfig(fail_on_shutdown_error=False))

    def fail_close() -> None:
        raise RuntimeError("backend down")

    runtime.register("resource", close=fail_close)
    runtime.start()
    runtime.close()
    assert runtime.state is RuntimeState.CLOSED


def test_ensure_running_has_deterministic_closed_behavior() -> None:
    runtime = RuhusaRuntime()

    with pytest.raises(InvalidStateTransitionError):
        runtime.ensure_running()

    runtime.start()
    runtime.ensure_running()
    runtime.close()

    with pytest.raises(ResourceClosedError):
        runtime.ensure_running()


def test_context_manager_closes_on_success() -> None:
    events: list[str] = []
    runtime = RuhusaRuntime()
    runtime.register(
        "resource",
        start=lambda: events.append("start"),
        close=lambda: events.append("close"),
    )

    with runtime:
        assert runtime.state is RuntimeState.RUNNING

    assert events == ["start", "close"]


def test_body_exception_is_not_masked_by_shutdown_failure() -> None:
    runtime = RuhusaRuntime()

    def fail_close() -> None:
        raise RuntimeError("shutdown failed")

    runtime.register("resource", close=fail_close)

    with pytest.raises(ValueError, match="application failure"):
        with runtime:
            raise ValueError("application failure")

    assert runtime.state is RuntimeState.CLOSED
