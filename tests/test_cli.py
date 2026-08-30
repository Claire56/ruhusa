from __future__ import annotations

import json

import pytest

from ruhusa import cli
from ruhusa.health import HealthCheckResult, HealthReport, HealthStatus


class FakePool:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeRegistry:
    def __init__(self, report: HealthReport) -> None:
        self._report = report

    def check(self) -> HealthReport:
        return self._report


def _report(*, healthy: bool) -> HealthReport:
    from datetime import UTC, datetime

    return HealthReport(
        generated_at=datetime(2026, 8, 29, 18, 0, tzinfo=UTC),
        checks=(
            HealthCheckResult(
                name="postgres.connectivity",
                status=(HealthStatus.HEALTHY if healthy else HealthStatus.UNHEALTHY),
            ),
        ),
    )


def _fake_support(
    monkeypatch,
    *,
    report: HealthReport | None = None,
    schema: bool = True,
    audit: bool = True,
):
    pool = FakePool()
    selected_report = report or _report(healthy=True)

    def create_pool(dsn: str, *, timeout: float):
        assert dsn == "postgresql://example"
        assert timeout == 5.0
        return pool

    def build_registry(pool_arg, *, include_audit_chain: bool):
        assert pool_arg is pool
        return FakeRegistry(selected_report)

    def schema_probe(pool_arg):
        assert pool_arg is pool
        return schema

    def audit_probe(pool_arg):
        assert pool_arg is pool
        return audit

    monkeypatch.setattr(
        cli,
        "_postgres_support",
        lambda: (
            create_pool,
            build_registry,
            schema_probe,
            audit_probe,
        ),
    )
    monkeypatch.setenv("RUHUSA_POSTGRES_DSN", "postgresql://example")
    return pool


def test_version_json_is_machine_readable(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_package_version", lambda: "0.8.0")

    assert cli.main(["version", "--json"]) == cli.EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload == {"ok": True, "version": "0.8.0"}


def test_doctor_json_has_expected_shape(capsys) -> None:
    assert cli.main(["doctor", "--json"]) == cli.EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert set(payload) == {
        "fastapi_extra_available",
        "ok",
        "postgres_extra_available",
        "python",
        "ruhusa",
    }


def test_missing_dsn_environment_variable_is_usage_error(monkeypatch, capsys) -> None:
    monkeypatch.delenv("RUHUSA_POSTGRES_DSN", raising=False)

    assert cli.main(["postgres", "health"]) == cli.EXIT_USAGE

    captured = capsys.readouterr()
    assert "RUHUSA_POSTGRES_DSN" in captured.err
    assert "not set" in captured.err


def test_missing_dsn_json_error_is_machine_readable(monkeypatch, capsys) -> None:
    monkeypatch.delenv("RUHUSA_POSTGRES_DSN", raising=False)

    assert cli.main(["postgres", "health", "--json"]) == cli.EXIT_USAGE

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["exit_code"] == cli.EXIT_USAGE


def test_postgres_health_success_and_pool_close(monkeypatch, capsys) -> None:
    pool = _fake_support(monkeypatch)

    assert cli.main(["postgres", "health"]) == cli.EXIT_OK

    output = capsys.readouterr().out
    assert "HEALTHY" in output
    assert "overall: healthy" in output
    assert pool.closed is True


def test_postgres_health_unhealthy_returns_exit_one(monkeypatch, capsys) -> None:
    pool = _fake_support(monkeypatch, report=_report(healthy=False))

    assert cli.main(["postgres", "health", "--json"]) == cli.EXIT_UNHEALTHY

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["healthy"] is False
    assert pool.closed is True


def test_postgres_schema_command(monkeypatch, capsys) -> None:
    pool = _fake_support(monkeypatch, schema=False)

    assert cli.main(["postgres", "schema", "--json"]) == cli.EXIT_UNHEALTHY

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "check": "postgres.schema",
        "healthy": False,
        "ok": False,
    }
    assert pool.closed is True


def test_postgres_audit_command(monkeypatch, capsys) -> None:
    pool = _fake_support(monkeypatch, audit=True)

    assert cli.main(["postgres", "audit", "--json"]) == cli.EXIT_OK

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "check": "postgres.audit_chain",
        "ok": True,
        "valid": True,
    }
    assert pool.closed is True


def test_connection_failure_does_not_expose_dsn(monkeypatch, capsys) -> None:
    secret_dsn = "postgresql://user:super-secret@database/private"
    monkeypatch.setenv("RUHUSA_POSTGRES_DSN", secret_dsn)

    def create_pool(dsn: str, *, timeout: float):
        assert dsn == secret_dsn
        raise RuntimeError(f"could not connect to {dsn}")

    monkeypatch.setattr(
        cli,
        "_postgres_support",
        lambda: (create_pool, None, None, None),
    )

    assert cli.main(["postgres", "health"]) == cli.EXIT_UNHEALTHY

    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err
    assert "super-secret" not in captured.err
    assert secret_dsn not in captured.err


def test_probe_failure_does_not_expose_backend_error(monkeypatch, capsys) -> None:
    pool = FakePool()
    monkeypatch.setenv("RUHUSA_POSTGRES_DSN", "postgresql://example")

    def create_pool(dsn: str, *, timeout: float):
        return pool

    class BrokenRegistry:
        def check(self):
            raise RuntimeError("password=very-secret")

    def build_registry(pool_arg, *, include_audit_chain: bool):
        return BrokenRegistry()

    monkeypatch.setattr(
        cli,
        "_postgres_support",
        lambda: (create_pool, build_registry, None, None),
    )

    assert cli.main(["postgres", "health"]) == cli.EXIT_UNHEALTHY

    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err
    assert "very-secret" not in captured.err
    assert pool.closed is True


def test_custom_dsn_environment_variable_is_supported(monkeypatch, capsys) -> None:
    pool = FakePool()
    monkeypatch.setenv("MY_RUHUSA_DSN", "postgresql://example")

    def create_pool(dsn: str, *, timeout: float):
        assert dsn == "postgresql://example"
        return pool

    def build_registry(pool_arg, *, include_audit_chain: bool):
        return FakeRegistry(_report(healthy=True))

    monkeypatch.setattr(
        cli,
        "_postgres_support",
        lambda: (create_pool, build_registry, None, None),
    )

    assert (
        cli.main(
            [
                "postgres",
                "health",
                "--dsn-env",
                "MY_RUHUSA_DSN",
            ]
        )
        == cli.EXIT_OK
    )

    assert pool.closed is True
    assert "overall: healthy" in capsys.readouterr().out


def test_timeout_must_be_positive() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["postgres", "health", "--timeout", "0"])

    assert exc_info.value.code == cli.EXIT_USAGE
