from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa import cli  # noqa: E402
from ruhusa.postgres import (  # noqa: E402
    create_postgres_pool,
    initialize_postgres_schema,
)

TEST_DSN = os.getenv("RUHUSA_TEST_POSTGRES_DSN")

pytestmark = pytest.mark.skipif(
    TEST_DSN is None,
    reason="RUHUSA_TEST_POSTGRES_DSN is not configured",
)

_ALL_TABLES = (
    "ruhusa_audit_events",
    "ruhusa_audit_chain",
    "ruhusa_executions",
    "ruhusa_tools",
    "ruhusa_invocations",
    "ruhusa_revocations",
    "ruhusa_grants",
    "ruhusa_schema_migrations",
    "ruhusa_schema_metadata",
)


def _drop_all(pool) -> None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            for table in _ALL_TABLES:
                cur.execute(f"DROP TABLE IF EXISTS {table} CASCADE")


def test_real_postgres_health_cli(monkeypatch, capsys) -> None:
    assert TEST_DSN is not None

    pool = create_postgres_pool(TEST_DSN, min_size=1, max_size=2)
    _drop_all(pool)
    initialize_postgres_schema(pool)
    pool.close()

    monkeypatch.setenv("RUHUSA_CLI_TEST_DSN", TEST_DSN)

    try:
        exit_code = cli.main(
            [
                "postgres",
                "health",
                "--dsn-env",
                "RUHUSA_CLI_TEST_DSN",
                "--json",
            ]
        )

        assert exit_code == cli.EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is True
        assert payload["healthy"] is True
        names = {check["name"] for check in payload["checks"]}
        assert names == {
            "postgres.connectivity",
            "postgres.schema",
            "postgres.audit_chain",
        }
    finally:
        cleanup_pool = create_postgres_pool(TEST_DSN, min_size=1, max_size=2)
        try:
            _drop_all(cleanup_pool)
        finally:
            cleanup_pool.close()
