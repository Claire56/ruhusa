from __future__ import annotations

import os

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa.postgres import create_postgres_pool, initialize_postgres_schema  # noqa: E402
from ruhusa.postgres_health import (  # noqa: E402
    build_postgres_health_registry,
    postgres_audit_chain_probe,
    postgres_connectivity_probe,
    postgres_schema_probe,
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


@pytest.fixture
def pool():
    assert TEST_DSN is not None
    p = create_postgres_pool(TEST_DSN, min_size=1, max_size=5)
    _drop_all(p)
    try:
        yield p
    finally:
        try:
            _drop_all(p)
        finally:
            p.close()


def test_connectivity_probe(pool) -> None:
    assert postgres_connectivity_probe(pool) is True


def test_schema_probe_after_migration(pool) -> None:
    initialize_postgres_schema(pool)
    assert postgres_schema_probe(pool) is True


def test_schema_probe_before_migration_is_unhealthy(pool) -> None:
    # No schema created — probe must return False, not raise.
    result = postgres_schema_probe(pool)
    assert result is False


def test_audit_chain_probe_after_migration(pool) -> None:
    initialize_postgres_schema(pool)
    assert postgres_audit_chain_probe(pool) is True


def test_build_registry_reports_healthy_after_migration(pool) -> None:
    initialize_postgres_schema(pool)
    registry = build_postgres_health_registry(pool)
    report = registry.check()
    assert report.healthy is True
    names = {c.name for c in report.checks}
    assert "postgres.connectivity" in names
    assert "postgres.schema" in names
    assert "postgres.audit_chain" in names


def test_build_registry_without_audit_chain(pool) -> None:
    initialize_postgres_schema(pool)
    registry = build_postgres_health_registry(pool, include_audit_chain=False)
    report = registry.check()
    assert report.healthy is True
    names = {c.name for c in report.checks}
    assert "postgres.audit_chain" not in names


def test_schema_version_mismatch_is_unhealthy(pool) -> None:
    initialize_postgres_schema(pool)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE ruhusa_schema_metadata SET version = 999 WHERE singleton = TRUE")
    assert postgres_schema_probe(pool) is False


def test_audit_chain_corruption_is_unhealthy(pool) -> None:
    initialize_postgres_schema(pool)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE ruhusa_audit_chain SET last_hash = 'tampered' WHERE singleton = TRUE"
            )
    assert postgres_audit_chain_probe(pool) is False
