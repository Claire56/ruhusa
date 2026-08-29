from __future__ import annotations

import hashlib
import os

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa.postgres import (  # noqa: E402
    SCHEMA_VERSION,
    create_postgres_pool,
    initialize_postgres_schema,
)
from ruhusa.postgres_migrations import (  # noqa: E402
    _ADVISORY_LOCK_KEY,
    _CHECKSUM_V1_TO_V2,
    _MIGRATION_STEPS,
    _MIGRATION_V1_TO_V2,
)

TEST_DSN = os.getenv("RUHUSA_TEST_POSTGRES_DSN")

pytestmark = pytest.mark.skipif(
    TEST_DSN is None,
    reason="RUHUSA_TEST_POSTGRES_DSN is not configured",
)

# ---------------------------------------------------------------------------
# Schema constants sanity checks (no database required, but gated by the
# DSN mark so they only run in CI where psycopg is installed)
# ---------------------------------------------------------------------------


def test_migration_checksum_matches_sql() -> None:
    """The hardcoded v1→v2 checksum must match the SQL it guards."""
    expected = hashlib.sha256(_MIGRATION_V1_TO_V2.encode()).hexdigest()
    assert expected == _CHECKSUM_V1_TO_V2


def test_migration_steps_registry_is_complete() -> None:
    """Every integer step from 1 to SCHEMA_VERSION must be registered."""
    for v in range(1, SCHEMA_VERSION):
        assert (v, v + 1) in _MIGRATION_STEPS, f"no migration step registered for ({v}, {v + 1})"


def test_advisory_lock_key_is_stable() -> None:
    """The advisory lock key must not be changed between releases."""
    assert _ADVISORY_LOCK_KEY == 7268724


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


@pytest.fixture
def pool():
    assert TEST_DSN is not None
    p = create_postgres_pool(TEST_DSN, min_size=1, max_size=5)
    try:
        yield p
    finally:
        p.close()


def _drop_all(pool) -> None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            for table in _ALL_TABLES:
                cur.execute(f"DROP TABLE IF EXISTS {table} CASCADE")


def _table_exists(pool, table: str) -> bool:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT to_regclass(%s) IS NOT NULL",
                (f"public.{table}",),
            )
            row = cur.fetchone()
    return bool(row and row[0])


def _read_version(pool) -> int | None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version FROM ruhusa_schema_metadata WHERE singleton = TRUE")
            row = cur.fetchone()
    return None if row is None else row[0]


def _migration_rows(pool) -> list[tuple[int, int, str]]:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT version_from, version_to, checksum
                FROM ruhusa_schema_migrations
                ORDER BY migration_id
                """
            )
            return cur.fetchall()


def _setup_v1_schema(pool) -> None:
    """Create a v1-era schema (no ruhusa_schema_migrations, version=1)."""
    _drop_all(pool)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Metadata table and version record
            cur.execute(
                """
                CREATE TABLE ruhusa_schema_metadata (
                    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
                    version INTEGER NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute("INSERT INTO ruhusa_schema_metadata (singleton, version) VALUES (TRUE, 1)")
            # Minimal v1 application tables (enough to prove state survives)
            cur.execute(
                """
                CREATE TABLE ruhusa_grants (
                    grant_id TEXT PRIMARY KEY,
                    grantor_id TEXT NOT NULL,
                    grantee_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    actions JSONB NOT NULL,
                    resource_prefixes JSONB NOT NULL,
                    max_numeric_arguments JSONB NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


def test_fresh_database_initializes_to_schema_version_two(pool) -> None:
    """A fresh database must initialize to the current SCHEMA_VERSION."""
    _drop_all(pool)

    initialize_postgres_schema(pool)

    assert _read_version(pool) == SCHEMA_VERSION
    assert _table_exists(pool, "ruhusa_schema_migrations")
    assert _table_exists(pool, "ruhusa_grants")
    assert _table_exists(pool, "ruhusa_executions")
    assert _table_exists(pool, "ruhusa_audit_events")


def test_fresh_database_has_no_migration_history(pool) -> None:
    """A fresh install must not write any migration-history rows."""
    _drop_all(pool)

    initialize_postgres_schema(pool)

    rows = _migration_rows(pool)
    assert rows == [], f"fresh install should not record migration steps; got {rows!r}"


def test_migration_from_v1_to_v2_creates_migrations_table(pool) -> None:
    """Migrating a v1 database must create ruhusa_schema_migrations."""
    _setup_v1_schema(pool)
    assert not _table_exists(pool, "ruhusa_schema_migrations")

    initialize_postgres_schema(pool)

    assert _table_exists(pool, "ruhusa_schema_migrations")
    assert _read_version(pool) == SCHEMA_VERSION


def test_migration_from_v1_to_v2_records_history(pool) -> None:
    """The v1→v2 migration must write exactly one history row."""
    _setup_v1_schema(pool)

    initialize_postgres_schema(pool)

    rows = _migration_rows(pool)
    assert len(rows) == 1
    version_from, version_to, checksum = rows[0]
    assert version_from == 1
    assert version_to == 2
    assert checksum == _CHECKSUM_V1_TO_V2


def test_migration_from_v1_is_idempotent(pool) -> None:
    """Re-initializing an already-migrated database must not add history."""
    _setup_v1_schema(pool)

    initialize_postgres_schema(pool)
    initialize_postgres_schema(pool)
    initialize_postgres_schema(pool)

    rows = _migration_rows(pool)
    assert len(rows) == 1, f"expected one history row after repeated init; got {len(rows)}"


def test_migration_preserves_existing_state(pool) -> None:
    """Data present before migration must still be readable after."""
    _setup_v1_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ruhusa_grants (
                    grant_id, grantor_id, grantee_id, task_id,
                    actions, resource_prefixes, max_numeric_arguments,
                    issued_at, expires_at
                )
                VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s)
                """,
                (
                    "grant-migration-test",
                    "grantor-1",
                    "grantee-1",
                    "task-1",
                    '["read"]',
                    '["resource/"]',
                    "{}",
                    "2026-01-01T00:00:00",
                    "2027-01-01T00:00:00",
                ),
            )

    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT grant_id FROM ruhusa_grants WHERE grant_id = %s",
                ("grant-migration-test",),
            )
            row = cur.fetchone()

    assert row is not None
    assert row[0] == "grant-migration-test"


def test_unsupported_future_version_raises_runtime_error(pool) -> None:
    """A database at a version newer than SCHEMA_VERSION must be rejected."""
    _drop_all(pool)
    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE ruhusa_schema_metadata SET version = 999 WHERE singleton = TRUE")

    try:
        with pytest.raises(RuntimeError, match="unsupported Ruhusa PostgreSQL schema version"):
            initialize_postgres_schema(pool)
    finally:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ruhusa_schema_metadata SET version = %s WHERE singleton = TRUE",
                    (SCHEMA_VERSION,),
                )
