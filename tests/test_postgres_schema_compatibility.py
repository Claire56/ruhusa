from __future__ import annotations

import os

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa.postgres import (  # noqa: E402
    SCHEMA_VERSION,
    create_postgres_pool,
    initialize_postgres_schema,
)

TEST_DSN = os.getenv("RUHUSA_TEST_POSTGRES_DSN")

pytestmark = pytest.mark.skipif(
    TEST_DSN is None,
    reason="RUHUSA_TEST_POSTGRES_DSN is not configured",
)

RUHUSA_TABLES = (
    "ruhusa_audit_events",
    "ruhusa_audit_chain",
    "ruhusa_executions",
    "ruhusa_tools",
    "ruhusa_invocations",
    "ruhusa_revocations",
    "ruhusa_grants",
    "ruhusa_schema_metadata",
)


@pytest.fixture
def pool():
    assert TEST_DSN is not None

    pool = create_postgres_pool(
        TEST_DSN,
        min_size=1,
        max_size=5,
    )

    try:
        yield pool
    finally:
        pool.close()


def _drop_schema(pool) -> None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            for table in RUHUSA_TABLES:
                cur.execute(f"DROP TABLE IF EXISTS {table} CASCADE")


def _table_exists(pool, table: str) -> bool:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT to_regclass(%s) IS NOT NULL
                """,
                (f"public.{table}",),
            )
            row = cur.fetchone()

    return bool(row and row[0])


def test_fresh_database_initializes_schema_version_one(
    pool,
) -> None:
    _drop_schema(pool)

    initialize_postgres_schema(pool)

    assert _table_exists(pool, "ruhusa_schema_metadata")

    for table in RUHUSA_TABLES[:-1]:
        assert _table_exists(pool, table)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT version
                FROM ruhusa_schema_metadata
                WHERE singleton = TRUE
                """
            )
            row = cur.fetchone()

    assert row == (SCHEMA_VERSION,)


def test_schema_initialization_is_idempotent(
    pool,
) -> None:
    _drop_schema(pool)

    initialize_postgres_schema(pool)
    initialize_postgres_schema(pool)
    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM ruhusa_schema_metadata
                """
            )
            row = cur.fetchone()

    assert row == (1,)


def test_reinitialization_preserves_existing_state(
    pool,
) -> None:
    _drop_schema(pool)
    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ruhusa_tools (
                    tool_id,
                    implementation_id,
                    allowed_actions
                )
                VALUES (%s, %s, %s::jsonb)
                """,
                (
                    "tool-release-test",
                    "sha256:release-test",
                    '["read"]',
                ),
            )

    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT allowed_actions
                FROM ruhusa_tools
                WHERE
                    tool_id = %s
                    AND implementation_id = %s
                """,
                (
                    "tool-release-test",
                    "sha256:release-test",
                ),
            )
            row = cur.fetchone()

    assert row is not None
    assert row[0] == ["read"]


def test_unsupported_schema_version_fails_before_application_ddl(
    pool,
) -> None:
    _drop_schema(pool)
    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE ruhusa_schema_metadata
                SET version = %s
                WHERE singleton = TRUE
                """,
                (999,),
            )

            # Remove one application table so we can prove initialization
            # does not execute application DDL before rejecting the version.
            cur.execute(
                """
                DROP TABLE ruhusa_tools
                """
            )

    try:
        with pytest.raises(
            RuntimeError,
            match="unsupported Ruhusa PostgreSQL schema version",
        ):
            initialize_postgres_schema(pool)

        assert not _table_exists(pool, "ruhusa_tools")

    finally:
        # Restore the shared integration database for following tests.
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE ruhusa_schema_metadata
                    SET version = %s
                    WHERE singleton = TRUE
                    """,
                    (SCHEMA_VERSION,),
                )

        initialize_postgres_schema(pool)
