"""v0.9-D3 schema-v4 signed recovery receipt migration checks."""

from __future__ import annotations

import hashlib
import os

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa.postgres import SCHEMA_VERSION, create_postgres_pool, initialize_postgres_schema
from ruhusa.postgres_migrations import (
    _CHECKSUM_V3_TO_V4,
    _MIGRATION_STEPS,
    RECOVERY_RECEIPTS_SCHEMA_DDL,
)


def test_recovery_receipts_migration_frozen():
    assert SCHEMA_VERSION == 4
    assert hashlib.sha256(RECOVERY_RECEIPTS_SCHEMA_DDL.encode()).hexdigest() == _CHECKSUM_V3_TO_V4
    assert _MIGRATION_STEPS[(3, 4)] == (RECOVERY_RECEIPTS_SCHEMA_DDL, _CHECKSUM_V3_TO_V4)


def test_recovery_receipts_ddl_has_replay_constraints():
    sql = RECOVERY_RECEIPTS_SCHEMA_DDL
    assert "evidence_id TEXT PRIMARY KEY" in sql
    assert "UNIQUE (invocation_id, claim_id, attempt)" in sql
    assert "REFERENCES ruhusa_executions(invocation_id)" in sql


@pytest.mark.skipif(not os.getenv("RUHUSA_TEST_POSTGRES_DSN"), reason="test DSN not set")
def test_schema_v4_initialize_idempotently_installs_recovery_table():
    pool = create_postgres_pool(os.environ["RUHUSA_TEST_POSTGRES_DSN"])
    try:
        initialize_postgres_schema(pool)
        initialize_postgres_schema(pool)
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version FROM ruhusa_schema_metadata WHERE singleton = TRUE")
                assert cur.fetchone() == (4,)
                cur.execute("SELECT to_regclass('public.ruhusa_recovery_receipts')")
                assert cur.fetchone()[0] is not None
    finally:
        pool.close()
