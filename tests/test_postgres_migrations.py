from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa.postgres_migrations import (  # noqa: E402
    _ADVISORY_LOCK_KEY,
    _CHECKSUM_V1_TO_V2,
    _MIGRATION_STEPS,
    _MIGRATION_V1_TO_V2,
)

from ruhusa.postgres import (  # noqa: E402
    _SCHEMA_STATEMENTS,
    SCHEMA_VERSION,
    PostgresAuditLog,
    create_postgres_pool,
    initialize_postgres_schema,
)

TEST_DSN = os.getenv("RUHUSA_TEST_POSTGRES_DSN")

pytestmark = pytest.mark.skipif(
    TEST_DSN is None,
    reason="RUHUSA_TEST_POSTGRES_DSN is not configured",
)

# ---------------------------------------------------------------------------
# Schema constants sanity checks
# ---------------------------------------------------------------------------


def test_migration_checksum_matches_sql() -> None:
    """_CHECKSUM_V1_TO_V2 must be the SHA-256 of _MIGRATION_V1_TO_V2.

    This test is meaningful because _CHECKSUM_V1_TO_V2 is a hardcoded literal,
    not computed from the SQL. If someone edits _MIGRATION_V1_TO_V2 without
    updating the constant, this test catches it before the checksum guard can
    be bypassed in production.
    """
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
# Fixtures and helpers
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

    p = create_postgres_pool(
        TEST_DSN,
        min_size=1,
        max_size=20,
    )

    _drop_all(p)

    try:
        yield p
    finally:
        try:
            _drop_all(p)
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


def _insert_audit_event_v1(pool) -> None:
    """Insert one valid audit event into a v1-era audit chain.

    Computes the event_hash using the same algorithm as PostgresAuditLog.append
    so that verify_chain() will pass after migration. The chain head row is
    assumed to already exist at (last_sequence=0, last_hash='GENESIS') from the
    INSERT statement included in _SCHEMA_STATEMENTS.
    """
    audit_id = "audit-v1-preservation"
    timestamp = "2026-01-01T00:00:00+00:00"
    payload = {
        "audit_id": audit_id,
        "timestamp": timestamp,
        "principal_id": "agent-1",
        "task_id": "task-v1",
        "action": "read",
        "resource": "resource/foo",
        "arguments": {},
        "effect": "allow",
        "reason": "v1 test event",
        "policy_id": "grant-v1-preservation",
        "previous_hash": "GENESIS",
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    event_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ruhusa_audit_events (
                    sequence, audit_id, timestamp,
                    principal_id, task_id, action, resource,
                    arguments, effect, reason, policy_id,
                    previous_hash, event_hash
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)
                """,
                (
                    1,
                    audit_id,
                    timestamp,
                    "agent-1",
                    "task-v1",
                    "read",
                    "resource/foo",
                    "{}",
                    "allow",
                    "v1 test event",
                    "grant-v1-preservation",
                    "GENESIS",
                    event_hash,
                ),
            )
            cur.execute(
                """
                UPDATE ruhusa_audit_chain
                SET last_sequence = 1,
                    last_hash = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE singleton = TRUE
                """,
                (event_hash,),
            )


def _setup_v1_schema(pool) -> None:
    """Create a complete v1-era schema with one row in every security table.

    v1 has no ruhusa_schema_migrations. One representative row per security
    category (grant, revocation, invocation, tool, execution, audit event)
    is inserted so that state-preservation tests exercise all durable security
    tables.

    TODO (v0.8-RC): replace the DDL here with a frozen snapshot of the v0.7
    schema rather than filtering the current _SCHEMA_STATEMENTS. Using the
    live DDL means a future addition to _SCHEMA_STATEMENTS could silently make
    the "v1" fixture include schema objects that did not exist in v0.7.
    """
    _drop_all(pool)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Metadata table at version 1
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

            # All v1 application tables from the shared DDL, excluding the
            # migrations table which did not exist in v1.
            for statement in _SCHEMA_STATEMENTS:
                if "ruhusa_schema_migrations" not in statement:
                    cur.execute(statement)

            # One grant
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
                    "grant-v1-preservation",
                    "orchestrator",
                    "agent-1",
                    "task-v1",
                    '["read"]',
                    '["resource/"]',
                    "{}",
                    "2026-01-01T00:00:00",
                    "2027-01-01T00:00:00",
                ),
            )

            # One revocation
            cur.execute(
                """
                INSERT INTO ruhusa_revocations (grant_id, revoked_at, reason)
                VALUES (%s, CURRENT_TIMESTAMP, %s)
                """,
                ("revoked-v1-preservation", "v1 test revocation"),
            )

            # One invocation
            cur.execute(
                """
                INSERT INTO ruhusa_invocations (
                    invocation_id, invoking_principal_id, executing_principal_id,
                    task_id, action, resource, arguments_digest,
                    recorded_at, expires_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    "inv-v1-preservation",
                    "orchestrator",
                    "agent-1",
                    "task-v1",
                    "read",
                    "resource/foo",
                    "sha256:abc123",
                    "2026-01-01T00:00:00",
                    "2026-01-02T00:00:00",
                ),
            )

            # One tool registration
            cur.execute(
                """
                INSERT INTO ruhusa_tools (tool_id, implementation_id, allowed_actions)
                VALUES (%s, %s, %s::jsonb)
                """,
                ("tool-v1-preservation", "sha256:impl-v1", '["read"]'),
            )

            # One execution record
            cur.execute(
                """
                INSERT INTO ruhusa_executions (invocation_id, expires_at, state)
                VALUES (%s, CURRENT_TIMESTAMP + INTERVAL '1 hour', 'available')
                """,
                ("inv-v1-preservation",),
            )

    # One audit event with a valid hash chain. This is inserted after the main
    # connection block so that the audit chain head row (written by the
    # _SCHEMA_STATEMENTS INSERT) is visible in a fresh transaction.
    _insert_audit_event_v1(pool)


# ---------------------------------------------------------------------------
# Integration tests — fresh install
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


def test_concurrent_fresh_initialization(pool) -> None:
    """Concurrent callers against an empty DB must all succeed with one schema.

    The advisory lock must prevent double-initialization: all callers return
    without error, exactly one metadata row is written, and the schema is
    valid throughout.
    """
    _drop_all(pool)

    errors: list[Exception] = []

    def try_init() -> None:
        try:
            initialize_postgres_schema(pool)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(try_init) for _ in range(15)]
        concurrent.futures.wait(futures)

    assert errors == [], f"concurrent initializers failed: {errors}"
    assert _read_version(pool) == SCHEMA_VERSION
    assert _table_exists(pool, "ruhusa_grants")
    assert _table_exists(pool, "ruhusa_schema_migrations")

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM ruhusa_schema_metadata")
            row = cur.fetchone()
    assert row == (1,), f"expected exactly one metadata row; got {row}"


# ---------------------------------------------------------------------------
# Integration tests — v1 → v2 migration
# ---------------------------------------------------------------------------


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
    """Re-initializing an already-migrated database must not add history rows."""
    _setup_v1_schema(pool)

    initialize_postgres_schema(pool)
    initialize_postgres_schema(pool)
    initialize_postgres_schema(pool)

    rows = _migration_rows(pool)
    assert len(rows) == 1, f"expected one history row after repeated init; got {len(rows)}"


def test_migration_preserves_all_security_state(pool) -> None:
    """Every v1 security record must survive the v1→v2 migration unchanged.

    Verifies that grants, revocations, invocations, tool registrations,
    executions, and the audit event chain all survive the v1→v2 migration
    intact. The audit chain is verified end-to-end via PostgresAuditLog so
    that any corruption of event_hash or chain linkage is caught.
    """
    _setup_v1_schema(pool)

    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT grant_id FROM ruhusa_grants WHERE grant_id = %s",
                ("grant-v1-preservation",),
            )
            assert cur.fetchone() is not None, "grant lost after migration"

            cur.execute(
                "SELECT grant_id FROM ruhusa_revocations WHERE grant_id = %s",
                ("revoked-v1-preservation",),
            )
            assert cur.fetchone() is not None, "revocation lost after migration"

            cur.execute(
                "SELECT invocation_id FROM ruhusa_invocations WHERE invocation_id = %s",
                ("inv-v1-preservation",),
            )
            assert cur.fetchone() is not None, "invocation lost after migration"

            cur.execute(
                "SELECT tool_id FROM ruhusa_tools WHERE tool_id = %s",
                ("tool-v1-preservation",),
            )
            assert cur.fetchone() is not None, "tool registration lost after migration"

            cur.execute(
                "SELECT invocation_id FROM ruhusa_executions WHERE invocation_id = %s",
                ("inv-v1-preservation",),
            )
            assert cur.fetchone() is not None, "execution record lost after migration"

            cur.execute(
                "SELECT audit_id FROM ruhusa_audit_events WHERE audit_id = %s",
                ("audit-v1-preservation",),
            )
            assert cur.fetchone() is not None, "audit event lost after migration"

    # Verify the hash chain is intact end-to-end after migration.
    assert PostgresAuditLog(pool).verify_chain() is True, (
        "audit chain integrity failed after v1→v2 migration"
    )


def test_migration_rollback_preserves_version(pool, monkeypatch) -> None:
    """A failing migration must roll back the entire transaction.

    The schema version must remain at the pre-migration value, no
    history row may be written, and the migrations table itself must
    not exist after the rollback (it was created inside the failed
    transaction).
    """
    import ruhusa.postgres_migrations as _pm

    _setup_v1_schema(pool)

    # Replace the (1, 2) step with SQL that PostgreSQL will reject.
    bad_sql = "NOT VALID SQL THAT WILL FAIL"
    bad_checksum = hashlib.sha256(bad_sql.encode()).hexdigest()
    monkeypatch.setattr(
        _pm,
        "_MIGRATION_STEPS",
        {(1, 2): (bad_sql, bad_checksum)},
    )

    with pytest.raises(Exception):
        initialize_postgres_schema(pool)

    # The transaction rolled back: version stays at 1.
    assert _read_version(pool) == 1

    # The migrations table was created inside the failed transaction and
    # must not exist after rollback.
    assert not _table_exists(pool, "ruhusa_schema_migrations")


# ---------------------------------------------------------------------------
# Integration tests — future / unsupported versions
# ---------------------------------------------------------------------------


def test_future_schema_version_fails_before_any_application_ddl(pool) -> None:
    """A future schema version must be rejected before any application table is touched.

    This test starts from a database that has ONLY the metadata table so that
    it proves the guard fires before any application DDL is attempted — unlike
    a test that first initializes a complete schema and then bumps the version.
    """
    _drop_all(pool)

    # Create ONLY the metadata table with a future version.
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE ruhusa_schema_metadata (
                    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
                    version INTEGER NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cur.execute(
                "INSERT INTO ruhusa_schema_metadata (singleton, version) VALUES (TRUE, 999)"
            )

    with pytest.raises(RuntimeError, match="unsupported Ruhusa PostgreSQL schema version"):
        initialize_postgres_schema(pool)

    # No application table should have been created.
    for table in _ALL_TABLES:
        if table != "ruhusa_schema_metadata":
            assert not _table_exists(pool, table), (
                f"{table} must not exist after future-version rejection"
            )


# ---------------------------------------------------------------------------
# Integration tests — tamper detection
# ---------------------------------------------------------------------------


def test_migration_history_tamper_is_detected_on_next_startup(pool) -> None:
    """A tampered history checksum must be caught by validate_migration_history.

    After a successful v1→v2 migration the stored checksum is altered to
    simulate a database-level tamper. The next startup must raise RuntimeError
    before serving any authorization traffic.
    """
    _setup_v1_schema(pool)
    initialize_postgres_schema(pool)

    # Confirm history was written correctly.
    rows = _migration_rows(pool)
    assert len(rows) == 1

    # Tamper: overwrite the checksum with a plausible-looking but wrong value.
    tampered = "a" * 64
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE ruhusa_schema_migrations SET checksum = %s",
                (tampered,),
            )

    # The next startup must detect the tamper.
    with pytest.raises(
        RuntimeError,
        match="migration history may have been tampered with",
    ):
        initialize_postgres_schema(pool)
