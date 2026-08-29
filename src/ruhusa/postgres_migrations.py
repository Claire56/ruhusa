from __future__ import annotations

import hashlib

from psycopg import Cursor

# Transaction-scoped advisory lock key for serializing concurrent schema
# migrations. All Ruhusa processes competing to migrate must agree on this
# value. The key is arbitrary but must be consistent across deployments.
_ADVISORY_LOCK_KEY = 7268724

# DDL that creates the migration history table. This statement is also the
# body of the v1→v2 migration: schema v2 introduces migration tracking itself.
_MIGRATION_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS ruhusa_schema_migrations (
    migration_id BIGSERIAL PRIMARY KEY,
    version_from INTEGER NOT NULL,
    version_to INTEGER NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""

# The v1→v2 migration creates the migration history infrastructure.
_MIGRATION_V1_TO_V2 = _MIGRATION_TABLE_DDL

# Expected SHA-256 of the v1→v2 migration SQL. Changing _MIGRATION_V1_TO_V2
# without updating this constant will cause run_migrations to raise at
# runtime. Historical migration SQL must be treated as immutable.
_CHECKSUM_V1_TO_V2 = hashlib.sha256(_MIGRATION_V1_TO_V2.encode()).hexdigest()

# Registry of available migration steps: (from_version, to_version) maps to
# (sql, expected_checksum). Each step is atomic within the caller's
# transaction.
_MIGRATION_STEPS: dict[tuple[int, int], tuple[str, str]] = {
    (1, 2): (_MIGRATION_V1_TO_V2, _CHECKSUM_V1_TO_V2),
}


def acquire_migration_lock(cur: Cursor) -> None:
    """Acquire a transaction-scoped advisory lock for schema migrations.

    The lock is released automatically when the enclosing transaction commits
    or rolls back. Only one process may hold this lock at a time, so
    concurrent initializers are serialized at the database level rather than
    at the application level.
    """
    cur.execute("SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,))


def run_migrations(cur: Cursor, from_version: int, to_version: int) -> None:
    """Execute all migration steps from from_version up to to_version.

    Bootstraps the migration history table before executing any step so that
    the history table itself can be recorded as a migration artifact. Each
    step is verified against its expected checksum before execution; a
    mismatch indicates that historical migration SQL has been modified and
    raises RuntimeError.

    The caller is responsible for holding the migration advisory lock and for
    updating ruhusa_schema_metadata.version after this function returns.
    """
    # Bootstrap: create the history table as infrastructure so we can record
    # migration steps into it. This is always CREATE TABLE IF NOT EXISTS and
    # is safe to run even if the table already exists.
    cur.execute(_MIGRATION_TABLE_DDL)

    current = from_version
    while current < to_version:
        step = (current, current + 1)

        if step not in _MIGRATION_STEPS:
            raise RuntimeError(f"no migration path from schema version {current} to {current + 1}")

        sql, expected_checksum = _MIGRATION_STEPS[step]

        actual_checksum = hashlib.sha256(sql.encode()).hexdigest()
        if actual_checksum != expected_checksum:
            raise RuntimeError(
                f"migration {step} SQL checksum mismatch: "
                f"expected {expected_checksum!r}, got {actual_checksum!r}; "
                f"historical migration SQL must not be modified"
            )

        cur.execute(sql)

        cur.execute(
            """
            INSERT INTO ruhusa_schema_migrations (
                version_from,
                version_to,
                checksum
            )
            VALUES (%s, %s, %s)
            """,
            (current, current + 1, actual_checksum),
        )

        current += 1
