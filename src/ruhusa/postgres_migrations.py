from __future__ import annotations

import hashlib

from psycopg import Cursor

# Transaction-scoped advisory lock key for serializing concurrent schema
# migrations. All Ruhusa processes competing to migrate must agree on this
# value. The key is arbitrary but must be consistent across deployments.
_ADVISORY_LOCK_KEY = 7268724

# DDL that creates the migration history table. This statement is also the
# body of the v1→v2 migration: schema v2 introduces migration tracking itself.
#
# version_to UNIQUE prevents duplicate history rows for the same step.
# CHECK (version_to = version_from + 1) enforces single-step migrations.
_MIGRATION_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS ruhusa_schema_migrations (
    migration_id BIGSERIAL PRIMARY KEY,
    version_from INTEGER NOT NULL,
    version_to INTEGER NOT NULL UNIQUE,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (version_to = version_from + 1)
)
"""

# The v1→v2 migration creates the migration history infrastructure.
_MIGRATION_V1_TO_V2 = _MIGRATION_TABLE_DDL

# Hardcoded SHA-256 of _MIGRATION_V1_TO_V2. This must NOT be computed from
# the SQL at runtime: the purpose of the constant is to detect edits to
# already-released migration SQL. If you change _MIGRATION_V1_TO_V2 you must
# also recompute this value — and doing so means releasing a new migration,
# not patching an existing one.
_CHECKSUM_V1_TO_V2 = "48edbed3d9348b746c410ac89cc7a7d042f597a5871ad9810bfa6de0c1119e9f"

# Current-schema DDL for durable approvals. Fresh schema creation imports this
# statement, while an existing schema-v2 database reaches the same object via
# the v2→v3 migration below. Keeping one canonical SQL body prevents fresh and
# upgraded databases from drifting.
APPROVAL_SCHEMA_DDL = "CREATE TABLE IF NOT EXISTS ruhusa_approvals (\n    approval_id TEXT PRIMARY KEY,\n    invocation_id TEXT NOT NULL\n        REFERENCES ruhusa_invocations(invocation_id)\n        ON DELETE RESTRICT,\n    task_id TEXT NOT NULL,\n    state TEXT NOT NULL DEFAULT 'pending'\n        CHECK (\n            state IN (\n                'pending',\n                'approved',\n                'consumed',\n                'rejected',\n                'revoked',\n                'expired'\n            )\n        ),\n    active_invocation_id TEXT\n        GENERATED ALWAYS AS (\n            CASE\n                WHEN state IN ('pending', 'approved') THEN invocation_id\n                ELSE NULL\n            END\n        ) STORED UNIQUE,\n    requested_at TIMESTAMPTZ NOT NULL,\n    expires_at TIMESTAMPTZ NOT NULL,\n    approved_by TEXT,\n    approved_at TIMESTAMPTZ,\n    rejected_by TEXT,\n    rejected_at TIMESTAMPTZ,\n    revoked_by TEXT,\n    revoked_at TIMESTAMPTZ,\n    consumed_at TIMESTAMPTZ,\n    consumed_claim_id TEXT,\n    consumed_attempt INTEGER\n        CHECK (consumed_attempt IS NULL OR consumed_attempt > 0),\n    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,\n    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,\n    CHECK (expires_at > requested_at),\n    CHECK (\n        state <> 'approved'\n        OR (\n            approved_by IS NOT NULL\n            AND approved_at IS NOT NULL\n        )\n    ),\n    CHECK (\n        state <> 'rejected'\n        OR (\n            rejected_by IS NOT NULL\n            AND rejected_at IS NOT NULL\n        )\n    ),\n    CHECK (\n        state <> 'revoked'\n        OR (\n            revoked_by IS NOT NULL\n            AND revoked_at IS NOT NULL\n        )\n    ),\n    CHECK (\n        state <> 'consumed'\n        OR (\n            approved_by IS NOT NULL\n            AND approved_at IS NOT NULL\n            AND consumed_at IS NOT NULL\n            AND consumed_claim_id IS NOT NULL\n            AND consumed_attempt IS NOT NULL\n        )\n    )\n)"

# v2→v3 introduces durable, invocation-bound human approvals.
_MIGRATION_V2_TO_V3 = APPROVAL_SCHEMA_DDL

# Hardcoded SHA-256 of _MIGRATION_V2_TO_V3.
_CHECKSUM_V2_TO_V3 = "be0a98f0642f61253c736d63261063c853a1bd998f0bac55ac470f0c210dc605"

# Registry of available migration steps: (from_version, to_version) maps to
# (sql, expected_checksum). Each step is atomic within the caller's
# transaction.
_MIGRATION_STEPS: dict[tuple[int, int], tuple[str, str]] = {
    (1, 2): (_MIGRATION_V1_TO_V2, _CHECKSUM_V1_TO_V2),
    (2, 3): (_MIGRATION_V2_TO_V3, _CHECKSUM_V2_TO_V3),
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


def validate_migration_history(cur: Cursor) -> None:
    """Validate migration checksum integrity for every present history row.

    Reads each row from ruhusa_schema_migrations and verifies its stored
    checksum against the expected value from _MIGRATION_STEPS.

    Scope and limitations: this validates checksums of rows that are present.
    It does not make migration history itself tamper-evident against a
    privileged database administrator.
    """
    cur.execute(
        """
        SELECT version_from, version_to, checksum
        FROM ruhusa_schema_migrations
        ORDER BY migration_id
        """
    )
    rows = cur.fetchall()

    for version_from, version_to, stored_checksum in rows:
        step = (version_from, version_to)

        if step not in _MIGRATION_STEPS:
            raise RuntimeError(
                f"unrecognized migration step {step} found in history; "
                f"this database may have been managed by a different "
                f"version of Ruhusa"
            )

        _, expected_checksum = _MIGRATION_STEPS[step]

        if stored_checksum != expected_checksum:
            raise RuntimeError(
                f"migration {step} history checksum mismatch: "
                f"stored {stored_checksum!r} does not match expected "
                f"{expected_checksum!r}; "
                f"migration history may have been tampered with"
            )
