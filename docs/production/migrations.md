# PostgreSQL Schema Migrations

Ruhusa manages its PostgreSQL schema version automatically. When
`initialize_postgres_schema` is called, it detects the current schema version,
runs any applicable migration steps inside a single transaction, and advances
the version atomically. No manual migration tooling is required.

## How it works

On startup, `initialize_postgres_schema` follows this sequence:

1. Acquires a PostgreSQL transaction-scoped advisory lock
   (`pg_advisory_xact_lock`) before any application DDL. Only one process may
   hold this lock at a time. Concurrent callers queue behind it and observe the
   result of the first caller when they proceed.
2. Creates `ruhusa_schema_metadata` if it does not exist (under the lock).
3. Reads the current schema version.
4. If the version is newer than the running Ruhusa build, raises `RuntimeError`
   without touching any application table. Downgrade is not supported.
5. If the version is older, runs the applicable migration steps in order,
   recording each step in `ruhusa_schema_migrations`, then updates the version.
6. Runs idempotent `CREATE TABLE IF NOT EXISTS` DDL for all application tables.
7. Validates migration checksum integrity for every present history row.
8. Verifies the final version and raises `RuntimeError` if it does not match.

The advisory lock is released automatically when the transaction commits or
rolls back, so failures are always fail-closed.

## Migration history

Every migration step is recorded in `ruhusa_schema_migrations`:

| Column         | Type        | Description                            |
|----------------|-------------|----------------------------------------|
| `migration_id` | `BIGSERIAL` | Monotonically increasing row identity  |
| `version_from` | `INTEGER`   | Schema version before this step        |
| `version_to`   | `INTEGER`   | Schema version after this step         |
| `checksum`     | `TEXT`      | SHA-256 of the migration SQL           |
| `applied_at`   | `TIMESTAMPTZ` | When this step was applied           |

A fresh installation at the current schema version does not write any
migration-history rows — the table exists but remains empty.

## Migration checksum integrity

Each migration step has an expected SHA-256 checksum hardcoded as a constant in
`ruhusa.postgres_migrations`. The checksum is verified against the SQL before
the step executes and is also stored in `ruhusa_schema_migrations` when the
step completes. On every subsequent startup `validate_migration_history` reads
back the stored checksums and compares each against its expected value, raising
`RuntimeError` before the process serves any authorization traffic if a mismatch
is found.

Historical migration SQL is immutable. A deployment must never modify migration
steps that have already been applied to a database; doing so changes the
expected checksum and causes the guard to raise `RuntimeError` on the next
startup.

**Scope and limitations.** `validate_migration_history` detects modification of
stored checksums and unrecognized migration steps. It cannot detect deletion of
a history row — a fresh schema-v2 installation intentionally has zero rows in
`ruhusa_schema_migrations`, so an empty table is indistinguishable from one
that had rows removed. The Ruhusa audit-event chain
(`ruhusa_audit_events` + `ruhusa_audit_chain`) is the tamper-evident record for
authorization decisions; the migration history table provides migration
checksum integrity, not broader tamper-evidence.

## Schema versions

| Version | Introduced in | Changes                                                  |
|---------|---------------|----------------------------------------------------------|
| 1       | Ruhusa 0.7    | Initial production schema (grants, revocations, invocations, tools, audit, executions) |
| 2       | Ruhusa 0.8    | Migration history tracking via `ruhusa_schema_migrations` |

## Deployment

`initialize_postgres_schema` is safe to call on every process startup. All
callers that reach it concurrently will serialize on the advisory lock; only
the first will perform DDL, and the rest will observe the already-migrated
state when the lock is released.

Deployments should still treat schema migration as a trusted infrastructure
operation — access to the Ruhusa database account should be restricted, and
the account should not have superuser privileges beyond what the application
tables require.
