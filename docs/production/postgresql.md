# PostgreSQL Persistence

Ruhusa v0.7-B introduces optional PostgreSQL-backed implementations of
the stable persistence protocols defined in v0.7-A.

## Scope

The PostgreSQL persistence layer includes:

- `PostgresGrantStore`
- `PostgresRevocationStore`
- `PostgresInvocationStore`
- `PostgresToolRegistry`
- `PostgresExecutionStore`
- `PostgresAuditLog`

## Installation

Install Ruhusa with PostgreSQL support:

```bash
pip install "ruhusa[postgres]"
```

The base Ruhusa package does not require PostgreSQL dependencies.

## Initialization

```python
from ruhusa.postgres import (
    PostgresAuditLog,
    PostgresExecutionStore,
    PostgresGrantStore,
    PostgresInvocationStore,
    PostgresRevocationStore,
    PostgresToolRegistry,
    create_postgres_pool,
    initialize_postgres_schema,
)

pool = create_postgres_pool("postgresql://user:password@localhost/ruhusa")

initialize_postgres_schema(pool)

grant_store = PostgresGrantStore(pool)
revocation_store = PostgresRevocationStore(pool)
invocation_store = PostgresInvocationStore(pool)
tool_registry = PostgresToolRegistry(pool)
execution_store = PostgresExecutionStore(pool)
audit_log = PostgresAuditLog(pool)
```

Schema initialization is explicit. Constructing a store does not
automatically create or modify database tables.

## Security Semantics

### Immutable grants

A `grant_id` is immutable after registration.
Attempting to register the same `grant_id` again raises `ValueError`,
even if the second registration contains different authority.
A legitimate re-issuance must use a new grant identifier.

### Immutable invocation provenance

An `invocation_id` is immutable after registration.
This prevents trusted provenance from being replaced after an
invocation identifier has been issued.

### Immutable tool identities

The pair `(tool_id, implementation_id)` is the unit of trust.
A registered pair cannot be overwritten with different allowed actions.

### Monotonic revocation

Revocation moves only toward earlier enforcement.
If multiple revocations are submitted for the same grant, PostgreSQL
atomically preserves the earliest effective revocation timestamp.
A later revocation can never delay an earlier revocation.

### Distributed execution fencing

`PostgresExecutionStore` makes lifecycle transitions atomic for one
canonical invocation across workers and processes.

A successful claim receives an `ExecutionPermit` containing:

- `invocation_id`
- `claim_id`
- `attempt`

All permit-owned state transitions require the current `claim_id` and
`attempt`. A permit from an older attempt therefore cannot complete,
cancel, release, or otherwise mutate a newer execution attempt.

Concurrent claims for the same invocation produce at most one winning
permit.

A stale claim is moved to `UNKNOWN`, not automatically back to
`AVAILABLE`, because worker disappearance does not prove that the
external side effect did not occur.

Only trusted reconciliation may resolve `UNKNOWN`:

- confirmed side effect → `COMPLETED`
- confirmed no side effect → `AVAILABLE`

### Durable audit chain

`PostgresAuditLog` serializes concurrent audit writers through a
single PostgreSQL chain-head row.

Each event contains the hash of the preceding event. The event and
chain-head update occur within one database transaction.

This provides:

- deterministic event ordering
- cross-process append serialization
- detection of missing events
- detection of modified event contents
- detection of an inconsistent chain head
- fail-closed behavior when audit persistence is unavailable

The hash chain is tamper-evident, not cryptographically immutable
against a database administrator who can rewrite the entire database
and recompute the chain. Deployments requiring stronger non-repudiation
should externally anchor or sign audit checkpoints. External anchoring
is outside the v0.7-B scope.

### Backend failures

PostgreSQL errors are not translated into `None`, `False`, or
"not found."
Store methods raise when authoritative state cannot be read reliably.
The Ruhusa authorization boundary is responsible for translating such
failures into fail-closed authorization decisions.

## Connection pooling

Ruhusa uses Psycopg 3's synchronous `ConnectionPool` because the
current v0.7-A persistence protocols are synchronous.
Applications should create one shared pool and inject that pool into
the PostgreSQL stores.

## Not included in this slice

The following are intentionally deferred:

- Redis
- FastAPI
- LangGraph adapters
- MCP adapters
- deployment infrastructure
- SQL-backed policy definitions

## Schema compatibility

Ruhusa v0.7 uses PostgreSQL schema version `1`.

`initialize_postgres_schema()` first reads the schema metadata for an
already-versioned database before executing application-table DDL.

If the stored schema version does not equal the version supported by the
running Ruhusa package, initialization raises an error.

Ruhusa does not automatically migrate an incompatible schema.

This is intentional fail-closed behavior: a process must not silently run
against security state whose representation it does not understand.

Schema initialization is idempotent for a compatible version and does not
delete or replace existing authorization state.

Version `1` is the first publicly released PostgreSQL schema. Future schema
changes will require an explicit migration strategy.
