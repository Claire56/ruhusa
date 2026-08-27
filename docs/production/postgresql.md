# PostgreSQL Persistence

Ruhusa v0.7-B introduces optional PostgreSQL-backed implementations of
the stable persistence protocols defined in v0.7-A.

## Scope

The PostgreSQL persistence layer currently includes:

- `PostgresGrantStore`
- `PostgresRevocationStore`
- `PostgresInvocationStore`
- `PostgresToolRegistry`
- `PostgresExecutionStore`

Durable audit logging is implemented separately because concurrent
audit-chain persistence requires additional serialization guarantees.

## Installation

Install Ruhusa with PostgreSQL support:

```bash
pip install "ruhusa[postgres]"
```

The base Ruhusa package does not require PostgreSQL dependencies.

## Initialization

```python
from ruhusa.postgres import (
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

- PostgreSQL audit log
- Redis
- FastAPI
- LangGraph adapters
- MCP adapters
- deployment infrastructure
- SQL-backed policy definitions
