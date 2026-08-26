# PostgreSQL Persistence

Ruhusa v0.7-B introduces optional PostgreSQL-backed implementations of
the stable persistence protocols defined in v0.7-A.

## Scope

The first PostgreSQL persistence slice includes:

- `PostgresGrantStore`
- `PostgresRevocationStore`
- `PostgresInvocationStore`
- `PostgresToolRegistry`

Execution lifecycle persistence and durable audit logging are implemented
in later v0.7-B slices because they require additional transaction and
concurrency guarantees.

## Installation

Install Ruhusa with PostgreSQL support:

```bash
pip install "ruhusa[postgres]"
```

The base Ruhusa package does not require PostgreSQL dependencies.

## Initialization

```python
from ruhusa.postgres import (
    PostgresGrantStore,
    PostgresInvocationStore,
    PostgresRevocationStore,
    PostgresToolRegistry,
    create_postgres_pool,
    initialize_postgres_schema,
)

pool = create_postgres_pool(
    "postgresql://user:password@localhost/ruhusa"
)

initialize_postgres_schema(pool)

grant_store = PostgresGrantStore(pool)
revocation_store = PostgresRevocationStore(pool)
invocation_store = PostgresInvocationStore(pool)
tool_registry = PostgresToolRegistry(pool)
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

- PostgreSQL execution lifecycle store
- PostgreSQL audit log
- Redis
- FastAPI
- LangGraph adapters
- MCP adapters
- deployment infrastructure
- SQL-backed policy definitions
