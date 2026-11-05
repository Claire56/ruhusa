# Authenticated recovery evidence (v0.9-D development)

**Development status:** D1 signed-evidence prototype plus opt-in D2 PostgreSQL atomic recovery adapter. Neither is a v0.9 release or complete production recovery enforcement.

An `UNKNOWN` execution MUST NOT become retryable merely because an agent reports that a side effect did not happen. The v0.9-D1 `AuthenticatedRecoveryService` accepts a cryptographically authenticated reconciliation receipt only if:

- An allowlisted issuer/key pair authenticates a canonical HMAC-SHA256 receipt (with constant-time signature comparison).
- Receipt timestamps are timezone-aware, already issued, unexpired, and within the configured maximum lifetime.
- The receipt binds its unique evidence ID, issuer, key ID, invocation ID, *specific claim ID and attempt number*, outcome, reason, and time interval.
- The execution record is currently `UNKNOWN` and exactly matches the referenced claim and attempt.
- The evidence ID has not been consumed. A failed backend operation does not release `UNKNOWN`.

`SIDE_EFFECT_CONFIRMED` moves the invocation to `COMPLETED`, preventing retry. `SIDE_EFFECT_NOT_APPLIED` moves it to `AVAILABLE`; a fresh Ruhusa authorization check is still required before a new execution claim. The existing execution stores perform the conditional state change.

## Trusted integration example

```python
from datetime import UTC, datetime
from ruhusa.recovery_evidence import (
    AuthenticatedRecoveryService,
    RecoveryEvidenceVerifier,
    InMemoryRecoveryEvidenceReplayStore,
)

# Server-only: load a 32+ byte secret from a secret manager, not source control.
verifier = RecoveryEvidenceVerifier({("trusted-reconciler", "key-2026-10"): signing_key})
service = AuthenticatedRecoveryService(
    execution_store, verifier, InMemoryRecoveryEvidenceReplayStore()
)
# Obtain `receipt` from authenticated reconciliation infrastructure.
accepted = service.reconcile(receipt, now=datetime.now(UTC))
```

`sign_recovery_evidence` is intended **only** for trusted reconciler infrastructure. Never provide keys, raw execution-store access, or an unrestricted reconciliation endpoint to an LLM, client, agent, or MCP tool.

## Important limits and production gates

1. The legacy `ExecutionStore.reconcile_unknown()` and `ExecutionController.reconcile_unknown()` remain available for compatibility and **bypass signature validation**. Deployments must protect these trusted internal APIs; the D1 service is not mandatory enforcement at every call site.
2. The in-memory evidence-ID registry is **process-local**. For multiple replicas or restarts, implement a durable shared registry with atomic uniqueness, preferably inside the same database transaction as the execution state transition. D1 does not provide that atomic cross-store guarantee.
3. HMAC key compromise allows evidence forgery. Provision/rotate signing keys through trusted identity and secrets infrastructure; do not embed them in agent prompts or logs.
4. A valid receipt is only as truthful as its issuer. An external transaction lookup or signed provider outcome must substantiate the result; D1 does not itself validate external payments or tool side effects.
5. PostgreSQL integration tests, cross-process replay, auditing, revocation of issuer keys, and evidence retention still require release validation. Do not claim production-safe authenticated recovery from these in-memory tests alone.


## D2: opt-in PostgreSQL atomic reconciliation (unreleased)

`PostgresAuthenticatedRecoveryService` in `ruhusa.postgres_recovery` verifies a signed
receipt **before** opening a transaction. Within one PostgreSQL transaction it locks
the exact execution row (`SELECT ... FOR UPDATE`), verifies that the execution is
`UNKNOWN` and its claim ID and attempt number match the receipt, inserts a
unique recovery receipt, and transitions the execution to `COMPLETED` or
`AVAILABLE`. A rollback undoes both the receipt and transition; a second replica
cannot simultaneously reconcile the same execution attempt. The receipt table
uses both a unique evidence ID and a unique `(invocation_id, claim_id, attempt)`
constraint. The state transition is still not atomic with an external side effect.

**D3 migration (development schema v4):** The receipts table is now created
by `initialize_postgres_schema(pool)` on fresh schema-v4 databases and through
a checksum-registered v3→v4 migration when upgrading schema-v3 databases.
The older D2 `PostgresAuthenticatedRecoveryService.initialize(pool)` method
remains for compatibility, but is no longer required after schema initialization.

```python
from ruhusa.postgres import initialize_postgres_schema
from ruhusa.postgres_recovery import PostgresAuthenticatedRecoveryService

initialize_postgres_schema(pool)
service = PostgresAuthenticatedRecoveryService(pool, verifier)
accepted = service.reconcile(receipt)
```

**Migration warning:** Back up your database before upgrading to development
schema v4. Applications using an older Ruhusa release with schema-v3 expectations
may refuse to initialize against schema v4. Do not deploy mixed versions until
compatibility is reviewed.

Use a dedicated trusted reconciler database role. Do **not** grant direct
`UPDATE` on `ruhusa_executions`, `INSERT` on `ruhusa_recovery_receipts`,
or access to raw `reconcile_unknown()` from untrusted HTTP/agent workloads.
The D2 service currently operates using the database privileges of its pool;
this is an architectural access-control requirement, **not** an automatically
enforced PostgreSQL role separation.

Run the integration tests against an **isolated test database** (the tests
truncate their execution/receipt tables):

```bash
uv run --extra postgres pytest tests/test_v09_postgres_authenticated_recovery.py -v
```

Set `RUHUSA_TEST_POSTGRES_DSN` first. Without this setting, tests skip. No
claims about concurrency or recovery transactions are established by skipped tests.

**Still pending before v0.9 release:** full fresh/upgrade migration validation,
PostgreSQL CI verification, restricted privileged recovery
entrypoints (including legacy APIs), issuer-key lifecycle/revocation, audit
integration, operational evidence retention, external outcome provenance and
crash/restart fault injection. Authentication proves who signed a claim, not
whether a provider's reported outcome was truthful.
