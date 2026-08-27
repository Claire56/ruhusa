# Changelog

All notable changes to Ruhusa are documented here.

Ruhusa follows semantic versioning while the public API remains pre-1.0.

## [0.7.0rc1] - 2026-08-27

### Added

- Stable persistence protocols for policy, audit, grant, revocation,
  invocation, tool registry, and execution dependencies.
- Optional PostgreSQL persistence through `ruhusa[postgres]`.
- `PostgresGrantStore`.
- `PostgresRevocationStore`.
- `PostgresInvocationStore`.
- `PostgresToolRegistry`.
- `PostgresExecutionStore`.
- `PostgresAuditLog`.
- Cross-process execution claim serialization.
- Execution permit fencing through claim identity and attempt number.
- Durable fail-closed `UNKNOWN` execution recovery.
- Concurrent reconciliation protection.
- Serialized PostgreSQL audit-chain writes.
- PostgreSQL audit tamper detection.
- PostgreSQL schema-version metadata and compatibility checks.
- Real PostgreSQL integration testing in CI.

### Changed

- Persistence protocols are the primary dependency boundary.
- Revocation enumeration uses the stable `snapshot()` contract.
- `compute_arguments_digest` is an intentional public API.
- Public exports are explicitly pinned by contract tests.
- Backend failures consistently propagate to fail-closed authorization
  behavior.
- Audit persistence failure prevents an unaudited ALLOW from escaping.

### Security

- PostgreSQL grant IDs are immutable.
- Invocation provenance records are immutable.
- Registered tool implementation identities are immutable.
- Revocation preserves the earliest effective revocation time.
- Concurrent execution claims have one database-authoritative winner.
- Stale execution permits cannot mutate newer attempts.
- Uncertain side effects remain fail closed until trusted reconciliation.
- Concurrent audit writers form one serialized hash chain.

### Compatibility

The v0.6 research artifact and its security experiments remain preserved.

The PostgreSQL implementation is optional and does not change the base
`ruhusa` installation dependency set.

### Known limitations

Ruhusa does not provide:

- atomic transactions spanning Ruhusa authorization and arbitrary external
  side effects;
- exactly-once guarantees for downstream systems;
- authentication of recovery evidence;
- an identity provider;
- a production IAM replacement;
- Redis persistence;
- SQL-backed policy definitions;
- external audit-chain anchoring;
- built-in FastAPI, LangGraph, or MCP adapters.

The PostgreSQL audit chain is tamper-evident. A database administrator with
sufficient privileges could rewrite stored events and recompute the chain.
Deployments requiring stronger non-repudiation should externally sign or
anchor audit checkpoints.

## [0.6.0]

### Added

- Execution lifecycle state and permits.
- Execution-time authorization revalidation.
- Fail-closed uncertain-execution state.
- Stale-claim quarantine.
- Trusted reconciliation APIs.
- Recovery fencing and stale-permit protection.

The v0.6 artifact remains the frozen research baseline for execution
lifecycle experiments.
