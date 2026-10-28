# Changelog

All notable changes to Ruhusa are documented here.

Ruhusa follows semantic versioning while the public API remains pre-1.0.

## [Unreleased] — v0.9 development

Development work is not yet part of a published Ruhusa release.

### In progress

- v0.9-D1 signed recovery evidence prototype with trusted issuer/key verification,
  invocation/claim/attempt binding, expiry validation, replay checks, and
  fail-closed UNKNOWN transitions. In-memory replay only; not production-ready.
- v0.9-C2 MCP SDK v2 low-level `tools/call` router prototype: server-owned
  tool registrations, trusted context resolver, fail-closed guarded dispatch,
  simulated tool example, and offline security regression tests. No production
  transport authentication or execution fencing is included.

- v0.9-C experimental transport-neutral MCP tool guard: trusted server-side
  identity/resource bindings, canonical invocation registration, mandatory
  strong provenance, fail-closed authorization-before-async-handler, and
  six offline regression tests. Not yet an SDK middleware or execution fence.

- v0.9-B3 experimental live-model/stateful authorization benchmark, with independently
  specified reference decisions, isolated trusted invocation fixtures, paired
  simulated baseline, coverage accounting, offline tests, and research protocol.
- Operation-bound durable approvals and PostgreSQL schema v3 in PR #28.
- Experimental v0.9-B real-model attack benchmark runner, offline fixture tests,
  paired permissive/Ruhusa simulation, and JSON metrics (not yet a release).
- Production MCP transport authentication and authenticated recovery evidence remain planned;
  do not treat these as shipped features.
- Stateful authorization control suite with trusted invocation/tool provenance
  fixtures and regression tests (v0.9-B2; not yet a release).

### Documentation

- Clarified stable v0.8.0 versus unreleased v0.9 status.
- Added a development status and documentation audit.

### v0.9-C2 protocol verification (unreleased)

- Added an optional real MCP Python SDK v2 client/server round-trip test for
  `tools/list` and `tools/call`, including allowed, denied, and missing-trusted-identity paths.
- The protocol test exercises only simulated side effects and skips when the
  optional SDK is not installed; production authentication and durable fencing
  remain future validation gates.

## [0.8.0] — 2026-09-02

### Added

- PostgreSQL schema v2 and ordered, checksummed migration history.
- Upgrade validation from the published v0.7.0 PostgreSQL schema.
- Health and operational observability interfaces.
- Production-hardening and release verification documentation.

See [v0.8.0 release notes](docs/releases/v0.8.0.md) for details and
security limitations.

## [0.7.0] - 2026-08-27

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
