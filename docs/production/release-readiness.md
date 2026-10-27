# Ruhusa Production Readiness (stable v0.8.0)

## Status

Ruhusa `0.8.0` is the latest published stable release. This document
describes stable pre-1.0 deployment expectations; v0.9 approval features
are development work and must not be assumed available in v0.8.0.

The v0.6 research artifact remains frozen separately.

## Production-capable guarantees

When configured with trusted dependencies, Ruhusa provides:

- deterministic default-deny authorization;
- least-privilege delegation;
- canonical grant provenance;
- continuous revocation;
- canonical invocation provenance;
- trusted tool implementation identity;
- fail-closed backend behavior;
- execution-time revalidation;
- durable PostgreSQL security state;
- cross-process execution claim serialization;
- execution permit fencing;
- fail-closed uncertain execution recovery;
- serialized, tamper-evident PostgreSQL audit logging.

## Deployment requirements

Production deployments should:

- use PostgreSQL for durable security state;
- initialize and validate the schema before serving authorization traffic;
- protect database credentials using the deployment platform's secret
  management system;
- require encrypted database connections where traffic crosses an
  untrusted network;
- restrict the Ruhusa database account to the required database/schema;
- maintain database backups;
- monitor database availability and latency;
- treat recovery reconciliation as a trusted infrastructure operation;
- ensure canonical invocation and grant registration occur only through
  trusted orchestration components.

## Fail-closed behavior

Failure to read authoritative security state is not equivalent to the
absence of that state.

Database failures are therefore allowed to propagate from persistence
implementations so the Ruhusa authorization boundary can deny safely.

An authorization decision that cannot be written to the configured audit
backend cannot escape as ALLOW.

## Explicit non-guarantees

Ruhusa does not claim:

- atomic authorization plus arbitrary remote side effects;
- exactly-once downstream side effects;
- authentication of reconciliation evidence;
- protection against a privileged database administrator rewriting an
  entire audit history and recomputing the hash chain;
- identity-provider functionality;
- general-purpose workflow orchestration;
- production IAM replacement.

## PostgreSQL scope

The optional `ruhusa[postgres]` installation contains durable
implementations for:

- grants;
- revocations;
- invocation provenance;
- trusted tool registrations;
- execution lifecycle;
- authorization audit events.

Policy evaluation remains behind the `PolicyStore` protocol. Ruhusa does
not serialize arbitrary Python policy conditions into PostgreSQL.

## Release and upgrade checks

For a stable v0.8.0 deployment, verify:

- formatting, linting and supported test suites pass;
- PostgreSQL integration tests run against a real database;
- the v0.7.0 schema-v1 to v0.8.0 schema-v2 upgrade succeeds and preserves data;
- migration history checksums validate and schema initialization is idempotent;
- wheel/sdist builds and optional-dependency installation work;
- the public API, CLI, and installed-package smoke tests pass;
- no known authorization or fail-closed regression remains open.

See [the archived v0.8.0 release checklist](release-checklist-v0.8.0.md)
for the historical publication checklist. Development PRs targeting
v0.9 must separately test schema v3 upgrade paths before merge.
