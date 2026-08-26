# Backend Contracts and Failure Semantics

**Milestone:** v0.7-A

## Dependency inversion

Before v0.7, `Ruhusa.__init__` used concrete in-memory classes in public type
annotations. v0.7-A makes the Protocols the extension contract.

```text
Protocol
  |
  +-- bundled in-memory implementation
  +-- PostgreSQL implementation
  +-- future enterprise implementation
```

## Framework invariants

### AUD-01 — No unaudited authorization

> An authorization decision that requires audit persistence must not return
> ALLOW when that audit record cannot be durably accepted by the configured
> audit backend.

This is a production-hardening invariant derived from the existing fail-closed
philosophy, not a research result. It closes the window where audit
infrastructure failure could produce an ALLOW that leaves no durable record.

```text
policy says ALLOW
        ↓
audit persistence fails
        ↓
v0.7-A: DENY  (not an unrecorded ALLOW)
```

## Fail-closed infrastructure rule

For a dependency consulted while deciding whether an action may proceed:

> **Unavailable or indeterminate security state must never become ALLOW.**

Backend authors should raise `StoreUnavailableError` for infrastructure
failures. Ruhusa also remains defensive against unexpected backend exceptions.

Expected behavior:

```text
PolicyStore unavailable       -> DENY
GrantStore unavailable        -> DENY
RevocationStore unavailable   -> DENY
InvocationStore unavailable   -> DENY
ToolRegistry unavailable      -> DENY
AuditLog unavailable on ALLOW -> DENY  (AUD-01)
ExecutionStore unavailable    -> execution admission denied
```

Administrative operations such as a direct `revoke_grant()` call may propagate
a backend exception because there is no authorization decision to return.

## RevocationStore: snapshot() and compatibility

The stable Protocol defines `snapshot()`, which returns a point-in-time
immutable view of revocation state. The bundled `InMemoryRevocationStore`
also retains `all()` as a deprecated compatibility alias for callers on the
v0.6 line. New implementations should implement `snapshot()` only.

## ExecutionStore atomicity

A production implementation must make lifecycle transitions atomic for one
invocation identifier. Concurrent claims must have at most one active winner,
and stale permits must never mutate a newer attempt.

The Protocol describes behavior, not a locking technology.

## PostgreSQL before Redis

v0.7-B should target PostgreSQL first and test transactional concurrency and
failure recovery.

Redis is deferred until a specific safe coordination role is defined. A
TTL-based distributed lock can expire while an external side effect is still in
progress, which can re-open duplicate execution risk.
