# Durable approvals

Ruhusa v0.9-A introduces a human-approval primitive bound to canonical invocation provenance.

## Security model

An approval is not permission for an agent in general. It is authority for one exact canonical invocation. The canonical `InvocationRecord` remains authoritative for principal, task, action, resource, arguments digest, tool identity, implementation identity, and expiry.

## Lifecycle

```text
PENDING
  ├─ approve ─> APPROVED ─> CONSUMED
  ├─ reject ──> REJECTED
  ├─ revoke ──> REVOKED
  └─ expire ──> EXPIRED

APPROVED
  ├─ revoke ──> REVOKED
  ├─ expire ──> EXPIRED
  └─ consume ─> CONSUMED
```

Terminal states never move backward.

## Consumption

Approval consumption is bound to an `ExecutionPermit` (`invocation_id`, `claim_id`, `attempt`). The first successful consumer wins atomically; later consumers fail closed.

## Crash / UNKNOWN behavior

`CONSUMED` is terminal. If a side effect becomes uncertain after consumption, the execution lifecycle must use Ruhusa's existing `UNKNOWN` state. Even if reconciliation later proves the side effect was not applied, the approval is not resurrected automatically. A retry requires a fresh approval.

## Trust boundary

`approved_by`, `rejected_by`, and `revoked_by` are supplied by trusted integration infrastructure. v0.9-A records these identities but does not authenticate them; verified external identity belongs to v0.9-B.
