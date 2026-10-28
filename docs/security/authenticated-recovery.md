# Authenticated recovery evidence (v0.9-D development)

**Development status:** D1 prototype, not a v0.9 release or a production-grade distributed reconciliation service.

An `UNKNOWN` execution MUST NOT become retryable merely because an agent reports that a side effect did not happen. The v0.9-D1 `AuthenticatedRecoveryService` accepts an authenticated reconciliation receipt only if:

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
