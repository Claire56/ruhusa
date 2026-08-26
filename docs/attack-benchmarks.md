# Ruhusa Attack Benchmarks

**Status:** Living research artifact  
**Current milestone:** v0.6 — execution lifecycle, execution-time authority, and recovery  
**Current implemented experiment count:** 44

Primary benchmark files:

```text
tests/test_replanning_attacks.py
tests/test_tool_identity_attacks.py
tests/test_execution_lifecycle_attacks.py
tests/test_execution_time_authority_attacks.py
tests/test_idempotency_recovery.py
```

---

## 1. Purpose

This document records the adversarial experiments used to evaluate Ruhusa.

The benchmark connects:

```text
security claim
    |
    v
attack
    |
    v
observed failure
    |
    v
security invariant
    |
    v
implementation control
    |
    v
executable verification
```

Security controls are not treated as guarantees merely because code exists.

---

## 2. Benchmark Labels

### GAP

The attack succeeds under the tested configuration.

A `GAP` test intentionally passes when vulnerable behavior is reproduced.

### BLOCKS

Ruhusa rejects the modeled attack under the stated configuration.

### CONTROL

The test confirms an earlier authorization property continues to hold while a new threat family is studied.

A passing test is therefore not automatically a successful defense. Its benchmark label matters.

---

## 3. Method

```text
define threat
    |
    v
write attack
    |
    v
run baseline
    |
    +-- BLOCKED -> document existing invariant
    |
    +-- ALLOW --> record GAP
                   |
                   v
              identify root cause
                   |
                   v
              add smallest control
                   |
                   v
              rerun attack
```

After a mitigation succeeds, the benchmark asks how the attacker would adapt.

---

# Part I — v0.4 Replanning and Delegation

## 4. v0.4 Research Question

> Can an agent regain or expand authority after denial or revocation by delegating, replanning, replaying authority, changing delegation paths, or fabricating replacement grants?

Primary file:

```text
tests/test_replanning_attacks.py
```

## 5. v0.4 Benchmark Matrix

| ID | Attack | Result | Primary Control |
|---|---|---|---|
| V4-01 | Delegate after denial | `BLOCKS` | chain origin |
| V4-02 | Widen child scope | `BLOCKS` | per-hop attenuation |
| V4-03 | Remint revoked authority under fresh grant ID | `BLOCKS` after mitigation | canonical grant issuance |
| V4-04 | Cross-task replay | `BLOCKS` | task binding |
| V4-05 | Alternate delegation path escalation | `BLOCKS` | attenuation + policy |
| V4-06 | Known grant ID with tampered scope | `BLOCKS` | canonical content equality |
| V4-07 | Grant-store failure | `BLOCKS` | fail closed |

## 6. v0.4 Finding

The important v0.4 distinction was:

```text
grant looks structurally valid
    !=
grant was actually issued
```

That finding introduced `InMemoryGrantStore`.

A follow-on attack then showed that grant-ID membership alone was insufficient; the presented grant must match canonical issued content.

---

# Part II — v0.5 Invocation and Tool Identity

## 7. v0.5 Research Question

> Does authorization remain valid when caller identity is forged, tools are substituted, runtime identity is misrepresented, or valid invocation provenance is replayed or routed through an unmediated path?

The current test module documents **17 implemented experiments**.

Experiments 15 and 17 now `BLOCK` after the v0.5-C complete-mediation fixes. Experiment 16 remains a documented `GAP` because Ruhusa v0.5.0 does not provide one-shot invocation consumption.

---

## 8. Experiment Matrix

| Exp | Scenario | Result |
|---|---|---|
| 1 | Authorized action through substituted tool, no registry | `GAP — ALLOW` |
| 2 | Same logical tool name, different implementation | `GAP — ALLOW` |
| 3 | Confused deputy with truthful low-privilege invoker | `BLOCKS — DENY` |
| 4 | Different action | `CONTROL/BLOCKS — DENY` |
| 5 | Different resource | `CONTROL/BLOCKS — DENY` |
| 6 | Missing invoker on delegated request | `BLOCKS — DENY` |
| 7 | Openly unregistered substituted tool | `BLOCKS — DENY` |
| 8 | Same tool name, unregistered implementation | `BLOCKS — DENY` |
| 9 | Forged invoker in weak mode | `GAP — ALLOW` |
| 10 | Forged invoker with canonical invocation provenance | `BLOCKS — DENY` |
| 11 | Forged registered tool identity in weak mode | `GAP — ALLOW` |
| 12 | Forged tool identity with canonical runtime provenance | `BLOCKS — DENY` |
| 13 | Invocation reused with changed operation arguments | `BLOCKS — DENY` |
| 14 | Expired invocation replay | `BLOCKS — DENY` |
| 15 | Direct/non-delegated strong-mode tool bypass | `BLOCKS — DENY` after v0.5-C |
| 16 | Exact same-operation invocation replay | `GAP — repeated ALLOW` |
| 17 | Missing canonical tool identity with registry configured | `BLOCKS — DENY` |

---

## 9. Experiments 1–2 — Tool Substitution Baseline

Without trusted tool identity, an authorization layer that sees only:

```text
principal
action
resource
arguments
```

cannot distinguish trusted implementation A from substitute implementation B.

These experiments intentionally preserve that baseline.

**Result:**

```text
GAP
```

---

## 10. Experiment 3 — Confused Deputy Consistency

A low-privilege agent induces a privileged billing agent to act.

When the request truthfully identifies the low-privilege invoker, the invoker does not match the leaf grantor.

**Result:**

```text
BLOCKS
```

This does not authenticate the self-asserted caller. Experiment 9 tests that adaptation.

---

## 11. Experiments 4–5 — Existing Scope Controls

These control experiments verify that:

```text
wrong action   -> DENY
wrong resource -> DENY
```

v0.5 provenance controls complement rather than replace scope enforcement.

---

## 12. Experiment 6 — Missing Invoker

A delegated weak-mode request omits caller identity.

Ruhusa fails closed rather than skipping the check.

**Result:**

```text
BLOCKS
```

---

## 13. Experiments 7–8 — Registry Membership

`InMemoryToolRegistry` distinguishes registered from openly unregistered:

```text
(tool_id, implementation_id)
```

pairs.

**Result:**

```text
BLOCKS
```

This is registry membership, not execution provenance.

---

## 14. Experiment 9 — Forged Invoker

The attacker supplies the expected leaf grantor as `invoking_principal_id`.

Weak mode compares matching values but cannot prove the actual runtime caller.

**Result:**

```text
GAP — ALLOW
```

---

## 15. Experiment 10 — Canonical Invocation Provenance

A trusted orchestration layer records the actual runtime invoker.

The executing agent may know the record but cannot alter its canonical value under the threat model.

A forged request-level caller does not override the trusted record.

**Result:**

```text
BLOCKS
```

---

## 16. Experiment 11 — Forged Registered Tool Identity

Weak mode trusts request-supplied tool identity enough to perform a registry lookup.

A compromised agent claims the identity of a registered implementation while actually using another implementation.

**Result:**

```text
GAP — ALLOW
```

This establishes:

> Registry membership is not execution provenance.

---

## 17. Experiment 12 — Runtime-Bound Tool Identity

The trusted orchestration layer records the actual tool identity in the canonical invocation record.

Ruhusa checks that identity against `ToolRegistry`.

Request-supplied tool claims do not override canonical runtime identity.

**Result:**

```text
BLOCKS
```

---

## 18. Experiment 13 — Modified-Operation Replay

A valid invocation ID is reused with changed arguments.

Canonical operation binding detects the mismatch.

**Result:**

```text
BLOCKS
```

This proves resistance to modified-operation replay, not exact duplicate replay.

---

## 19. Experiment 14 — Stale Invocation Replay

An expired invocation record is replayed while the broader task may remain active.

Invocation lifetime is independently enforced.

**Result:**

```text
BLOCKS
```

---

## 20. Experiment 15 — Direct/Non-Delegated Complete-Mediation Bypass

### Original Gap

The initial strong invocation/tool path was nested inside the delegated-request branch.

With:

```text
InvocationStore configured
ToolRegistry configured
delegation_chain = ()
```

a direct request could skip strong verification while also skipping weak tool verification.

The original attack reproduced:

```text
GAP — ALLOW
```

### v0.5-C Control

Canonical invocation verification was moved so it applies independently of delegation.

Delegation-specific invoker/leaf-grantor validation remains conditional on a delegation chain.

The attack was rerun.

**Current result:**

```text
BLOCKS — DENY
```

### Research Meaning

> A fail-closed security component is insufficient if a valid execution path can avoid invoking it.

This experiment introduces **complete mediation** as a separate concern from provenance.

---

## 21. Experiment 16 — Exact Invocation Replay

Experiment 13 blocks replay when the operation changes.

Experiment 16 keeps the operation identical:

```text
same invocation_id
same action
same resource
same arguments
```

The current invocation store has no one-shot consumption state.

**Current result:**

```text
GAP — repeated ALLOW
```

### v0.5 Contract

This is an intentionally documented limitation of v0.5.0.

Ruhusa v0.5.0 provides operation-bound provenance but does not claim:

- one-shot authorization
- exactly-once execution
- atomic authorization + side effect
- downstream idempotency

The issue is deferred to future work on authorization/execution lifecycle semantics.

---

## 22. Experiment 17 — Missing Canonical Tool Identity

### Threat

A tool registry is configured, but the canonical invocation record lacks tool identity.

Without a fail-closed requirement, tool verification could be silently skipped.

### v0.5-C Control

When tool verification is required, missing canonical tool identity is now an authorization failure.

**Current result:**

```text
BLOCKS — DENY
```

### Research Meaning

> Trusted provenance must be complete enough to support the security decision being made.

---

# Part III — v0.6 Execution Lifecycle and Execution-Time Authority

## 23. v0.6 Research Question

> When an operation is correctly authorized, under what execution-lifecycle and timing transformations can that authority be replayed, concurrently reused, become stale, or diverge from the authority that remains valid at the instant of use?

v0.6 is intentionally split into three attack families:

```text
v0.6-A
execution uniqueness and lifecycle state

v0.6-B
execution-time authority validity and TOCTOU

v0.6-C
fail-closed stale-claim and UNKNOWN recovery
```

Primary files:

```text
tests/test_execution_lifecycle_attacks.py
tests/test_execution_time_authority_attacks.py
tests/test_idempotency_recovery.py
```

## 24. v0.6-A — Execution Lifecycle Matrix

| Exp | Scenario | Observed Result | Primary Control / Meaning |
|---:|---|---|---|
| 18 | Exact same invocation replay through `authorize()` | `GAP — repeated ALLOW` | preserved v0.5 baseline; `authorize()` is non-consuming |
| 19 | Second execution claim for same invocation | `BLOCKS` | process-local atomic claim |
| 20 | Concurrent claim race | `BLOCKS` | exactly one process-local winner |
| 21 | Replay after completion | `BLOCKS` | terminal `COMPLETED` state |
| 22 | Failure known before side effect | `CONTROL — retry allowed` | explicit safe release |
| 23 | Uncertain external outcome retry | `BLOCKS` | terminal `UNKNOWN` state |
| 24 | Stale or forged execution permit | `BLOCKS` | active claim ID + attempt binding |
| 25 | Expired execution authority | `BLOCKS` | canonical invocation expiry |
| 26 | Authorization denial | `CONTROL — no lifecycle consumption` | claim occurs only after ALLOW |
| 27 | Execution-store failure | `BLOCKS` | fail closed |

### v0.6-A Finding

The direct before/after comparison is:

```text
authorize(invocation) -> ALLOW
authorize(invocation) -> ALLOW

but

begin(invocation) -> CLAIMED
begin(invocation) -> DENY
```

This establishes:

> **Operation-bound provenance does not imply execution uniqueness.**

The control is intentionally scoped to the research store. `InMemoryExecutionStore` demonstrates process-local atomic claiming; it does not establish distributed exactly-once semantics.

## 25. v0.6-B — Execution-Time Authority Matrix

| Exp | Scenario | Observed Result | Primary Control / Meaning |
|---:|---|---|---|
| 28 | Grant revoked before execution claim | `BLOCKS` | `begin()` re-authorizes before claim |
| 29 | Grant revoked after claim, no revalidation | `GAP` | reproduces v0.6-A temporal weakness |
| 30 | Grant revoked after claim, with revalidation | `BLOCKS` | execution-time full authorization check |
| 31 | Task expires after claim | `BLOCKS` | task validity re-evaluated at use |
| 32 | Policy removed/changed after claim | `BLOCKS` | current policy re-evaluated at use |
| 33 | Stale or forged permit at revalidation | `BLOCKS` | active attempt ownership required |
| 34 | Execution-store failure during revalidation | `BLOCKS` | fail closed |
| 35 | Revocation after successful revalidation but before use | `GAP` | residual post-check TOCTOU boundary |

### v0.6-B Finding

Experiment 29 shows:

```text
ALLOW
  |
claim
  |
revoke
  |
complete
  |
side effect may still be treated as valid
```

Experiment 30 repeats the same workflow with the new execution boundary:

```text
ALLOW
  |
claim
  |
revoke
  |
revalidate
  |
DENY -> CANCELLED
```

This establishes:

> **Authorization-time validity does not imply execution-time validity.**

Experiment 35 then demonstrates the next boundary:

> **Execution-time revalidation does not make authorization state atomic with a remote side effect.**

## 26. v0.6 State Semantics

```text
AVAILABLE --claim--> CLAIMED --complete--> COMPLETED
    ^                   |
    |                   +--uncertain------> UNKNOWN
    |                   |
    |                   +--authority invalid-> CANCELLED
    |
    +--release-before-side-effect-- CLAIMED
```

Interpretation:

- `COMPLETED` blocks replay of a known completed execution;
- `UNKNOWN` blocks automatic retry when the external outcome cannot be determined;
- `CANCELLED` terminates an invocation whose authority became invalid before use;
- safe release to `AVAILABLE` is permitted only when the protected side effect is known not to have started.

## 27. v0.6 Explicit Non-Claims

The current benchmark does not establish:

- distributed consensus across workers or pods;
- exactly-once external side effects;
- downstream idempotency;
- durable execution-state recovery;
- atomic authorization/revocation plus external side effect;
- reconciliation of `UNKNOWN`;
- prevention of authority changes after the final revalidation instant.

These are not hidden implementation omissions; they are explicit research boundaries.

---

## 27A. v0.6-C — Recovery Matrix

Primary file:

```text
tests/test_idempotency_recovery.py
```

| Exp | Scenario | Observed Result | Primary Control / Meaning |
|---:|---|---|---|
| 36 | Stale `CLAIMED` execution | `BLOCKS unsafe retry` | stale claim becomes `UNKNOWN`, not `AVAILABLE` |
| 37 | Recovery before stale threshold | `BLOCKS` | live claim cannot be stolen |
| 38 | Reconciliation confirms side effect occurred | `COMPLETED` / replay blocked | confirmed effect permanently consumes execution |
| 39 | Reconciliation confirms no side effect occurred | `CONTROL — fresh claim allowed` | explicit recovery to `AVAILABLE` |
| 40 | Reconciliation from non-`UNKNOWN` state | `BLOCKS` | recovery transition restricted to `UNKNOWN` |
| 41 | Concurrent reconciliation race | `BLOCKS duplicate transition` | one process-local winner |
| 42 | Old permit after recovery and fresh claim | `BLOCKS` | claim ID + attempt binding |
| 43 | Non-positive stale threshold | `BLOCKS invalid configuration` | recovery window validation |
| 44 | Empty recovery reason | `BLOCKS malformed recovery` | explicit recovery rationale required |

### v0.6-C Finding

A lost worker or timeout is not evidence that a side effect did not occur.

```text
stale CLAIMED
    |
    v
UNKNOWN
    |
    +-- trusted confirmation: effect occurred ----> COMPLETED
    |
    +-- trusted confirmation: no effect ----------> AVAILABLE
```

This establishes:

> **Execution-attempt uniqueness does not imply side-effect uniqueness.**

It also exposes a remaining trust boundary:

> **A self-asserted recovery outcome is not trusted execution evidence.**

The v0.6-C implementation assumes `reconcile_unknown()` is called only by
trusted reconciliation infrastructure. It does not authenticate that caller or
verify recovery evidence provenance itself.

# Part IV — Cross-Version Findings

## 28. Provenance Progression

v0.4:

```text
valid-looking grant
!=
issued grant
```

v0.5 caller identity:

```text
matching caller field
!=
actual invoker
```

v0.5 tool identity:

```text
registered claimed tool
!=
actual implementation
```

v0.5-C:

```text
correct security control
!=
complete mediation
```

Experiment 16 adds:

```text
operation-bound provenance
!=
execution uniqueness
```

v0.6-A adds:

```text
authorization ALLOW
!=
single execution claim
```

v0.6-B adds:

```text
authorization-time validity
!=
execution-time validity

execution-time revalidation
!=
atomic authorization + side effect
```

v0.6-C adds:

```text
execution-attempt uniqueness
!=
side-effect uniqueness

self-asserted recovery outcome
!=
trusted execution evidence
```

---

## 29. Current Coverage

The benchmark now covers:

- delegation-origin bypass
- privilege amplification
- cross-task replay
- fresh-grant remint
- canonical grant tampering
- revocation behavior
- tool substitution
- logical tool-name collision
- confused-deputy behavior
- missing invoker
- forged invoker
- forged registered tool identity
- operation substitution
- stale invocation
- direct/non-delegated mediation
- exact invocation replay
- missing canonical tool identity
- duplicate execution claiming
- process-local concurrent execution races
- replay after completion
- safe pre-side-effect retry
- uncertain-outcome retry
- stale/forged execution permits
- execution authority expiry
- execution-store failure
- post-claim revocation
- post-claim task expiry
- post-claim policy change
- execution-time revalidation
- residual post-revalidation TOCTOU
- stale execution-claim recovery
- early stale-claim recovery attempts
- UNKNOWN-to-COMPLETED reconciliation
- UNKNOWN-to-AVAILABLE reconciliation
- concurrent reconciliation races
- stale permits after recovery
- malformed recovery parameters

Coverage of a threat category does not imply exhaustive coverage of every possible variant.

---

## 30. Known Remaining Gaps

Future benchmark areas include:

- atomic authorization/revocation + external side effect
- downstream idempotency and duplicate-side-effect suppression
- distributed execution-claim consistency
- durable execution-state recovery
- authenticated/provenanced reconciliation evidence
- durable reconciliation of `UNKNOWN` outcomes
- authority leases / epochs
- multi-agent collusion
- descendant revocation
- durable approval replay
- distributed-store consistency
- cryptographic principal identity
- cryptographic tool attestation
- trusted-orchestrator compromise
- branch/merge authority propagation
- information provenance
- derived-data authority
- malicious behavior inside a correctly identified trusted tool

---

## 31. Requirements for New Benchmarks

A new benchmark should identify:

1. threat
2. preconditions
3. attacker capability
4. baseline behavior
5. expected invariant
6. control
7. exact executable test
8. legitimate positive path where appropriate
9. likely attacker adaptation

A security control should not be documented as a guarantee until suitable adversarial evidence exists.

---

## 32. Validation

Run all tests:

```bash
uv run pytest
```

Run the v0.4 benchmark:

```bash
uv run pytest tests/test_replanning_attacks.py -v
```

Run the v0.5 benchmark:

```bash
uv run pytest tests/test_tool_identity_attacks.py -v
```

Run the v0.6 execution-lifecycle benchmarks:

```bash
uv run pytest tests/test_execution_lifecycle_attacks.py -v
uv run pytest tests/test_execution_time_authority_attacks.py -v
uv run pytest tests/test_idempotency_recovery.py -v
```

Frozen v0.5.0 release baseline:

```text
27 files left unchanged
All checks passed
91 passed
dist/ruhusa-0.5.0.tar.gz
dist/ruhusa-0.5.0-py3-none-any.whl
```

Validated v0.6-C development baseline before release-version bump:

```text
All checks passed!
118 passed
dist/ruhusa-0.5.0.tar.gz
dist/ruhusa-0.5.0-py3-none-any.whl
```

Final v0.6.0 release validation:

```text
ruff check:  All checks passed\npytest:      118 passed\nbuild:       dist/ruhusa-0.6.0.tar.gz\nbuild:       dist/ruhusa-0.6.0-py3-none-any.whl
```

---

## 33. Research Traceability

```text
Research Question
       |
       v
Threat Model
       |
       v
Attack Benchmark
       |
       v
Observed Failure
       |
       v
Security Invariant
       |
       v
Implementation Control
       |
       v
Executable Verification
       |
       v
Experimental Result
```

The long-term objective is not only:

> Is this action allowed?

but:

> Has the authority represented by this action remained valid, correctly mediated, and appropriately bounded throughout the workflow that produced it?
