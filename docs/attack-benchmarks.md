# Ruhusa Attack Benchmarks

**Status:** Living research artifact  
**Current development milestone:** v0.5  
**Primary benchmark files:** `tests/test_replanning_attacks.py`, `tests/test_tool_identity_attacks.py`

---

## 1. Purpose

This document records adversarial experiments used to evaluate Ruhusa's authorization model.

The benchmark is designed to connect:

```text
security claim
    |
    v
attack
    |
    v
violated invariant
    |
    v
implementation control
    |
    v
executable test
    |
    v
observed result
```

A security feature is not treated as a meaningful guarantee merely because code exists for it.

---

## 2. Outcome Labels

### `GAP`

The attack succeeds under the configuration being tested.

A `GAP` test intentionally passes when the vulnerable behavior is reproduced.

### `BLOCKS`

Ruhusa rejects the modeled attack under the stated configuration.

### `CONTROL`

The experiment confirms that an earlier authorization control still behaves correctly while a new attack family is studied.

A passing test does **not** automatically mean Ruhusa is secure. Always read the benchmark label.

---

## 3. Research Method

```text
define threat
    |
    v
write executable attack
    |
    v
run against baseline
    |
    +---- blocked ----> identify existing invariant
    |
    +---- succeeds ---> record GAP
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

After a mitigation succeeds, the next question is:

> How would an attacker adapt after observing the new control?

That follow-on step produced the canonical-grant finding in v0.4 and the self-asserted invocation/tool identity findings in v0.5.

---

# Part I — v0.4 Replanning and Delegation

## 4. v0.4 Research Question

> Can an agent recover or expand authority after denial or revocation by delegating, replanning, replaying authority, changing delegation paths, or fabricating replacement grants?

Primary file:

```text
tests/test_replanning_attacks.py
```

## 5. v0.4 Benchmark Matrix

| ID | Attack | Result | Control | Verification |
|---|---|---|---|---|
| V4-01 | Denied agent delegates to bypass denial | `BLOCKS` | Chain must originate from task initiator | `test_denied_agent_cannot_delegate_to_bypass_denial` |
| V4-02 | Child grant widens parent scope | `BLOCKS` | Per-hop scope attenuation | `test_child_grant_cannot_widen_scope` |
| V4-03 | Revoked authority reminted with fresh `grant_id` | `BLOCKS` after v0.4 mitigation | Trusted canonical grant issuance | `test_revoked_grant_reuse_via_fresh_chain_is_blocked_by_grant_store` |
| V4-04 | Cross-task replay | `BLOCKS` | Task binding | `test_cross_task_replay_after_denial` |
| V4-05 | Alternate delegation path widens authority | `BLOCKS` | Per-hop attenuation | `test_alternate_delegation_path_does_not_widen_effective_authority` |
| V4-06 | Known grant ID with tampered scope | `BLOCKS` | Canonical full-content equality | `test_registered_id_with_tampered_scope_is_denied` |
| V4-07 | Grant-store backend failure | `BLOCKS` | Fail closed | `test_grant_store_failure_is_fail_closed` |

## 6. v0.4 Experimental Finding

The baseline exposed a fresh-grant remint weakness.

```text
revoked grant
    |
    v
attacker constructs new grant_id
with equivalent-looking authority
    |
    v
structural validation alone
cannot establish issuance
```

The root cause was the difference between:

```text
Is this grant structurally valid?
```

and:

```text
Was this grant actually issued?
```

`InMemoryGrantStore` introduced canonical provenance and exact content matching.

The follow-on tampering attack then established that grant-ID membership alone was insufficient; the presented object must match the canonical issued grant.

---

# Part II — v0.5 Invocation and Tool Identity

## 7. v0.5 Research Question

> Does authorization remain valid when an allowed operation is redirected through a different tool, caller identity is forged, a privileged agent is used as a confused deputy, or previously valid invocation provenance is replayed or mutated?

Primary file:

```text
tests/test_tool_identity_attacks.py
```

The current test module documents **sixteen implemented experiments** (Experiments 15 and 16 are running GAP benchmarks; Experiment 17 is a candidate).

---

## 8. v0.5 Experiment Matrix

| Exp | Scenario | Mode | Result | Verification |
|---|---|---|---|---|
| 1 | Authorized action routed through substituted tool | no registry | `GAP` — `ALLOW` | `test_authorized_action_via_substituted_tool_is_not_detected` |
| 2 | Same logical tool name, different implementation | no registry | `GAP` — `ALLOW` | `test_same_tool_name_different_implementation_is_not_detected` |
| 3 | Low-privilege caller induces privileged deputy and is truthfully represented | weak consistency | `BLOCKS` — `DENY` | `test_confused_deputy_low_privilege_induces_privileged_agent` |
| 4 | Completely different action | existing controls | `CONTROL/BLOCKS` — `DENY` | `test_completely_different_action_is_denied` |
| 5 | Different resource | existing controls | `CONTROL/BLOCKS` — `DENY` | `test_different_resource_is_denied` |
| 6 | Missing invoking principal on delegated request | weak consistency | `BLOCKS` — `DENY` | `test_missing_invoking_principal_is_denied_for_delegated_action` |
| 7 | Unregistered substituted tool | registry, weak mode | `BLOCKS` — `DENY` | `test_substituted_tool_is_blocked_by_registry` |
| 8 | Same logical tool, unregistered implementation | registry, weak mode | `BLOCKS` — `DENY` | `test_same_tool_name_different_implementation_blocked_by_registry` |
| 9 | Forge `invoking_principal_id` to legitimate leaf grantor | weak mode | `GAP` — `ALLOW` | `test_forged_invoking_principal_bypasses_current_provenance_check` |
| 10 | Same forged invoker with canonical invocation store | strong delegated mode | `BLOCKS` — `DENY` | `test_forged_invoking_principal_blocked_by_invocation_store` |
| 11 | Forge registered tool identity while actually using substitute implementation | registry, weak mode | `GAP` — `ALLOW` | `test_forged_tool_identity_bypasses_weak_registry_check` |
| 12 | Same forged tool identity with canonical runtime record | strong delegated mode + registry | `BLOCKS` — `DENY` | `test_forged_tool_identity_blocked_by_invocation_store` |
| 13 | Reuse invocation ID with modified arguments | strong delegated mode | `BLOCKS` — `DENY` | `test_operation_substitution_blocked_by_arguments_digest` |
| 14 | Replay expired invocation record | strong delegated mode | `BLOCKS` — `DENY` | `test_stale_invocation_record_is_denied` |
| 15 | Non-delegated request bypasses strong-mode tool check | strong mode, no chain | `GAP` — `ALLOW` | `test_non_delegated_request_bypasses_strong_mode_tool_check` |
| 16 | Exact same-operation invocation replay | strong delegated mode | `GAP` — `ALLOW` | `test_exact_invocation_replay_is_not_prevented` |
| 17 | Invocation record with `tool_id=None` skips tool verification | strong mode + registry | candidate — not yet benchmarked | — |

---

## 9. Experiments 1–2 — Tool Substitution Baseline

The v0.4-style authorization model sees:

```text
principal
action
resource
arguments
```

but not which implementation actually executes.

Therefore two different implementations can appear identical to authorization.

Result:

```text
GAP
```

This established that an action string is not a tool identity.

---

## 10. Experiment 3 — Initial Confused-Deputy Check

A low-privilege agent induces `billing-agent` to execute an otherwise authorized refund.

When the request truthfully carries:

```text
invoking_principal_id = "low-privilege-agent"
```

and the leaf grant was issued by:

```text
user-1
```

the mismatch is denied.

Result:

```text
BLOCKS
```

However, this only proves consistency when the caller field is honest.

Experiment 9 demonstrates the adapted attack: forge the caller field.

---

## 11. Experiments 4–5 — Existing Scope Controls

These are control cases confirming that earlier protections still hold.

Different action:

```text
DENY
```

Different resource:

```text
DENY
```

v0.5 provenance controls are intended to complement, not replace, action/resource scope enforcement.

---

## 12. Experiment 6 — Missing Caller Provenance

A delegated request omits `invoking_principal_id`.

Weak mode treats omission as a hard failure instead of skipping the check.

Result:

```text
BLOCKS
```

This prevents an omission bypass, but does not authenticate a supplied value.

---

## 13. Experiments 7–8 — Tool Registry

`InMemoryToolRegistry` introduces canonical registration of:

```text
(tool_id, implementation_id)
```

and allowed actions.

An openly unregistered implementation is denied.

Result:

```text
BLOCKS
```

But the request still self-asserts the pair in weak mode.

Experiment 11 tests that stronger forgery.

---

## 14. Experiment 9 — Forged Invoker

A compromised executing agent knows the leaf grantor and submits:

```text
invoking_principal_id = "user-1"
```

even though the true caller is a lower-privilege agent.

Weak mode sees equality and allows the request.

Result:

```text
GAP
```

Root cause:

> Equality between two request-visible identities does not authenticate runtime provenance.

---

## 15. Experiment 10 — Trusted Invocation Provenance

Strong mode uses `InMemoryInvocationStore`.

The request supplies an `invocation_id`, but the executing agent is assumed unable to modify the canonical `InvocationRecord` associated with that identifier.

Security does **not** depend on the record being secret.

The canonical record identifies the actual caller observed by the trusted orchestration layer.

If the real caller is not the leaf grantor:

```text
DENY
```

Result:

```text
BLOCKS
```

---

## 16. Experiment 11 — Forged Registered Tool Identity

Weak registry mode verifies the request's claimed pair.

An attacker can therefore claim:

```text
tool_id = registered tool
implementation_id = registered trusted implementation
```

while actually executing a substitute implementation.

The registry lookup succeeds because the claimed values are legitimate.

Result:

```text
GAP
```

Root cause:

> Registry membership establishes what identities are trusted, not what implementation actually executed.

---

## 17. Experiment 12 — Runtime-Bound Tool Identity

In strong delegated mode, the orchestration layer records the actual tool identity in the canonical `InvocationRecord`.

Ruhusa checks:

```text
record.tool_id
record.implementation_id
```

against `InMemoryToolRegistry`.

Self-asserted request tool fields do not override the record.

Result:

```text
BLOCKS
```

The stronger construction is:

```text
trusted runtime observation
+
canonical registry
```

---

## 18. Experiment 13 — Operation Substitution

The canonical invocation record binds:

```text
action
resource
arguments_digest
```

The attacker reuses a valid `invocation_id` with changed arguments.

Ruhusa recomputes the argument digest and detects the mismatch.

Result:

```text
BLOCKS
```

This proves resistance to **modified-operation replay**.

It does **not** prove one-shot invocation semantics.

---

## 19. Experiment 14 — Stale Invocation Replay

The canonical invocation record has its own `expires_at`.

A stale invocation is denied even when the parent task remains active.

Result:

```text
BLOCKS
```

This distinguishes task lifetime from invocation lifetime.

---

# Part III — Open v0.5 Benchmark Cases

## 20. Experiment 15 — Non-Delegated Strong-Mode Tool Bypass

**Status:** running GAP benchmark — `test_non_delegated_request_bypasses_strong_mode_tool_check`

**Result:** `GAP` — `ALLOW`

Strong invocation verification runs only inside `if request.delegation_chain:`, so it is skipped for non-delegated requests. Weak tool verification runs only when `tool_registry is configured AND invocation_store is not configured`, so it is also skipped when an InvocationStore is present.

A direct/non-delegated request in a configuration with both stores skips both paths. Policy decides alone.

```text
InvocationStore configured
ToolRegistry configured
delegation_chain = ()
principal directly allowed by policy
substitute tool (unregistered implementation_id)
        |
        v
Ruhusa authorizes without verifying tool identity → ALLOW (GAP)
```

The benchmark confirms the gap. The architectural decision — whether non-delegated direct calls must also pass tool verification — is an open v0.5 question. See `docs/threat-model.md` T14.

---

## 21. Experiment 16 — Exact Invocation Replay

**Status:** running GAP benchmark — `test_exact_invocation_replay_is_not_prevented`

**Result:** `GAP` — `ALLOW`

Experiment 13 blocks replay with a modified operation (arguments digest mismatch). Experiment 16 tests replay where the operation is identical.

`InMemoryInvocationStore` has no `consume()` method. The same `invocation_id` with identical action, resource, and arguments passes repeatedly.

```text
invocation_id = inv-replay-001
refund $250

request #1 → ALLOW
request #2 → ALLOW  (GAP)
request #3 → ALLOW
```

The benchmark establishes the current contract: Ruhusa does not enforce one-shot invocation semantics. Duplicate-side-effect prevention is currently an execution-layer responsibility. The architectural decision — whether to add `consume()` to `InvocationStore` — is an open v0.5 question. See `docs/threat-model.md` T15.

---

## 22. Candidate Experiment 17 — Missing Canonical Tool Identity

**Status:** identified; test not yet added.

Strong tool verification currently executes when the canonical invocation record contains a non-`None` `tool_id`.

Candidate case:

```text
InvocationStore configured
ToolRegistry configured
protected operation is tool-mediated
InvocationRecord.tool_id = None
        |
        v
Should Ruhusa fail closed?
```

The framework currently lacks an independent "this operation must be tool-mediated" requirement. The test should clarify the desired invariant.

---

# Part IV — Cross-Version Findings

## 23. Recurring Provenance Pattern

v0.4:

```text
grant looks valid
    !=
grant was issued
```

v0.5 caller identity:

```text
caller field matches expected identity
    !=
caller actually invoked agent
```

v0.5 tool identity:

```text
claimed tool exists in registry
    !=
that implementation actually executed
```

Emerging principle:

> **Security-relevant identity claims must be grounded in trusted provenance, not merely represented as matching strings inside an agent-controlled request.**

---

## 24. Current Coverage

Executable benchmarks currently cover:

- delegation-origin bypass
- child privilege amplification
- fresh-grant remint
- cross-task replay
- alternate delegation-path escalation
- canonical grant-content tampering
- grant-store failure
- baseline tool substitution
- logical tool-name collision
- confused-deputy consistency checks
- missing invoker
- forged invoker
- unregistered tool substitution
- forged registered tool identity
- operation substitution
- stale invocation replay
- wrong action
- wrong resource
- non-delegated tool-verification bypass (GAP)
- exact same-operation invocation replay (GAP)

The presence of a category does not imply exhaustive coverage of every variant.

---

## 25. Known Benchmark Gaps

In addition to Candidate Experiment 17, future benchmark areas include:

- TOCTOU between authorization and execution
- concurrent revocation
- multi-agent collusion
- retry/recovery state mutation
- descendant revocation
- human-approval replay
- distributed-store consistency
- cryptographic principal identity
- cryptographic tool attestation
- trusted-orchestrator compromise
- branch/merge authorization propagation
- information provenance
- derived-data authority
- malicious behavior inside a correctly identified trusted tool

---

## 26. Requirements for New Benchmark Cases

A new security benchmark should identify:

1. threat
2. preconditions
3. attacker capability
4. baseline behavior
5. expected invariant
6. control
7. exact executable test
8. legitimate positive path where appropriate
9. likely attacker adaptation

A new security control should not be documented as a guarantee until a suitable benchmark supports it.

---

## 27. Running Benchmarks

All tests:

```bash
uv run pytest
```

v0.4 replanning attacks:

```bash
uv run pytest tests/test_replanning_attacks.py -v
```

v0.5 tool/invocation attacks:

```bash
uv run pytest tests/test_tool_identity_attacks.py -v
```

Full validation:

```bash
uv run ruff format .
uv run ruff check .
uv run pytest
uv build
```

---

## 28. Research Traceability

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

Ruhusa's long-term goal is not only to answer:

> Is this tool call allowed?

but also:

> Has the authority represented by this action remained valid throughout the workflow transformations that produced it?
