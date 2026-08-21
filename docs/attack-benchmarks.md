# Ruhusa Attack Benchmarks

**Status:** Living research artifact
**Framework scope:** v0.4 baseline through v0.5 development
**Primary benchmark files:**
- `tests/test_replanning_attacks.py`
- `tests/test_tool_identity_attacks.py`

---

## 1. Purpose

This document records the adversarial experiments used to evaluate Ruhusa's authorization
model. Ruhusa is developed using an attack-first process: a security control is not treated
as a meaningful guarantee simply because it exists in code. The corresponding attack must be
represented by an executable experiment.

The benchmark suite is therefore intended to answer questions such as:

- Can an agent regain authority after a denial by delegating or replanning?
- Can delegated authority expand through an additional hop?
- Can revoked or task-bound authority be replayed?
- Can a fabricated grant appear legitimate?
- Can a privileged agent be induced to act as a confused deputy?
- Can self-asserted caller or tool identity be forged?
- Can a legitimate invocation identifier be replayed for a different operation?
- Can stale invocation provenance continue to authorize an action?

The benchmark is not a claim that Ruhusa covers every possible agent-security threat. It
records the attacks that have been explicitly modeled and the observed behavior of the
framework under those experiments.

---

## 2. Benchmark Philosophy

Ruhusa distinguishes between three types of benchmark outcomes.

**GAP** — the attack succeeds under the configuration being tested. A GAP test is
intentionally written so that the test passes when the vulnerable behavior is successfully
reproduced. For example:

```
Attacker forges self-asserted invoking_principal_id
        |
        v
Weak provenance mode
        |
        v
ALLOW
        |
        v
GAP reproduced
```

A passing GAP test must therefore not be interpreted as meaning the attack was blocked.

**BLOCKS** — the attack is rejected by an implemented control. A BLOCKS test passes only
when Ruhusa produces the expected denial or otherwise prevents the attack.

**CONTROL** — a control experiment confirms that an existing authorization mechanism still
behaves correctly while a new attack family is being studied. Examples include action outside
allowed scope remains denied, resource outside allowed scope remains denied, legitimate
invocation remains allowed after a new security control is introduced.

---

## 3. Research Method

The preferred Ruhusa benchmark cycle is:

```
Define threat
     |
     v
Construct executable attack
     |
     v
Run against current baseline
     |
     +---- BLOCKED ----> identify existing invariant
     |
     +---- SUCCEEDS ---> record GAP
                          |
                          v
                     identify root cause
                          |
                          v
                     add smallest targeted control
                          |
                          v
                     rerun same attack
                          |
                          v
                       BLOCKS
```

A follow-on adversarial step is then required:

```
Control blocks initial attack
        |
        v
Ask how an attacker would adapt
        |
        v
Construct bypass variant
        |
        +---- BLOCKED ----> stronger evidence
        |
        +---- SUCCEEDS ---> new gap / new research result
```

This second step produced important findings in both v0.4 and v0.5.

---

## 4. Benchmark Trust Model

The benchmark assumes that agents and agent-constructed authorization inputs may be
malicious. In particular, an attacker may attempt to control or forge:

- `AuthorizationRequest`
- delegation chains — `grant_id`, `invoking_principal_id`, `tool_id`,
  `implementation_id`, `action`, `resource`, `arguments`, task references
- invocation identifiers observed during prior execution

Trusted state is intentionally separated from those self-asserted fields. Current trusted
research boundaries include: canonical grant state in `InMemoryGrantStore`, revocation state
in `InMemoryRevocationStore`, canonical tool registrations in `InMemoryToolRegistry`,
runtime invocation provenance in `InMemoryInvocationStore`, and deterministic authorization
policy evaluation.

The benchmark assumes executing agents do not have direct write access to these trusted
stores.

---

## 5. Configuration Modes

The v0.5 experiments intentionally distinguish between weak and strong identity/provenance
modes.

### 5.1 Weak Invocation Provenance

When no `InMemoryInvocationStore` is configured, delegated authorization may check:

```
request.invoking_principal_id == leaf delegation grantor
```

This provides a consistency check but does not authenticate the caller. The field is
self-asserted by the request and is therefore forgeable under the benchmark attacker model.
Weak invocation provenance is not treated as a full INV-17 security guarantee.

### 5.2 Weak Tool Identity

When an `InMemoryToolRegistry` is configured without an invocation store, Ruhusa can
validate the request's `(tool_id, implementation_id)` against the canonical registry. This
blocks an openly unregistered implementation, but the identity fields themselves remain
self-asserted by the request. A compromised agent can therefore claim the registered tool
identity even when a different implementation actually executed.

### 5.3 Strong Runtime Provenance

When an `InMemoryInvocationStore` is configured, Ruhusa retrieves a canonical
`InvocationRecord` created by the trusted orchestration layer. The record binds:
`invocation_id`, invoking principal, executing principal, task, action, resource, arguments
digest, tool identity, implementation identity, `recorded_at`, and `expires_at`.

In strong mode, the invocation record is authoritative for invocation provenance and tool
identity. Self-asserted `invoking_principal_id`, `tool_id`, and `implementation_id` values
on the request do not establish the security claim.

---

## Part I — v0.4 Replanning and Delegation Benchmarks

## 6. v0.4 Research Question

The v0.4 benchmark asked: can an agent recover or expand authority after denial or
revocation by replanning, changing its delegation chain, replaying authority, or fabricating
a replacement grant?

Primary test file: `tests/test_replanning_attacks.py`

Seven adversarial scenarios are represented in the current suite.

---

## 7. v0.4 Benchmark Summary

| ID | Attack | Expected / Current Result | Primary Control | Verification Test |
|----|--------|--------------------------|-----------------|-------------------|
| V4-01 | Denied agent delegates to another agent and retries | BLOCKS — DENY | Delegation chain must originate from task initiator | `test_denied_agent_cannot_delegate_to_bypass_denial` |
| V4-02 | Child grant widens parent scope | BLOCKS — DENY | Per-hop scope attenuation | `test_child_grant_cannot_widen_scope` |
| V4-03 | Revoked authority reminted under fresh grant_id | BLOCKS — DENY | Trusted canonical grant issuance | `test_revoked_grant_reuse_via_fresh_chain_is_blocked_by_grant_store` |
| V4-04 | Grant replayed across tasks | BLOCKS — DENY | Task binding | `test_cross_task_replay_after_denial` |
| V4-05 | Alternate delegation path used to widen authority | BLOCKS — DENY for excess scope | Per-hop attenuation + policy | `test_alternate_delegation_path_does_not_widen_effective_authority` |
| V4-06 | Registered grant ID reused with modified scope | BLOCKS — DENY | Canonical full-content equality | `test_registered_id_with_tampered_scope_is_denied` |
| V4-07 | Grant-store backend unavailable | BLOCKS — DENY | Fail-closed trusted issuance verification | `test_grant_store_failure_is_fail_closed` |

---

## 8. v0.4 Key Experimental Finding

The important v0.4 result was not merely that scope attenuation or revocation worked. The
benchmark exposed a provenance problem.

**Baseline weakness.** A revoked grant could be replaced with a newly constructed grant
containing equivalent authority but a fresh `grant_id`. Structural delegation validation
could answer "is this grant internally valid?" but could not answer "was this authority
actually issued?"

**Root cause.** Grant structure was being treated as evidence of grant provenance.

**Control.** `InMemoryGrantStore` introduced a canonical issuance boundary:

```
presented grant
      |
      v
registered grant_id?
      |
     NO ----> DENY
      |
     YES
      |
      v
contents exactly match canonical grant?
      |
     NO ----> DENY
      |
     YES
      |
      v
continue authorization
```

**Follow-on variant.** The benchmark then tested a known legitimate `grant_id` with altered
scope. That attack was blocked by exact canonical equality rather than an ID-only membership
check.

This established an important Ruhusa research principle: a security-relevant identifier is
not sufficient evidence of provenance; the trusted system must establish what that identifier
canonically represents.

---

## Part II — v0.5 Tool Identity and Invocation Provenance Benchmarks

## 9. v0.5 Research Question

The v0.5 benchmark asks: does authorization remain valid when an allowed operation is
redirected through a different tool, when implementation identity is substituted, when a
privileged agent is induced to act for an unauthorized caller, or when previously valid
runtime provenance is replayed for a different operation?

Primary test file: `tests/test_tool_identity_attacks.py`

The current development benchmark contains fourteen experiments.

---

## 10. v0.5 Benchmark Summary

| Exp | Attack / Control | Mode | Result | Security Meaning | Verification Test |
|-----|-----------------|------|--------|-----------------|-------------------|
| 1 | Authorized action routed through substituted tool | Baseline / no registry | GAP — ALLOW | Action string does not identify implementation | `test_authorized_action_via_substituted_tool_is_not_detected` |
| 2 | Same logical tool name, different implementation | Baseline / no registry | GAP — ALLOW | Logical name alone does not establish implementation identity | `test_same_tool_name_different_implementation_is_not_detected` |
| 3 | Low-privilege agent induces privileged billing agent | Weak INV-17 consistency check | BLOCKS — DENY when caller is honestly represented | Invoker must match leaf grantor | `test_confused_deputy_low_privilege_induces_privileged_agent` |
| 4 | Completely different action attempted | Existing control | BLOCKS — DENY | Action scope/policy remains effective | `test_completely_different_action_is_denied` |
| 5 | Different resource attempted | Existing control | BLOCKS — DENY | Resource scope remains effective | `test_different_resource_is_denied` |
| 6 | Missing invoking principal | Weak INV-17 consistency check | BLOCKS — DENY | Missing provenance fails closed | `test_missing_invoking_principal_is_denied_for_delegated_action` |
| 7 | Unregistered substituted tool | Tool registry, weak identity mode | BLOCKS — DENY | Registry distinguishes registered vs unregistered pair | `test_substituted_tool_is_blocked_by_registry` |
| 8 | Same logical tool name, unregistered implementation | Tool registry, weak identity mode | BLOCKS — DENY | `(tool_id, implementation_id)` is stronger than name-only identity | `test_same_tool_name_different_implementation_blocked_by_registry` |
| 9 | Forge `invoking_principal_id` to legitimate grantor | Weak provenance mode | GAP — ALLOW | Self-asserted caller identity is forgeable | `test_forged_invoking_principal_bypasses_current_provenance_check` |
| 10 | Same forged invoker attack with canonical invocation store | Strong provenance mode | BLOCKS — DENY | Trusted runtime caller replaces self-asserted caller identity | `test_forged_invoking_principal_blocked_by_invocation_store` |
| 11 | Forge trusted tool identity fields | Tool registry without invocation store | GAP — ALLOW | Registered identity claim can still be forged by request creator | `test_forged_tool_identity_bypasses_weak_registry_check` |
| 12 | Same forged tool identity with canonical invocation record | Strong provenance + tool registry | BLOCKS — DENY | Actual orchestrator-observed implementation is authoritative | `test_forged_tool_identity_blocked_by_invocation_store` |
| 13 | Reuse legitimate invocation ID with modified arguments | Strong provenance | BLOCKS — DENY | Invocation is bound to exact operation arguments | `test_operation_substitution_blocked_by_arguments_digest` |
| 14 | Replay expired invocation record | Strong provenance | BLOCKS — DENY | Invocation provenance has independent temporal validity | `test_stale_invocation_record_is_denied` |

---

## 11. Experiment 1 — Tool Substitution Baseline

**Threat.** A trusted-looking semantic action is routed to a different implementation:

```
billing-agent + issue_refund
        |
        v
expected trusted implementation
is substituted with:
        |
        v
malicious implementation
```

The principal, action, resource, and arguments are unchanged.

**Baseline observation.** Without tool identity, both operations are indistinguishable to
the authorization layer. Result: GAP — ALLOW.

**Research implication.** An action identifier describes requested behavior; it does not
identify the code that will perform that behavior.

---

## 12. Experiment 2 — Logical Tool Name Collision

**Threat.** Two implementations claim the same logical tool name:

```
billing_refund_tool
       |
       +-- trusted implementation
       |
       +-- attacker implementation
```

**Baseline observation.** A name-only identity would not distinguish them. Result: GAP —
ALLOW.

**Research implication.** Tool identity requires at least a canonical pairing of
`(tool_id, implementation_id)` rather than a logical name alone.

---

## 13. Experiment 3 — Initial Confused-Deputy Control

**Threat.** A low-privilege agent cannot perform a refund directly but induces an authorized
billing agent to perform it:

```
low-privilege-agent
       |
       | induces
       v
billing-agent
       |
       | issue_refund
       v
protected resource
```

**Initial v0.5-A control.** The immediate invoking principal is compared with the grantor of
the leaf delegation grant. Result when the request honestly reports the attacker: BLOCKS —
DENY.

**Limitation discovered later.** The invoking principal was initially a self-asserted field.
Experiment 9 demonstrates that the field itself can be forged. Therefore Experiment 3 proves
a consistency property, not authenticated invocation provenance by itself.

---

## 14. Experiments 4 and 5 — Existing Scope Controls

Experiments 4 and 5 are control experiments. They establish that the introduction of new
tool-identity and invocation-provenance attacks does not invalidate existing authorization
controls.

Experiment 4 (different action — `delete_account` attempted while `issue_refund` authorized):
BLOCKS — DENY. Experiment 5 (different resource — `customer:456` attempted while
`customer:123` authorized): BLOCKS — DENY.

These controls matter because the v0.5 research is intended to strengthen provenance without
replacing action and resource scope enforcement.

---

## 15. Experiment 6 — Missing Invocation Identity

**Threat.** A delegated request omits `invoking_principal_id` to avoid the initial INV-17
comparison. Result: BLOCKS — DENY. Missing invocation identity fails closed.

**Research implication.** A security-relevant check must not be optional simply because its
associated request field is optional at the Python type level. However, requiring a value
still does not prove the value is authentic. Experiment 9 tests that next step.

---

## 16. Experiments 7 and 8 — Canonical Tool Registry

Experiments 7 and 8 rerun the original tool-substitution scenarios after introducing
`InMemoryToolRegistry`. The registry treats `(tool_id, implementation_id)` as the unit of
registered tool identity.

Experiment 7 — substitute openly identified with an unregistered implementation ID: BLOCKS
— DENY. Experiment 8 — attacker uses same logical tool name, different implementation ID:
BLOCKS — DENY.

**Important limitation.** These experiments prove that canonical registry membership
distinguishes an openly unregistered implementation. They do not establish that
self-asserted request fields correspond to the implementation actually executing. Experiment
11 demonstrates that stronger attack.

---

## 17. Experiment 9 — Forged Invoker

**Threat.** The attacker knows the leaf delegation grantor is `user-1`. Instead of
truthfully reporting `invoking_principal_id = low-privilege-agent`, the compromised
executing agent submits `invoking_principal_id = user-1`. Weak-mode result: GAP — ALLOW.

**Root cause.** The authorization check verifies equality between claimed invoker and leaf
grantor, but the request itself controls the claimed invoker. Equality between two fields
does not authenticate either field's real-world provenance. This is the invocation
equivalent of the grant-provenance finding from v0.4.

---

## 18. Experiment 10 — Trusted Invocation Provenance

**Control.** `InMemoryInvocationStore` stores a canonical `InvocationRecord` created by the
trusted orchestration layer. The executing agent may present an `invocation_id`, but it
cannot determine what the trusted record says about that ID. Strong-mode authorization
checks the canonical record rather than the request's self-asserted caller field.

**Attack paths.** (a) Missing invocation ID: delegated request with `invocation_id` absent
→ DENY. (b) Forged request field: request claims `invoking_principal_id = user-1`, trusted
`InvocationRecord` says `invoking_principal_id = low-privilege-agent` → canonical record
wins → DENY. Result: BLOCKS — DENY.

**Research implication.** Invocation identity claims require trusted runtime provenance; a
principal string inside an agent-controlled request is insufficient.

---

## 19. Experiment 11 — Forged Registered Tool Identity

**Threat.** After a tool registry is introduced, the attacker adapts. Instead of presenting
an obviously unregistered implementation ID, the compromised agent lies: actual
implementation is `billing_refund_tool@attacker-sha256:evil`; request claims
`billing_refund_tool@v1.2.0-sha256:abc123`. The claimed pair exists in the registry. Weak
mode result: GAP — ALLOW.

**Root cause.** The registry establishes what identities are trusted but not which
implementation actually executed. The request still self-asserts the identity being looked
up.

**Research implication.** Registry membership is not execution provenance. A trusted
registry answers "is this implementation identity trusted?" It does not, by itself, answer
"is this the implementation that actually executed?"

---

## 20. Experiment 12 — Runtime-Bound Tool Identity

**Control.** In strong mode, the trusted orchestrator records the actual resolved tool
identity in `InvocationRecord`. Ruhusa uses `record.tool_id` and `record.implementation_id`
for registry verification. The request's self-asserted tool identity is ignored for the
strong provenance decision.

**Attack.** Request falsely claims trusted implementation; canonical invocation record
contains actual substitute implementation:

```
AuthorizationRequest: implementation_id = TRUSTED_IMPL_ID
InvocationRecord:     implementation_id = SUBSTITUTE_IMPL_ID
        |
        v
ToolRegistry: SUBSTITUTE_IMPL_ID not trusted
        |
        v
DENY
```

Result: BLOCKS — DENY. The stronger security binding is trusted runtime observation plus
canonical tool registry, rather than registry membership alone.

---

## 21. Experiment 13 — Invocation Operation Substitution

**Threat.** A legitimate invocation record exists for `issue_refund` on
`customer:123:billing` with `amount = 250`. The attacker observes the valid `invocation_id`
and attempts to reuse it for `amount = 500`. The modified amount remains inside the ordinary
delegated scope and policy limit, so those controls alone would permit the request.

**Control.** `InvocationRecord` binds the invocation to action, resource, and SHA-256
digest of canonicalized arguments. Ruhusa recomputes the arguments digest from the live
request. Recorded digest ≠ live request digest → DENY.

**Security meaning.** An invocation ID is not a reusable bearer reference for arbitrary
operations permitted to the same agent. It is bound to the operation for which the trusted
runtime created it.

---

## 22. Experiment 14 — Stale Invocation Replay

**Threat.** An attacker retains a previously valid `invocation_id` and reuses it while the
broader task remains active.

**Control.** `InvocationRecord.expires_at` is enforced independently of
`TaskContext.expires_at`. Task still active + `InvocationRecord` expired → DENY. Result:
BLOCKS — DENY.

**Research implication.** Task lifetime and invocation lifetime are distinct authorization
concepts. A long-running task does not imply that every invocation created during that task
should remain reusable until task expiry.

---

## Part III — Cross-Version Findings

## 23. Recurring Research Pattern

The v0.4 and v0.5 benchmarks reveal the same deeper pattern.

v0.4 — agent presents grant fields, fields look structurally valid, but were they actually
issued? Result: trusted `GrantStore` required.

v0.5 invocation provenance — agent presents `invoking_principal_id`, value matches expected
grantor, but did that principal actually invoke the agent? Result: trusted `InvocationStore`
required.

v0.5 tool identity — agent presents registered tool identity, identity exists in
`ToolRegistry`, but is that what actually executed? Result: trusted runtime-observed tool
identity plus canonical `ToolRegistry`.

The emerging general principle:

> Security-relevant identity claims must be grounded in trusted provenance, not merely
> represented as matching strings inside an agent-controlled request.

---

## 24. Authority Preservation View

The benchmark is evolving from individual request validation toward preservation of
authority across workflow transformations. A protected action may be the product of:

```
human intent → delegation → sub-delegation → replanning
    → agent invocation → tool resolution → protected operation
```

The research question is therefore broader than "is this final action allowed?" The
benchmark increasingly asks: does the authority exercised by this action still correspond to
the authority that was legitimately delegated through every security-relevant transformation
that produced it?

---

## 25. Current Benchmark Coverage

The benchmark currently exercises the following threat classes: delegation-origin bypass,
privilege amplification through child delegation, revocation bypass through fresh grant
reminting, cross-task replay, alternate delegation-path escalation, canonical
grant-content tampering, authorization-store failure, tool substitution, logical tool-name
collision, confused-deputy invocation, missing invocation provenance, forged invocation
identity, forged tool identity, operation substitution / invocation replay, stale invocation
provenance, action-scope violation, and resource-scope violation.

The presence of an attack class in this list means an executable experiment exists. It does
not imply that every variant of that class has been explored.

---

## 26. Known Benchmark Gaps

The current benchmark does not yet provide comprehensive coverage for: concurrent
authorization and revocation races; check-to-use / TOCTOU between authorization and
side-effect execution; multi-agent collusion; branch-and-merge authorization propagation;
retry storms and state mutation across repeated tool calls; automatic descendant revocation;
cryptographic agent identity; cryptographic tool attestation; compromise of the trusted
orchestration layer; compromise of trusted stores; distributed-store consistency and
propagation delay; human-approval replay or approval-token substitution; derived-data and
information-flow authority; aggregation inference across separately authorized data; durable
workflow recovery after authorization state changes; and malicious tool behavior after a
correctly authenticated tool has been authorized.

These areas are candidates for future benchmark milestones.

---

## 27. Requirements for New Benchmark Cases

A new Ruhusa security claim should normally include an executable benchmark case. Each
benchmark should document: threat, preconditions, attacker capability, baseline behavior,
expected security invariant, control, verification, legitimate path, and follow-on attack.

Suggested test documentation format:

```python
# ---------------------------------------------------------------------------
# Experiment N: Short attack name
#
# Threat:
#   ...
#
# Baseline:
#   GAP — ALLOW
#
# Root cause:
#   ...
#
# Control:
#   ...
#
# Expected:
#   BLOCKS — DENY
# ---------------------------------------------------------------------------
```

---

## 28. Benchmark Interpretation Rules

**Rule 1 — Passing tests are not automatically successful defenses.** A passing GAP test
means the vulnerability was reproduced as expected. Always inspect the test's declared
benchmark status.

**Rule 2 — Weak and strong modes must not be conflated.** A control based on self-asserted
request fields may provide consistency checking without authenticated provenance. Claims
about INV-17 or INV-18 should state whether the experiment uses weak / self-asserted mode
or strong / trusted runtime provenance mode.

**Rule 3 — Positive-path testing matters.** A control that blocks all operations is not a
successful authorization design. Where practical, mitigation tests should demonstrate both
the attack path (DENY) and a legitimate path (ALLOW).

**Rule 4 — Security claims are scoped to represented attacks.** A successful test means the
tested attack variant is blocked under its stated assumptions. It does not prove complete
resistance to the entire threat category.

**Rule 5 — Known gaps remain visible.** Intentional GAP experiments should remain in the
benchmark after a stronger mode is implemented. They preserve the research history and
demonstrate why the stronger control was required.

---

## 29. Running the Benchmarks

```bash
# Run all project tests
uv run pytest

# Run the v0.4 replanning benchmark only
uv run pytest tests/test_replanning_attacks.py -v

# Run the v0.5 tool-identity and invocation-provenance benchmark only
uv run pytest tests/test_tool_identity_attacks.py -v

# Recommended full validation before recording a milestone result
uv run ruff format .
uv run ruff check .
uv run pytest
uv build
```

---

## 30. Milestone Documentation

The benchmark document is a living index of attack cases. Version-specific threat models
should remain frozen once a milestone is released.

```
docs/
├── architecture.md
├── attack-benchmarks.md          # living benchmark index
├── threat-model.md               # current threat model
└── threat-model/
    ├── v0.4.md                   # frozen v0.4 snapshot
    └── v0.5.md                   # create when v0.5 is released
```

When a milestone is completed: freeze the experiment set for that milestone; record the
associated security invariants; update the current threat model; create the versioned
threat-model snapshot; record the release validation result; and preserve baseline GAP
experiments that explain why new controls were introduced.

---

## 31. Research Traceability

The intended traceability chain is:

```
Research Question → Threat Model → Attack Benchmark → Observed Failure
    → Security Invariant → Implementation Control → Executable Verification
    → Experimental Result
```

This traceability is central to Ruhusa's role as a research framework. A security feature
should be explainable not only in terms of what the code does, but also: which attack
motivated it; which invariant it is intended to preserve; which test provides evidence;
which assumptions the evidence depends on; and which attack variants remain unresolved.

---

## 32. Current Research Direction

The benchmark currently suggests a transition from authorization of isolated actions toward
authorization preservation across workflow transformations. The working research question is:

> Under what workflow transformations does authorization cease to represent the authority
> originally delegated by a principal, and what runtime invariants are required to preserve
> that authority across delegation, revocation, replanning, concurrency, tool invocation,
> and information propagation?

The benchmark provides the executable evidence layer for studying that question. Future
experiments should continue to distinguish action authority from provenance of authority,
and eventually from information authority, so that Ruhusa can measure not only whether an
operation is allowed, but whether the authority exercised by that operation remains valid
throughout the workflow that produced it.
