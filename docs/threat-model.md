# Ruhusa Threat Model

**Document status:** Living threat model for the current v0.5 line  
**Current package version:** 0.5.0  
**Frozen prior snapshot:** `docs/threat-model/v0.4.md`

---

## 1. Purpose

This document describes Ruhusa's current trust model, attacker capabilities, security invariants, tested threats, implemented controls, confirmed gaps, and known limitations.

When the v0.5 release is finalized, this content may be frozen as:

```text
docs/threat-model/v0.5.md
```

The frozen snapshot should then remain unchanged.

Ruhusa's central principles are:

> **The LLM may propose an action, but deterministic authorization logic outside the model decides whether it may execute.**

> **Authority should narrow as agents delegate—not expand.**

---

## 2. Security Objective

Ruhusa aims to preserve authorization correctness even when an executing AI agent is compromised, hallucinating, prompt-injected, or willing to misrepresent authorization-relevant information.

The framework does not attempt to guarantee correct model reasoning.

The objective is to prevent unauthorized protected actions when those actions pass through the Ruhusa authorization boundary under the stated trust assumptions.

---

## 3. Trust Boundary

### Trusted Components

When correctly configured, the research model treats the following as trusted:

- Ruhusa authorization core
- deterministic policy configuration
- `InMemoryGrantStore`
- `InMemoryRevocationStore`
- `InMemoryInvocationStore`
- `InMemoryToolRegistry`
- trusted task metadata
- trusted orchestration layer
- `InMemoryAuditLog` for normal application operation

### Untrusted Components and Inputs

The following may be attacker-controlled:

- LLM reasoning
- prompts
- retrieved documents
- `AuthorizationRequest`
- `invoking_principal_id`
- `tool_id`
- `implementation_id`
- action
- resource
- arguments
- presented delegation objects
- known invocation identifiers

Security does not depend on canonical identifiers or record contents remaining secret.

The central trust assumption is that the executing agent cannot directly modify canonical grant, invocation, revocation, tool-registry, or policy state.

---

## 4. Attacker Capabilities

The benchmark attacker may:

- construct arbitrary authorization requests
- lie about caller identity
- lie about tool identity
- select different actions, resources, or arguments
- present altered or fabricated grants
- retry after denial
- choose alternate delegation paths
- replay grant IDs
- replay invocation IDs
- replay an invocation for the exact same operation
- attempt direct/non-delegated paths
- attempt execution after revocation
- induce privileged agents to act as confused deputies
- attempt to exploit backend failures

The attacker is not currently assumed to have:

- arbitrary code execution inside the Ruhusa process
- direct write access to trusted stores
- control of the trusted orchestration layer
- compromise of the host/runtime trust boundary

---

## 5. Security Invariants

### INV-01 — Default Deny

No matching policy yields `DENY`.

### INV-02 — Fail Closed

If a required authorization dependency cannot be safely evaluated, the request is denied.

### INV-03 — Delegation Origin

A delegation chain begins at the task initiator.

### INV-04 — Identity Continuity

Each delegation hop connects the prior grantee to the next grantor.

### INV-05 — No Privilege Amplification

Delegated authority may remain equal or narrow; it may not widen.

### INV-06 — Task Binding

Delegated authority cannot be replayed into another task.

### INV-07 — Temporal Validity

Tasks, grants, and invocation records are subject to their configured time bounds.

### INV-08 — Continuous Revocation

A presented chain containing revoked authority is denied.

### INV-09 — Earlier Revocation Wins

Revocation may become effective earlier, but a later update must not restore authority by moving revocation later.

### INV-10 — Scoped Actions

Requested actions must fit effective delegated scope.

### INV-11 — Scoped Resources

Requested resources must fit effective delegated scope.

### INV-12 — Scoped Arguments

Security-relevant arguments must fit effective delegated constraints.

### INV-13 — Trusted Grant Provenance

When canonical grant verification is configured, structural grant validity alone is insufficient.

### INV-14 — Canonical Grant Integrity

Presented grant contents must match canonical issued grant contents.

### INV-15 — Grant Identity Immutability

A grant identity cannot silently change meaning.

### INV-16 — Auditability

Authorization decisions are recorded for reconstruction.

### INV-17 — Trusted Invocation Provenance

When an invocation store is configured, canonical runtime provenance binds:

- executing principal
- task
- action
- resource
- arguments
- expiry

For delegated requests, it additionally binds the immediate invoker to the leaf delegation grantor.

### INV-18 — Trusted Tool Execution Identity

When a tool registry is configured, canonical runtime tool identity must be present, registered, and authorized for the requested action.

Request-level tool identity claims do not override canonical runtime identity.

### Explicit Non-Invariant — Exactly-Once Execution

Ruhusa v0.5.0 does not claim that an invocation may authorize only once.

Experiment 16 confirms exact invocation replay remains possible.

---

## 6. Threat Catalog

### T1 — Wrong Action

An agent attempts an action outside delegated or policy scope.

**Status:** `BLOCKS`  
**Benchmark:** Experiment 4.

### T2 — Wrong Resource

An agent targets an unauthorized resource.

**Status:** `BLOCKS`  
**Benchmark:** Experiment 5.

### T3 — Confused Deputy With Truthful Caller Identity

A low-privilege agent induces a privileged agent to act and the request truthfully represents the low-privilege caller.

**Status:** `BLOCKS`

Weak mode provides only caller-consistency checking. It must not be interpreted as authenticated provenance because T5 remains possible.

### T4 — Missing Invoker

A delegated weak-mode request omits caller identity.

**Status:** `BLOCKS`

### T5 — Forged Invoker in Weak Mode

A compromised agent claims the legitimate leaf grantor as `invoking_principal_id`.

**Status:** `GAP — ALLOW`  
**Benchmark:** Experiment 9.

### T6 — Forged Invoker With Canonical Provenance

The same request-level forgery is attempted while canonical invocation provenance is configured.

**Status:** `BLOCKS`  
**Benchmark:** Experiment 10.

### T7 — Tool Substitution With No Registry

A protected action is routed to an arbitrary implementation.

**Status:** `GAP`  
**Benchmarks:** Experiments 1–2.

### T8 — Openly Unregistered Tool in Weak Registry Mode

The request openly identifies an unregistered implementation.

**Status:** `BLOCKS`  
**Benchmarks:** Experiments 7–8.

This does not protect against forged registered identity.

### T9 — Forged Registered Tool Identity in Weak Mode

The executing agent claims a trusted registered identity while actually using another implementation.

**Status:** `GAP — ALLOW`  
**Benchmark:** Experiment 11.

### T10 — Forged Tool Identity With Canonical Runtime Provenance

The request lies about tool identity, but the canonical invocation record identifies the actual implementation.

**Status:** `BLOCKS`  
**Benchmark:** Experiment 12.

### T11 — Modified-Operation Invocation Replay

A valid invocation ID is reused with a different action, resource, or arguments.

**Status:** `BLOCKS`  
**Benchmark:** Experiment 13.

### T12 — Stale Invocation Replay

A canonical invocation is used after expiry.

**Status:** `BLOCKS`  
**Benchmark:** Experiment 14.

### T13 — Authorization Backend Failure

A required security backend fails during authorization.

**Status:** evaluated paths fail closed.

### T14 — Direct/Non-Delegated Strong-Mode Tool Bypass

The original v0.5 path allowed a direct request to skip strong invocation/tool verification.

**Original result:** `GAP — ALLOW`

v0.5-C moved canonical invocation verification outside the delegated-only path.

**Current status:** `BLOCKS — DENY`  
**Benchmark:** Experiment 15.

This threat established that:

> **Fail-closed dependencies do not substitute for complete mediation.**

### T15 — Exact Same-Operation Invocation Replay

The same valid invocation ID is reused with the exact same action, resource, and arguments.

**Status:** `GAP — repeated ALLOW`  
**Benchmark:** Experiment 16.

This is an explicitly documented v0.5.0 limitation.

Ruhusa does not currently claim:

- one-shot authorization
- exactly-once execution
- atomic authorization + side effect
- execution-layer idempotency

### T16 — Missing Canonical Tool Identity

A tool registry is configured but canonical runtime provenance contains no tool identity.

v0.5-C now treats required missing canonical tool identity as an authorization failure.

**Status:** `BLOCKS — DENY`  
**Benchmark:** Experiment 17.

---

## 7. Configuration Modes

### Weak Mode

Without an invocation store:

- caller identity may be self-asserted
- tool identity may be self-asserted
- registry membership may catch openly unregistered identities
- forged legitimate-looking identities remain possible

Weak mode is not a trusted provenance guarantee.

### Strong Mode

With canonical invocation provenance:

- executor is verified
- task is verified
- action is verified
- resource is verified
- arguments are verified
- expiry is verified
- delegated invoker is verified
- canonical tool identity is verified when a registry is configured

Strong invocation verification applies to direct and delegated requests.

---

## 8. Complete Mediation

Experiment 15 demonstrated that the existence of a strong security check is insufficient if some request paths do not execute it.

v0.5-C corrected this by applying canonical invocation verification independently of delegation.

The general rule is:

> **Every protected action requiring a security control must pass through that control.**

---

## 9. Invocation Replay Semantics

Operation binding protects against substitution:

```text
recorded refund 250
replayed refund 500
        |
        v
DENY
```

but not identical replay:

```text
recorded refund 250
replayed refund 250
        |
        v
ALLOW
```

Therefore v0.5.0 provides operation-bound provenance, not one-shot or exactly-once semantics.

---

## 10. Fail-Closed Behavior

The following evaluated failures deny authorization:

- expired task
- invalid delegation
- missing/unknown required invocation record
- invocation-store exception
- missing required canonical tool identity
- untrusted tool implementation
- tool-registry exception
- grant-store exception
- revocation-store exception
- policy exception
- no matching policy

Fail closed protects failure paths.

Complete mediation ensures the relevant security path is actually reached.

Both properties are required.

---

## 11. Revocation

Revocation is grant-scoped.

Every grant presented in a delegation chain is checked.

A chain containing a revoked grant is denied.

Ruhusa does not yet maintain automatic descendant revocation.

---

## 12. Audit

Authorization decisions are recorded in a hash-chained in-memory audit log.

The audit chain is not independently signed or externally anchored.

It should not be described as tamper-proof.

---

## 13. Known Limitations

Ruhusa v0.5.0 does not provide:

- production-grade persistent authorization stores
- cryptographic principal identity
- cryptographic tool attestation
- automatic descendant revocation
- one-shot invocation consumption
- exactly-once execution
- atomic authorization + external side effect
- durable human approval
- comprehensive information-flow authorization
- protection from trusted-orchestrator compromise
- independently anchored audit evidence

Weak mode additionally remains vulnerable to self-asserted caller and tool identity forgery.

---

## 14. Out of Scope

The current framework does not claim to solve:

- general LLM alignment
- prompt-injection prevention itself
- content moderation
- malware detection
- model training security
- host/runtime compromise
- network security
- credential storage
- full IAM
- distributed consensus
- production availability
- sandbox escape
- comprehensive data-flow control

---

## 15. Security Testing Strategy

Ruhusa combines:

### Invariant Tests

Examples:

- default deny
- task binding
- revocation
- scope attenuation
- canonical grant integrity
- fail-closed security backends

### Adversarial Workflow Tests

Examples:

- delegation after denial
- fresh-grant remint
- cross-task replay
- confused deputy
- caller forgery
- tool substitution
- tool identity forgery
- operation substitution
- stale invocation replay
- complete-mediation bypass
- exact replay
- missing canonical tool identity

See `docs/attack-benchmarks.md`.

---

## 16. v0.5.0 Validation Baseline

The release candidate completed:

```text
uv run ruff format .
27 files left unchanged

uv run ruff check .
All checks passed!

uv run pytest
91 passed

uv build
dist/ruhusa-0.5.0.tar.gz
dist/ruhusa-0.5.0-py3-none-any.whl
```

Experiment status:

```text
Experiment 15 -> BLOCKS
Experiment 16 -> GAP / documented limitation
Experiment 17 -> BLOCKS
```

---

## 17. v0.5 Release Boundary

The v0.5 security contract intentionally includes the exact-replay limitation.

The release does not need to claim exactly-once execution in order to be internally consistent.

Future research can investigate:

- authorization consumption
- idempotency keys
- authorization/execution atomicity
- retry semantics
- concurrency
- TOCTOU

---

## 18. Research Position

Ruhusa should not claim novelty merely for default deny, revocation, least privilege, task binding, or deterministic policy enforcement.

The broader research question is:

> **Under what workflow transformations does authorization cease to represent the authority originally delegated by a principal, and what runtime invariants are required to preserve that authority across delegation, revocation, replanning, concurrency, tool invocation, and information propagation?**

The v0.5 experiments identify three related but distinct concerns:

```text
identity claim
    !=
trusted provenance

trusted security control
    !=
complete mediation

operation-bound provenance
    !=
execution uniqueness
```

This expands the research from static authorization toward preservation of authority across the lifecycle of an agentic workflow.

---

## 19. Maintenance Rule

A security control should not be documented as a guarantee until:

1. the threat is stated;
2. the trust assumptions are explicit;
3. the control is implemented; and
4. executable evidence supports the claim.

A `GAP` should remain visible until it is either mitigated or explicitly accepted as part of the security contract.

After release, freeze this document as:

```text
docs/threat-model/v0.5.md
```

and do not rewrite that historical snapshot.
