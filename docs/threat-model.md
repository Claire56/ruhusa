# Ruhusa Threat Model

**Document status:** Living threat model  
**Current framework milestone:** v0.5 development  
**Frozen prior snapshot:** `docs/threat-model/v0.4.md`

---

## 1. Purpose

This document describes the current trust model, attacker capabilities, security invariants, known threats, implemented controls, and unresolved research gaps for Ruhusa.

It is a living document while v0.5 is under development.

When v0.5 is complete, this document should be copied to:

```text
docs/threat-model/v0.5.md
```

and that snapshot should remain frozen.

Ruhusa's central security principles are:

> **The LLM may propose an action, but deterministic authorization logic outside the model decides whether it may execute.**

> **Authority should narrow as agents delegate—not expand.**

---

## 2. Security Objective

Ruhusa aims to preserve authorization correctness even when an executing AI agent is compromised, hallucinating, prompt-injected, or otherwise willing to misrepresent authorization-relevant information.

The security objective is not to guarantee correct model reasoning.

The objective is to prevent unauthorized protected actions when those actions pass through the Ruhusa authorization boundary under the stated trust assumptions.

---

## 3. Trust Boundary

### Trusted components

The current research model treats the following as trusted when correctly configured:

- Ruhusa authorization core
- deterministic policy configuration
- `InMemoryGrantStore`
- `InMemoryRevocationStore`
- `InMemoryInvocationStore`
- `InMemoryToolRegistry`
- trusted task metadata
- trusted orchestration layer
- `InMemoryAuditLog` for normal application operation

### Untrusted components and inputs

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
- invocation identifiers known to an executing agent

The executing agent may know canonical identifiers and record contents. Security must not depend on those values being secret.

The key assumption is that the executing agent cannot directly modify canonical grant, invocation, revocation, policy, or tool-registry state.

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
- replay known grant IDs
- replay known invocation IDs
- attempt to operate after revocation
- induce a privileged agent to act as a confused deputy
- exploit backend failure paths in an attempt to fail open

The attacker is not currently assumed to have:

- arbitrary code execution inside the Ruhusa process
- direct write access to trusted stores
- control of the trusted orchestration layer
- cryptographic compromise of the Python runtime or host

---

## 5. Security Invariants

### INV-01 — Default Deny

No matching policy yields `DENY`.

### INV-02 — Fail Closed

If required authorization state cannot be evaluated safely, the request is denied.

### INV-03 — Delegation Origin

The root of a delegation chain must be the task initiator.

### INV-04 — Delegation Identity Continuity

The grantee of one hop must be the grantor of the next.

### INV-05 — No Privilege Amplification

A child grant may narrow but not widen inherited authority.

### INV-06 — Task Binding

Delegated authority is bound to the task for which it was issued.

### INV-07 — Temporal Validity

Tasks, grants, and strong-mode invocation records are subject to their respective time bounds.

### INV-08 — Continuous Revocation

A presented delegation chain containing a revoked grant is denied.

### INV-09 — Earlier Revocation Wins

A revocation may become effective earlier but should not be moved later by a subsequent record.

### INV-10 — Scoped Actions

Requested actions must fit effective delegated scope.

### INV-11 — Scoped Resources

Requested resources must fit effective delegated scope.

### INV-12 — Scoped Arguments

Security-relevant arguments must fit effective delegated constraints.

### INV-13 — Trusted Grant Provenance

When a grant store is configured, structural grant validity is insufficient. The grant must have been registered through the trusted issuance boundary.

### INV-14 — Canonical Grant Integrity

A presented grant must exactly match the canonical registered grant.

### INV-15 — Grant Identity Immutability

A registered grant identity cannot silently change meaning.

### INV-16 — Auditability

Authorization decisions are recorded for later reconstruction.

### INV-17 — Trusted Invocation Provenance

In **strong delegated mode**, the canonical invocation record must bind the immediate invoker, executing principal, task, and protected operation.

Weak `invoking_principal_id` comparison is a compatibility consistency check, not authenticated provenance.

### INV-18 — Trusted Tool Execution Identity

In **strong delegated mode with a tool registry**, the tool identity used for authorization comes from canonical runtime provenance and must correspond to a trusted registered implementation authorized for the requested action.

Weak request-field tool verification is not authenticated execution provenance.

---

## 6. Threat Catalog

### T1 — Wrong action

An agent attempts an action outside delegated or policy scope.

**Status:** blocked by existing scope/policy controls.  
**Benchmark:** Experiment 4.

### T2 — Wrong resource

An agent applies an otherwise allowed action to an unauthorized resource.

**Status:** blocked.  
**Benchmark:** Experiment 5.

### T3 — Confused deputy with truthful caller identity

A low-privilege agent induces a privileged agent to act, and the request truthfully reports the low-privilege invoker.

**Weak-mode status:** blocked by invoker/leaf-grantor consistency.  
**Strong-mode status:** blocked by canonical invocation provenance.

This is not equivalent to complete confused-deputy resistance in weak mode because caller identity can be forged.

**Benchmark:** Experiment 3.

### T4 — Missing invoker

A delegated request omits `invoking_principal_id` in weak mode.

**Status:** blocked; omission fails closed.  
**Benchmark:** Experiment 6.

### T5 — Forged invoker in weak mode

A compromised agent forges `invoking_principal_id` to equal the legitimate leaf grantor.

**Status:** open gap in weak mode.  
**Benchmark:** Experiment 9.

### T6 — Forged invoker in strong delegated mode

The same request-level forgery is attempted while a canonical invocation store is configured.

**Status:** blocked because the request field is not authoritative.  
**Benchmark:** Experiment 10.

### T7 — Tool substitution with no registry

A protected action is routed through an arbitrary implementation.

**Status:** open gap in no-registry configurations.  
**Benchmarks:** Experiments 1–2.

### T8 — Unregistered tool substitution with weak registry

The request openly identifies an unregistered substitute implementation.

**Status:** blocked by `(tool_id, implementation_id)` registry membership.  
**Benchmarks:** Experiments 7–8.

### T9 — Forged registered tool identity in weak mode

A compromised agent actually uses a substitute implementation but claims the identity of a registered implementation.

**Status:** open gap in weak registry mode.  
**Benchmark:** Experiment 11.

### T10 — Forged tool identity in strong delegated mode

The request lies about tool identity, but the canonical invocation record identifies the actual resolved implementation.

**Status:** blocked when a tool registry is configured and the canonical record carries the runtime tool identity.  
**Benchmark:** Experiment 12.

### T11 — Operation substitution

An attacker reuses a legitimate invocation ID with a different action, resource, or arguments.

**Status:** blocked in strong delegated mode through exact action/resource comparison and arguments digest.  
**Benchmark:** Experiment 13.

### T12 — Stale invocation replay

An invocation ID is replayed after its canonical record expires while the broader task may still be active.

**Status:** blocked in strong delegated mode.  
**Benchmark:** Experiment 14.

### T13 — Backend failure as fail-open attack

An attacker causes a policy or security-state backend to fail.

**Status:** relevant paths are intended to fail closed and are represented by unit tests.

### T14 — Direct/non-delegated strong-mode tool bypass

A directly authorized request is evaluated while both an invocation store and tool registry are configured.

Current invocation-store verification is inside the delegated-request path, while weak tool verification is skipped when an invocation store exists.

**Status:** open, identified by code/document review; adversarial benchmark not yet added.

### T15 — Exact same-operation invocation replay

An attacker reuses the same valid invocation ID with the exact same action, resource, and arguments.

Operation binding does not distinguish first use from repeated identical use.

**Status:** open design/benchmark question. No one-shot consumption mechanism currently exists.

### T16 — Missing canonical tool identity in strong mode

A strong-mode invocation record contains no tool identity even though a tool registry is configured.

Current strong tool verification is conditional on `record.tool_id is not None`.

**Status:** open design/benchmark question.

---

## 7. Configuration Modes

### No invocation store

Caller provenance is self-asserted.

With no tool registry, tool identity is unchecked.

With a tool registry, openly unregistered tools are blocked, but a compromised agent can forge a registered tool identity.

### Strong delegated mode

When an invocation store is configured and the request is delegated, canonical runtime provenance is checked for:

- invoker
- executor
- task
- action
- resource
- arguments digest
- expiry

When a tool registry is also configured and the record contains tool identity, the canonical runtime tool pair is checked against the registry.

This is the strongest currently implemented configuration for delegated requests.

### Important scope limitation

Do not generalize the strong delegated-mode guarantee to all requests until direct/non-delegated strong-mode behavior is benchmarked and, if necessary, corrected.

---

## 8. Fail-Closed Behavior

The following failures result in `DENY`:

- task expiry
- invalid delegation
- missing/unknown strong-mode invocation ID for delegated requests
- invocation-store exceptions
- tool-registry exceptions
- grant-store exceptions
- revocation-store exceptions
- policy-evaluation exceptions
- no matching policy

Fail-closed behavior improves authorization integrity at the cost of availability.

---

## 9. Revocation Semantics

Revocation is grant-scoped.

Every grant presented in a delegation chain is checked.

A request containing a revoked ancestor is denied.

Ruhusa does not currently maintain automatic descendant revocation. Child grants are not independently marked revoked solely because their parent was revoked.

---

## 10. Audit Model

Authorization decisions are recorded in a hash-chained in-memory audit log.

The current audit mechanism is not independently signed or externally anchored.

It should not be described as tamper-proof.

The threat model assumes normal application control over the audit store; direct host/process compromise is out of scope.

---

## 11. Known Limitations

Current limitations include:

- in-memory security state
- grant store remains configuration-dependent
- weak caller identity is forgeable
- weak tool identity is forgeable
- no cryptographic agent identity
- no cryptographic tool attestation
- no atomic authorize-and-execute transaction
- no automatic descendant revocation
- no one-shot invocation consumption
- direct/non-delegated strong-mode tool enforcement not yet benchmarked
- missing canonical tool identity behavior not yet benchmarked
- no complete durable approval workflow
- no comprehensive information-flow authorization
- trusted-orchestrator compromise outside current guarantee
- audit chain not externally anchored

---

## 12. Out of Scope

The current framework does not claim to solve:

- general LLM alignment
- prompt-injection prevention itself
- content moderation
- malware detection
- model training security
- host or interpreter compromise
- network-layer security
- credential storage
- full IAM
- distributed consensus
- production high availability
- sandbox escape
- comprehensive data-flow control
- cryptographic workload identity

---

## 13. Security Testing Strategy

Ruhusa uses two complementary categories:

### Invariant tests

Verify direct properties such as:

- default deny
- task binding
- revocation
- scope attenuation
- canonical grant matching
- fail-closed errors

### Adversarial workflow tests

Model attacker adaptation:

- delegation after denial
- alternate delegation paths
- fresh-grant remint
- cross-task replay
- confused deputy
- caller forgery
- tool substitution
- tool identity forgery
- operation substitution
- stale invocation replay

See `docs/attack-benchmarks.md`.

---

## 14. Current v0.5 Release Gate

v0.5 should not be frozen until:

```text
existing v0.5 benchmark suite                 green
direct/non-delegated strong-mode tool case    resolved
exact invocation replay semantics             explicitly decided/tested
missing canonical tool identity case          explicitly decided/tested
architecture docs                             aligned
attack benchmark docs                         aligned
living threat model                           aligned
package version                               bumped in release commit
frozen v0.5 threat model                      created
```

The package remains `0.3.0` during active v0.5 development.

---

## 15. Research Position

Ruhusa should not claim novelty merely for default deny, revocation, task binding, least privilege, or policy enforcement. Those are foundational controls.

The broader research question is:

> **Under what workflow transformations does authorization cease to represent the authority originally delegated by a principal, and what runtime invariants are required to preserve that authority across delegation, revocation, replanning, concurrency, tool invocation, and information propagation?**

The benchmark evidence suggests that a recurring failure mode is loss of provenance as authority crosses workflow boundaries.

The long-term objective is therefore not only:

> Is this action allowed?

but also:

> Has the authority exercised by this action remained valid through every security-relevant transformation that produced it?

---

## 16. Maintenance Rule

A control should not be documented as a security guarantee until:

1. the threat is stated;
2. the trust assumptions are explicit;
3. the control is implemented; and
4. an appropriate executable test or experiment supports the claim.

When v0.5 is released, freeze this document as `docs/threat-model/v0.5.md`.
