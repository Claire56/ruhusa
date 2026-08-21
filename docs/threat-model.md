# Threat Model

This document describes the security model, trust boundaries, security invariants, and
known threats for the Ruhusa authorization library. It is a living document, updated as
the design evolves. A frozen snapshot will be committed when v0.5 is complete.

---

## Trust boundary

Ruhusa operates inside a multi-agent system where not all participants are equally trusted.
The central distinction is between the **orchestration layer** and **executing agents**.

The orchestration layer is trusted: it creates tasks, issues delegation grants, registers
invocation records, and populates the tool registry. Ruhusa assumes that anything the
orchestrator writes to the grant store, invocation store, or tool registry is a faithful
record of what the orchestrator actually observed or intended.

Executing agents are not trusted: a compromised, hallucinating, or adversarially prompted
agent may supply false values in any field of the `AuthorizationRequest` it constructs.
Ruhusa's design goal is that even a fully compromised executing agent cannot escalate
privileges or misuse authority beyond what the orchestrator explicitly authorized, provided
the authorization system is configured appropriately.

---

## Security invariants

The following invariants must hold for every `ALLOW` decision Ruhusa emits.

**Deny by default.** No policy match is a hard `DENY`. Every exception must be explicitly
granted; silence is not permission.

**Task must be active.** Authorization is only possible within an active task window. An
expired task yields `DENY` regardless of delegation or policy.

**Delegation chain must be identity-continuous.** Each grant's `grantee_id` must equal the
next grant's `grantor_id`. A break anywhere in the chain yields `DENY`.

**Delegated scope may narrow, never expand.** Each link in a delegation chain may restrict
the inherited scope; it may not introduce new actions or resources. The effective scope is
the intersection of all scopes in the chain.

**Grants must originate from the task initiator.** The root grantor of every chain must be
`task.initiated_by`. A chain that begins elsewhere is denied.

**Each grant must be bound to the current task.** Every grant's `task_id` must equal the
task under which authorization is being requested.

**If a grant store is configured, every chain grant must be registered through it.**
Unregistered grants are denied regardless of their contents.

**Revoked authority must not authorize.** If any grant in the chain has been revoked at or
before the authorization time, the request is denied.

**Action, resource, and arguments must fit the effective delegated scope.** The intersection
scope of the chain is checked against the live request.

**INV-17 — invocation provenance (delegated requests only).** The authenticated immediate
invoker of every delegated execution must match the grantor of the leaf delegation grant.
Two modes enforce this:

  *Strong mode* (invocation store configured): the orchestrator registers an
  `InvocationRecord` keyed by `invocation_id`. Ruhusa reads the authenticated
  `invoking_principal_id` from that record and compares it to the leaf grant's
  `grantor_id`. The executing agent cannot forge this — it does not hold write access to
  the store.

  *Weak mode* (no invocation store): Ruhusa reads `invoking_principal_id` from the
  `AuthorizationRequest`. This field is self-asserted by the executing agent and can be
  forged. It provides a lightweight check for non-adversarial environments but is not a
  security boundary. See threat T4 below.

**INV-18 — tool identity.** When a tool registry is configured and no invocation store is
present (weak mode), the request's `tool_id` and `implementation_id` must be registered
and the registration must authorize the requested action. When both a registry and an
invocation store are configured (strong mode), tool identity comes from the invocation
record — the self-asserted request fields are ignored entirely.

**Operation binding (strong mode).** When an invocation store is configured, the
`InvocationRecord` binds the exact operation — action, resource, and a SHA-256 digest of
the canonical arguments — that was authorized at invocation time. Ruhusa recomputes the
digest from the live request and denies any mismatch. This prevents argument escalation and
cross-operation replay of a valid `invocation_id`.

**Invocation record expiry (strong mode).** The `InvocationRecord` carries an `expires_at`
independent of the task's expiry. Stale records are denied even when the task is still
active.

**Fail-closed throughout.** Every store, registry, and policy evaluation is wrapped in
exception handling. Any backend failure yields `DENY`. Availability is a liveness concern;
correctness requires that unavailability defaults to denial, not to grant.

---

## Threat catalog

Threats are grouped by the attack class. Each entry names the attack, describes the attack
vector, states the current status under each deployment configuration, and references the
experiment(s) that document it. Full outcomes are in `docs/attack-benchmarks.md`.

### Action and resource scope violations

**T1 — Wrong action.** Agent attempts an action not in the authorized set. Blocked by
policy and scope evaluation. Experiment 4.

**T2 — Wrong resource.** Agent attempts to apply an authorized action to a resource outside
the authorized prefix. Blocked by scope evaluation. Experiment 5.

### Delegation and confused-deputy attacks

**T3 — Confused deputy.** A low-privilege agent induces a higher-privilege agent to act on
its behalf. The invoking principal field (INV-17) exposes the inducer's identity. If the
inducer is not the leaf grant grantor, the request is denied. Blocked in both weak and
strong mode. Experiment 3.

**T4 — Missing invoking principal on a delegated request.** An attacker omits
`invoking_principal_id` entirely, hoping to bypass the provenance check. INV-17 is
fail-closed: omission is a hard `DENY` in both modes. Experiment 6.

**T5 — Forged invoking principal (weak mode).** A compromised executing agent sets
`invoking_principal_id` to the leaf grant grantor's identity even though it was not the
actual caller. Weak mode trusts the self-asserted field; the forgery succeeds.
Gap under weak-mode deployment. Experiment 9.

**T6 — Forged invoking principal (strong mode).** Same attack, but an invocation store is
configured. The orchestrator's record contains the authenticated invoker; the forged field
in the request is ignored. The record's invoker does not match the leaf grantor, so the
request is denied. Blocked in strong mode. Experiment 10.

### Tool identity attacks

**T7 — Tool substitution (no registry).** An attacker routes an authorized action through
an unregistered or malicious tool implementation. With no tool registry configured, Ruhusa
has no mechanism to verify the implementation. Both the legitimate and substitute
implementations receive `ALLOW`. Gap in no-registry deployments. Experiments 1–2.

**T8 — Tool substitution (registry, weak mode).** Same attack, but a tool registry is
configured. The substitute's implementation ID is not registered; the request is denied.
The attacker cannot bypass this by claiming a registered `implementation_id` because... see
T10. Blocked by registry in weak mode. Experiments 7–8.

**T9 — Forged tool identity (weak mode).** A compromised executing agent claims a registered
`tool_id` and `implementation_id` in the `AuthorizationRequest` while actually invoking a
substitute implementation. The registry lookup checks the asserted values, which happen to
be registered, so the check passes. The actual tool executing is not the one the registry
describes. Gap under weak-mode deployment with a registry. Experiment 11.

**T10 — Forged tool identity (strong mode).** Same attack, but an invocation store is
configured. The orchestrator records the tool implementation it actually resolved in the
`InvocationRecord`. Ruhusa uses the record's `tool_id` / `implementation_id` for the
registry check; the self-asserted request fields are ignored. The record contains the
attacker's substitute implementation, which is not registered, so the request is denied.
Blocked in strong mode. Experiment 12.

### Invocation replay and operation substitution

**T11 — Operation / argument substitution.** An attacker obtains a valid `invocation_id`
authorized for one operation and presents it with different arguments (e.g., escalating a
$250 refund to $500) or a different action or resource. The `InvocationRecord` binds the
exact operation via a SHA-256 digest of the arguments and exact string comparison of action
and resource. A mismatch in any field yields `DENY`. Blocked in strong mode. Experiment 13.

**T12 — Stale invocation replay.** An attacker reuses an old `invocation_id` after its
authorized window has closed. The `InvocationRecord.expires_at` is enforced independently
of the task's expiry; an expired record yields `DENY` even when the task is still active.
Blocked in strong mode. Experiment 14.

### Infrastructure failures

**T13 — Backend unavailability as an attack surface.** An attacker causes a store or
registry to become unavailable, hoping that the failure path defaults to `ALLOW`. All
failure paths in Ruhusa are fail-closed: backend exceptions yield `DENY`. Covered by
`test_invocation_store_backend_failure_denies` and related tests.

---

## Two-mode architecture

Ruhusa supports two deployment modes with different security guarantees. Choosing between
them is a deployment-time decision based on the threat environment.

**Weak mode** (no `InMemoryInvocationStore`): suitable for non-adversarial environments
where executing agents are trusted not to forge identity fields. Provides delegation scope
enforcement, revocation, policy evaluation, and optional tool-name / implementation-id
checks via the registry. The invoker and tool identity fields on `AuthorizationRequest` are
self-asserted and not authenticated. An operator upgrading to strong mode does not need to
change any policy or grant configuration.

**Strong mode** (`InMemoryInvocationStore` configured): suitable for environments where
executing agents are untrusted. The orchestrator registers a tamper-evident invocation
record at invocation time; all identity and operation claims in the authorization check are
derived from that record rather than from the request. Requires that the orchestration layer
holds exclusive write access to the invocation store and does not expose it to executing
agents.

The combination of strong mode and a tool registry is the fully hardened configuration. It
closes all fourteen documented threat scenarios. Any other configuration leaves at least one
threat class open.

---

## Remaining gaps

The following gaps are known and accepted under specific deployment configurations.

Under **weak mode with no registry** (the simplest deployment), tool identity is entirely
unchecked (T7), and invoker provenance is self-asserted (T5). This configuration is
appropriate only where all participating agents are fully trusted.

Under **weak mode with a registry**, tool substitution using an unregistered implementation
is blocked (T8), but a compromised agent can forge a registered implementation ID (T9).
Invoker provenance remains self-asserted (T5).

Under **strong mode without a registry**, tool identity is not checked at all — the
invocation record's `tool_id` and `implementation_id` fields are recorded but no registry
lookup occurs. Invoker forgery (T6), operation substitution (T11), and stale replay (T12)
are all blocked. Tool substitution is not in scope for this configuration.

These gaps are documented here so that operators can make an informed deployment choice.
They are not implementation defects; they reflect the explicit design of the two-mode
architecture.

---

## Versioning note

The package version is `0.3.0` during active v0.5 development. The v0.4 milestone
(delegation refinements and replanning controls) was completed while the package version
stayed at `0.3.0`. The version will be bumped to `0.5.0` in a dedicated release commit once
the full v0.5 checklist is satisfied:

- confused-deputy provenance: blocked
- forged invocation identity: blocked
- invocation replay / substitution: blocked
- tool substitution: blocked
- tool implementation spoofing: blocked
- full suite: green
- threat model: updated (this document)
- attack benchmarks: updated (`docs/attack-benchmarks.md`)
