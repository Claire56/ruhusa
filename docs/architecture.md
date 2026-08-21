# Ruhusa Architecture

**Architecture status:** Living document  
**Current framework milestone:** v0.5 development  
**Release status:** Pre-1.0 research framework

---

## 1. Purpose

Ruhusa is an open-source research framework for continuous, least-privilege authorization across AI agents, tools, and multi-agent workflows.

Its role is intentionally narrow:

> **The LLM may propose an action, but it never decides whether that action is authorized.**

Ruhusa sits between agent intent and protected side effects. It evaluates authority using deterministic policy, delegation state, revocation state, canonical provenance, resource and argument constraints, and audit controls.

Ruhusa is not an agent framework, workflow engine, model router, identity provider, or general-purpose IAM replacement.

Its architectural responsibility is to answer:

> May this principal perform this protected operation, under this task, through this authority and runtime provenance, at this point in time?

The broader research question is:

> Has the authority represented by this action remained valid throughout the workflow transformations that produced it?

---

## 2. Design Principles

### 2.1 The LLM Is Not the Authorization Boundary

Agents may interpret intent, propose actions, select tools, construct arguments, delegate work, and replan.

Authorization remains deterministic and outside the model.

### 2.2 Authority Must Narrow Through Delegation

A child grant may be equal to or narrower than its parent grant. It may not expand authority.

```text
Parent: refund <= $500
Child:  refund <= $250   VALID
Child:  refund <= $1000  DENY
```

### 2.3 Identity Claims Are Not Provenance

A request containing:

```text
grant_id = "grant-123"
```

does not prove that grant was issued.

Likewise:

```text
invoking_principal_id = "user-1"
```

does not prove `user-1` actually invoked the agent, and:

```text
tool_id = "billing_refund_tool"
implementation_id = "trusted-v1"
```

does not prove that implementation actually executed.

Where provenance matters, Ruhusa must rely on trusted canonical state rather than agent self-assertion.

### 2.4 Protected Actions Are Re-Evaluated

Authorization is evaluated at the protected-action boundary. A workflow that was previously authorized may later be denied because of revocation, task expiry, invocation expiry, policy changes, or trusted runtime state.

### 2.5 Required Security State Fails Closed

If required authorization state cannot be safely verified, Ruhusa denies the action.

### 2.6 Compatibility Checks Are Not Strong Security Guarantees

Weak pre-1.0 modes may inspect self-asserted identity fields for compatibility. Those modes must remain explicitly distinguishable from trusted runtime provenance.

### 2.7 Operation Binding Is Not One-Shot Consumption

Binding an invocation record to a specific action, resource, and argument digest prevents **modified-operation replay**.

It does not, by itself, prevent the exact same valid invocation from being authorized more than once.

That distinction is now confirmed experimentally by Experiment 16.

---

## 3. Architectural Position

```text
Human / System Principal
          |
          v
Agent / Multi-Agent Workflow
          |
          | proposes protected operation
          v
Trusted Orchestration Boundary
          |
          | creates trusted runtime provenance
          v
AuthorizationRequest
          |
          v
+----------------------------------+
|              Ruhusa              |
|                                  |
| deterministic authorization      |
| delegation validation            |
| provenance verification          |
| revocation                       |
| scope enforcement                |
| policy evaluation                |
| audit                            |
+----------------+-----------------+
                 |
        +--------+---------+
        |        |         |
      ALLOW    DENY   REQUIRE_APPROVAL
        |
        v
Protected Tool / API / Resource
```

Ruhusa is part of the authorization plane, not the reasoning plane.

---

## 4. Trust Boundary

### Untrusted or agent-controlled

```text
LLM reasoning
prompts
retrieved content
AuthorizationRequest fields
presented DelegationGrant objects
invoking_principal_id claims
tool_id claims
implementation_id claims
action
resource
arguments
```

### Trusted or canonical

```text
Ruhusa authorization core
StaticPolicyStore
InMemoryGrantStore
InMemoryRevocationStore
InMemoryInvocationStore
InMemoryToolRegistry
InMemoryAuditLog
trusted task metadata
trusted orchestration layer
```

The security value of an identifier comes from the canonical object it resolves to, not from the identifier string itself.

---

## 5. High-Level Runtime Architecture

The orchestration layer and tool registry have different responsibilities.

The orchestrator observes what actually happened. The registry defines which tool implementations are trusted.

```text
                   Human / System Principal
                             |
                             v
                    Trusted Orchestrator
                             |
            +----------------+----------------+
            |                                 |
            | records actual invocation       | resolves actual tool
            v                                 |
      InvocationRecord                        |
            |                                 |
            v                                 |
  InMemoryInvocationStore                     |
            |                                 |
            +---------------+                 |
                            |                 |
                            v                 v
                          Ruhusa <------ InMemoryToolRegistry
                            |               trusted registrations
                            |
                            v
                   Authorization Decision
```

The orchestrator does **not** populate the ToolRegistry merely by resolving a tool. Trusted registrations are a separate administrative/canonical concern.

---

## 6. Current `Ruhusa.authorize()` Order

The current implementation evaluates checks in this order:

```text
AuthorizationRequest
        |
        v
1. Task validity
        |
        v
2. Structural delegation validation
   - task initiator origin
   - identity continuity
   - task binding
   - grant time validity
   - scope attenuation
        |
        v
3. Invocation provenance for delegated requests
   STRONG:
     InvocationStore lookup
     invoker
     executor
     task
     action
     resource
     arguments digest
     invocation expiry
     runtime tool identity
   WEAK:
     self-asserted invoking_principal_id consistency
        |
        v
4. Weak-mode tool verification
   only when ToolRegistry exists
   and InvocationStore does not
        |
        v
5. Canonical grant provenance
   GrantStore, when configured
        |
        v
6. Revocation
        |
        v
7. Effective delegated scope
   action
   resource
   arguments
        |
        v
8. Policy evaluation
        |
        v
ALLOW | DENY | REQUIRE_APPROVAL
        |
        v
Audit every exit
```

This order reflects the current code, not a normative requirement that future versions must retain exactly the same sequence.

It also explains Experiment 15: strong invocation/tool verification is currently nested under `request.delegation_chain`, while weak tool verification is skipped whenever an invocation store exists.

---

## 7. Core Request Model

`AuthorizationRequest` represents the operation being evaluated.

Conceptually:

```text
AuthorizationRequest
├── principal
├── invoking_principal_id
├── invocation_id
├── task
├── delegation_chain
├── action
├── resource
├── arguments
├── tool_id
├── implementation_id
└── context
```

These fields do not all have the same trust level.

`invoking_principal_id`, `tool_id`, and `implementation_id` are self-asserted in weak mode. `invocation_id` is useful only because it resolves to a canonical record in a trusted store.

---

## 8. Delegation Architecture

Structural delegation validation is kept separate from runtime provenance.

### Chain origin

The first grant must originate from `task.initiated_by`.

### Identity continuity

```text
user-1 -> supervisor-agent -> billing-agent
```

The grantee of each grant must equal the grantor of the next.

### Scope attenuation

Each child scope must be a subset of its parent.

### Task binding

Every grant must belong to the current task.

### Temporal validity

Each grant must be active at authorization time and have a valid issuance/expiry window.

---

## 9. Trusted Grant Provenance

v0.4 established that structural validity does not prove legitimate issuance.

`InMemoryGrantStore` provides canonical grant provenance.

```text
presented grant
      |
      v
registered grant_id?
   |        |
  NO       YES
   |        |
 DENY       v
      exact canonical match?
          |       |
         NO      YES
          |       |
        DENY   continue
```

This distinguishes:

```text
Is this grant structurally valid?
```

from:

```text
Was this grant actually issued?
```

Grant identifiers are immutable within the registry: a known ID cannot silently be redefined with different authority.

---

## 10. Revocation

`InMemoryRevocationStore` is evaluated during protected delegated actions.

```text
12:00 grant valid
12:05 action -> ALLOW
12:10 grant revoked
12:11 action -> DENY
```

Properties:

- revocation is re-checked
- backend failure fails closed
- earlier emergency revocation may supersede a later scheduled revocation
- records are grant-scoped

Ruhusa does not yet maintain automatic descendant revocation. A presented chain containing a revoked ancestor is denied, but descendants are not independently marked revoked solely because their parent was revoked.

---

## 11. Invocation Provenance

v0.5 separates:

```text
who executes?
```

from:

```text
who caused the execution?
```

This distinction is essential for confused-deputy analysis.

### Weak mode

For delegated requests without an invocation store, Ruhusa requires `invoking_principal_id` and compares it with the grantor of the leaf delegation grant.

This detects missing or inconsistent caller claims.

It does **not** authenticate the caller. A compromised executing agent can forge the field.

### Strong delegated mode

`InMemoryInvocationStore` contains canonical `InvocationRecord` objects created by the trusted orchestration layer.

The record binds:

```text
invocation_id
invoking_principal_id
executing_principal_id
task_id
action
resource
arguments_digest
tool_id
implementation_id
recorded_at
expires_at
```

The executing agent may know the contents of a record or its identifier. Security does not rely on secrecy. The requirement is that the agent cannot modify the canonical record in the trusted store.

---

## 12. Strong Invocation Verification

For delegated requests in strong mode:

```text
request.invocation_id
        |
        v
record exists?
   NO ------> DENY
        |
       YES
        |
        v
invoker == leaf grantor?
   NO ------> DENY
        |
        v
executor == request principal?
   NO ------> DENY
        |
        v
task == request task?
   NO ------> DENY
        |
        v
action == request action?
   NO ------> DENY
        |
        v
resource == request resource?
   NO ------> DENY
        |
        v
arguments digest matches?
   NO ------> DENY
        |
        v
record unexpired?
   NO ------> DENY
        |
        v
strong tool check, when applicable
```

Operation binding prevents a valid invocation reference from being reused for a *different* action, resource, or argument set.

### Confirmed limitation: exact replay

Experiment 16 confirms that operation binding does not establish one-shot consumption.

The current `InMemoryInvocationStore` does not consume an invocation after authorization.

Therefore:

```text
same invocation_id
same action
same resource
same arguments
        |
        v
repeated authorizations may ALLOW
```

This is now a confirmed behavior, not an untested question.

The remaining architectural decision is whether Ruhusa should:

1. add one-shot/consumable invocation semantics; or
2. explicitly define exact replay/idempotency as an execution-layer responsibility.

---

## 13. Argument Binding

`compute_arguments_digest()` canonicalizes an arguments mapping using sorted JSON and hashes it with SHA-256.

```text
arguments
   |
   v
canonical JSON
   |
   v
SHA-256
   |
   v
arguments_digest
```

Ruhusa recomputes the digest from the live request and compares it with the canonical invocation record.

This detects argument substitution such as:

```text
recorded invocation: refund $250
live request:         refund $500
```

even if both values would otherwise satisfy ordinary scope and policy.

---

## 14. Tool Identity

An action string does not identify executable code.

```text
action = "issue_refund"
```

does not distinguish a trusted implementation from a substitute implementation.

`InMemoryToolRegistry` registers a pair:

```text
(tool_id, implementation_id)
```

and the actions that pair may perform.

The implementation identifier is canonical application metadata. Ruhusa does not currently provide cryptographic executable attestation.

---

## 15. Weak Tool Verification

When a tool registry is configured **without** an invocation store, Ruhusa requires the request to supply both:

```text
tool_id
implementation_id
```

and verifies:

- the pair is registered
- the pair allows the requested action

This blocks an openly unregistered implementation.

It does not prove that the claimed implementation actually executed. A compromised agent may claim a registered pair while using different code.

Experiment 11 confirms that this forgery succeeds in weak mode.

---

## 16. Strong Tool Verification

For a **delegated request** with both an invocation store and a tool registry, the authoritative tool identity comes from the canonical `InvocationRecord`.

```text
Trusted Orchestrator
        |
        | observes actual resolved tool
        v
InvocationRecord
        |
        v
InvocationStore
        |
        v
Ruhusa
        |
        | record.tool_id + record.implementation_id
        v
ToolRegistry
        |
        v
trusted and allowed for action?
```

Self-asserted request tool fields do not override the strong-mode record.

### Confirmed gap: non-delegated strong-mode bypass

Experiment 15 confirms that this protection is scoped to delegated requests in the current implementation.

With both stores configured:

```text
InvocationStore configured
ToolRegistry configured
delegation_chain = ()
principal directly allowed by policy
unregistered substitute tool
        |
        v
ALLOW
```

The reason is structural:

```text
strong invocation/tool check
    -> runs only inside delegated path

weak tool check
    -> runs only when no InvocationStore exists
```

Therefore a direct/non-delegated request can currently skip both checks.

This is a confirmed v0.5 gap and should not be described as protected until the architecture is changed and the benchmark rerun.

### Remaining candidate: missing canonical tool identity

Strong tool verification currently executes when `record.tool_id is not None`.

The behavior when a tool registry is configured but the canonical invocation record omits tool identity remains untested.

That is Candidate Experiment 17.

---

## 17. Effective Scope

Delegated scope enforcement remains independent of provenance controls.

### Action scope

Only delegated actions may execute.

### Resource scope

Only resources inside the effective resource prefixes may be used.

### Argument scope

Security-relevant argument constraints must remain inside effective delegated limits.

v0.5 strengthens provenance; it does not replace these earlier controls.

---

## 18. Policy Architecture

`StaticPolicyStore` is intentionally small and deterministic.

Policy evaluation may inspect principal, action, resource, arguments, and deterministic request context.

The possible effects are:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

No matching rule results in `DENY`. Policy evaluation exceptions also result in `DENY`.

The policy interface is separable from the authorization core so future adapters can integrate external PDPs without moving authorization into LLM judgment.

---

## 19. Human Approval

`REQUIRE_APPROVAL` is a first-class decision effect.

Ruhusa does not yet provide a complete approval workflow. A production integration would need durable pause/resume, authenticated approvers, separation of duties, TTL, replay resistance, and durable approval evidence.

---

## 20. Audit

`InMemoryAuditLog` records authorization decisions.

The current log is hash-chained.

It is **not** independently signed, externally anchored, or guaranteed tamper-proof.

The audit model is intended for research reconstruction and debugging, not production forensic assurance.

---

## 21. Authorization Plane vs Execution Plane

```text
AUTHORIZATION PLANE
--------------------------------
TaskContext
DelegationGrant
PolicyStore
GrantStore
RevocationStore
InvocationStore
ToolRegistry
AuditLog
        |
        v
Ruhusa.authorize()


EXECUTION PLANE
--------------------------------
Agent
  |
  | proposes action
  v
authorization decision
  |
  +-- DENY
  +-- REQUIRE_APPROVAL
  |
  +-- ALLOW
        |
        v
Protected Tool/API
```

Ruhusa authorizes. It does not itself guarantee that the caller correctly enforces the decision or that the external tool is idempotent.

This distinction is especially relevant to Experiment 16: without one-shot invocation semantics, duplicate execution may require execution-layer idempotency unless Ruhusa's contract is strengthened.

---

## 22. Fail-Closed Behavior

Authorization-critical lookup failures return `DENY`.

Current fail-closed paths include:

```text
policy evaluation failure
revocation lookup failure
grant-store verification failure
invocation-store verification failure
tool-registry verification failure
task expiry
```

The principle is:

> **Availability failure must not silently become authorization success.**

Fail-closed behavior applies only where the relevant check is actually reached. Experiment 15 demonstrates that a skipped security path is different from a failed security dependency.

---

## 23. Current v0.5 Gaps and Open Questions

### Confirmed Gap — Experiment 15: direct/non-delegated strong-mode tool bypass

**Observed result:** `ALLOW`

The current strong tool path does not cover direct/non-delegated requests when an invocation store is configured.

### Confirmed Gap — Experiment 16: exact invocation replay

**Observed result:** repeated `ALLOW`

The current invocation model binds the operation but does not consume the invocation.

The remaining design decision is whether exact replay is:

- an authorization-layer concern requiring one-shot invocation semantics; or
- an execution-layer concern requiring idempotency/deduplication.

### Candidate Experiment 17: missing canonical tool identity

**Status:** identified, not yet tested.

If a tool registry is configured but the canonical invocation record omits tool identity, the framework should explicitly define whether the request:

- fails closed; or
- is treated as a legitimate non-tool-mediated operation.

A benchmark should establish the contract.

---

## 24. Architectural Evolution

```text
v0.1  deterministic authorization core
      default deny
      delegation
      scope constraints
      policy
      approval effect
      hash-chained audit

v0.2  continuous revocation
      fail-closed revocation state

v0.3  task-bound delegation
      cross-task replay protection

v0.4  replanning attack benchmark
      trusted grant provenance
      canonical grant integrity

v0.5  in development
      invocation provenance
      confused-deputy analysis
      tool identity
      implementation identity
      operation-bound invocation records
      stale invocation rejection
      confirmed non-delegated tool-verification gap
      confirmed exact-invocation replay gap
```

---

## 25. Architectural Invariants

**INV-01 — Default deny.** No matching authorization rule means no authority.

**INV-02 — Fail closed.** Unverifiable required security state yields `DENY`.

**INV-03 — Delegation origin.** Delegation chains begin at the task initiator.

**INV-04 — Identity continuity.** Delegation hops form a continuous principal chain.

**INV-05 — No privilege amplification.** Delegation may narrow, never widen.

**INV-06 — Task binding.** Delegated authority cannot be replayed into another task.

**INV-07 — Temporal validity.** Expired or not-yet-valid authority cannot execute.

**INV-08 — Continuous revocation.** Revoked authority cannot authorize subsequent protected actions when the revoked grant is part of the evaluated chain.

**INV-09 — Earlier revocation wins.** Revocation may move earlier, not later.

**INV-10 — Scoped actions.** Requested actions must fit effective delegated scope.

**INV-11 — Scoped resources.** Requested resources must fit effective delegated scope.

**INV-12 — Scoped arguments.** Security-relevant arguments must fit effective delegated scope.

**INV-13 — Trusted grant provenance.** When canonical issuance verification is configured, structural grant validity alone is insufficient.

**INV-14 — Canonical grant integrity.** Presented grants must match canonical issued contents.

**INV-15 — Grant identity immutability.** A grant identity cannot silently change meaning.

**INV-16 — Auditability.** Authorization outcomes are recorded for reconstruction.

**INV-17 — Trusted invocation provenance.** In strong delegated mode, canonical runtime provenance binds invoker, executor, task, and protected operation.

**INV-18 — Trusted tool execution identity.** In strong delegated mode with a registry and canonical tool identity present, tool authorization uses runtime-observed canonical tool identity rather than self-asserted request fields.

INV-17 and INV-18 are intentionally scoped. Current benchmark evidence does not support extending INV-18 to direct/non-delegated requests.

There is not yet an invariant requiring one-shot invocation consumption.

---

## 26. Known Architectural Limitations

Current limitations include:

- in-memory research stores
- no cryptographic agent identity
- no cryptographic tool attestation
- no atomic authorization + external side effect
- no automatic descendant-revocation graph
- no one-shot invocation consumption
- direct/non-delegated strong-mode tool bypass confirmed by Experiment 15
- canonical missing-tool behavior not yet benchmarked
- no complete information-flow authorization
- no durable human-approval workflow
- trusted-orchestrator compromise outside the current guarantee

---

## 27. Relationship to Other Documents

```text
docs/architecture.md
    -> how the system is structured

docs/threat-model.md
    -> assumptions, threats, and security claims

docs/attack-benchmarks.md
    -> executable evidence

tests/
    -> concrete verification
```

A control should not become a documented guarantee until an appropriate threat and executable test support the claim.

---

## 28. Documentation Lifecycle

`docs/architecture.md` is a living document.

Historical architecture snapshots may be preserved separately, such as:

```text
docs/architecture/v0.1.md
```

Versioned threat models should remain frozen once released.

The frozen v0.4 threat model lives at:

```text
docs/threat-model/v0.4.md
```

When v0.5 is complete, the living threat model can be frozen to:

```text
docs/threat-model/v0.5.md
```

---

## 29. Core Architectural Principle

```text
Agent proposes
      |
      v
Trusted runtime establishes provenance
      |
      v
Ruhusa verifies authority
      |
      v
Deterministic policy decides
      |
      v
ALLOW / DENY / REQUIRE_APPROVAL
      |
      v
Protected side effect
```

> **Agent intelligence may determine what to attempt. Trusted deterministic authorization determines what may execute.**
