# Ruhusa Architecture

**Architecture status:** Living document
**Current framework milestone:** v0.5 development
**Release status:** Pre-1.0 research framework

---

## 1. Purpose

Ruhusa is an open-source research framework for continuous, least-privilege authorization
across AI agents, tools, and multi-agent workflows. Its role is narrow by design: the LLM
may propose an action, but it never decides whether that action is authorized.

Ruhusa sits between agent intent and protected side effects. It evaluates whether an action
is permitted using deterministic authorization logic, delegation state, revocation state,
trusted provenance, scope constraints, policy, and audit controls.

Ruhusa is not an agent framework, model router, workflow engine, identity provider, or
general-purpose IAM replacement. Its architectural responsibility is to answer:

> May this principal perform this protected operation, under this task, through this
> delegation and runtime provenance, at this point in time?

As the framework evolves, the broader research question becomes:

> Has the authority represented by this action remained valid throughout the workflow
> transformations that produced it?

---

## 2. Design Principles

### 2.1 The LLM Is Not the Authorization Boundary

LLMs may interpret user intent, select candidate actions, propose tool calls, generate
arguments, delegate work, and replan after failure. LLMs do not make the final authorization
decision. That decision is made by deterministic code outside the model.

### 2.2 Authority Must Narrow Through Delegation

A child agent may receive authority equal to or narrower than the authority available to its
parent. It may not expand that authority.

```
Parent authority:   refund <= $500
Valid child:        refund <= $250
Invalid child:      refund <= $1,000
```

### 2.3 Security-Relevant Claims Require Provenance

A string inside an agent-controlled request is not, by itself, proof of identity or
authority. For example, `grant_id = "grant-123"` does not prove the grant was legitimately
issued. Similarly, `invoking_principal_id = "user-1"` does not prove that `user-1` actually
invoked the agent. And `tool_id = "billing-refund-tool"` / `implementation_id = "trusted-v1"`
does not prove that the trusted implementation actually executed.

Where provenance matters, Ruhusa resolves security-relevant state from trusted or canonical
sources.

### 2.4 Protected Actions Are Re-Evaluated

Authorization is evaluated at the protected-action boundary. Authority that was valid earlier
in a workflow may become invalid later because of revocation, task expiry, invocation expiry,
changed policy, or changed trusted runtime state.

### 2.5 Required Security State Fails Closed

If Ruhusa cannot safely determine required authorization state, the action is denied:

```
policy backend failure           -> DENY
revocation backend failure       -> DENY
grant provenance unavailable     -> DENY
invocation provenance unavailable -> DENY
```

### 2.6 Compatibility Modes Must Not Be Confused With Strong Guarantees

Ruhusa may preserve weaker compatibility modes during pre-1.0 development. Those modes can
provide useful consistency checks, but they must not be described as equivalent to trusted
provenance.

---

## 3. Architectural Position

Ruhusa sits between agent decision-making and external side effects.

```
Human / System Principal
          |
          v
Agent / Multi-Agent Workflow
          |
          | proposes protected action
          v
Trusted Orchestration Boundary
          |
          | constructs / enriches runtime context
          v
AuthorizationRequest
          |
          v
+----------------------------------+
|             Ruhusa               |
|                                  |
| deterministic authorization      |
| provenance verification          |
| delegation validation            |
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

Ruhusa is therefore part of the authorization plane, not the reasoning plane.

---

## 4. Trust Boundary

The architecture separates agent-controlled claims from trusted authorization state.

```
UNTRUSTED / AGENT-CONTROLLED
--------------------------------
LLM reasoning
prompts
retrieved documents
AuthorizationRequest fields
delegation objects presented at runtime
caller identity claims
tool identity claims
action arguments
resource identifiers


TRUSTED / CANONICAL
--------------------------------
Ruhusa authorization core
StaticPolicyStore
InMemoryGrantStore
InMemoryRevocationStore
InMemoryInvocationStore
InMemoryToolRegistry
InMemoryAuditLog
trusted task metadata
trusted runtime orchestration
```

The distinction is architectural, not merely conceptual. Whenever a security decision depends
on provenance, Ruhusa should prefer canonical state over self-asserted request fields.

---

## 5. High-Level Architecture

The current architecture through v0.5 development is:

```
                    Human / System Principal
                              |
                              v
                    Trusted Orchestrator
                              |
             +----------------+----------------+
             |                                 |
             | records invocation              | resolves actual tool
             v                                 v
     InMemoryInvocationStore             InMemoryToolRegistry
             |                                 |
             +----------------+----------------+
                              |
                              v
                    AuthorizationRequest
                              |
                              v
                  +------------------------+
                  |        Ruhusa          |
                  | Authorization Core     |
                  +-----------+------------+
                              |
                              v
                   1. Task validation
                              |
                              v
                   2. Delegation validation
                      - chain origin
                      - identity continuity
                      - task binding
                      - temporal validity
                      - scope attenuation
                              |
                              v
                   3. Grant provenance
                      InMemoryGrantStore
                              |
                              v
                   4. Invocation provenance
                      InMemoryInvocationStore
                      - invoker
                      - executor
                      - task
                      - action
                      - resource
                      - arguments digest
                      - tool identity
                      - implementation identity
                      - expiry
                              |
                              v
                   5. Tool identity
                      InMemoryToolRegistry
                              |
                              v
                   6. Revocation
                      InMemoryRevocationStore
                              |
                              v
                   7. Effective scope
                      - action
                      - resource
                      - arguments
                              |
                              v
                   8. Policy evaluation
                      StaticPolicyStore
                              |
                              v
                 +------------+-------------+
                 |            |             |
               ALLOW        DENY      REQUIRE_APPROVAL
                 |
                 v
              Tool / API
```

The exact ordering may evolve as the framework matures, but the separation of concerns
should remain stable.

---

## 6. Core Request Model

The `AuthorizationRequest` represents the operation Ruhusa is being asked to evaluate.
Conceptually, it contains:

```
AuthorizationRequest
├── principal
├── invoking principal claim
├── invocation identifier
├── task
├── delegation chain
├── action
├── resource
├── arguments
├── tool identity claim
├── implementation identity claim
└── context
```

Not every field has the same trust level.

**Agent-controlled request fields.** Fields such as `action`, `resource`, `arguments`,
`invoking_principal_id`, `tool_id`, and `implementation_id` may be supplied by an
agent-controlled workflow. They should therefore be treated as claims unless a trusted
boundary independently establishes them.

**Trusted runtime references.** Fields such as `invocation_id` can act as references into
trusted runtime state when backed by `InMemoryInvocationStore`. The security value comes
from the canonical record retrieved from the store, not from the identifier alone.

---

## 7. Authorization Core

`Ruhusa.authorize()` is the primary authorization boundary. Its job is not merely to match
a policy rule. It coordinates multiple independent checks: task validity, delegation
structure, trusted grant provenance, trusted invocation provenance, trusted tool identity,
revocation, effective action/resource/argument scope, policy, and audit.

The authorization core should remain deterministic and independent of LLM reasoning.

---

## 8. Task Validation

Every authorization request executes within a `TaskContext`. Task context provides a bounded
workflow identity. Typical task properties include `task_id`, `initiated_by`, `purpose`, and
`expires_at`. The task acts as the root context for delegation. A request is denied when the
task is expired. Task identity is also used to prevent cross-task authority replay.

---

## 9. Delegation Architecture

Delegation allows one principal to transfer a bounded subset of authority to another
principal. The delegation model enforces structural invariants independently from trusted
runtime provenance.

### 9.1 Chain Origin

The first grant must originate from the task initiator (`task.initiated_by`). Mismatch →
DENY.

### 9.2 Identity Continuity

Each delegation hop must connect correctly — the grantee of one grant must equal the grantor
of the next:

```
user-1 -> supervisor-agent -> billing-agent
```

### 9.3 Scope Attenuation

Each child grant must remain within the authority of its parent. Scope may include actions,
resource prefixes, and numeric argument limits.

### 9.4 Task Binding

Every grant in the chain must belong to the current task. This prevents reuse of Task A
authority under Task B.

### 9.5 Temporal Validity

Delegation grants are bounded by issuance and expiry times. A grant cannot be used before it
becomes valid, after it expires, or when its validity window is invalid.

---

## 10. Trusted Grant Provenance

Structural validity does not prove legitimate issuance. Ruhusa v0.4 introduced
`InMemoryGrantStore` to establish canonical grant provenance:

```
Presented DelegationGrant
          |
          v
grant_id registered?
    |            |
   NO           YES
    |            |
  DENY           v
          contents match canonical?
               |          |
              NO         YES
               |          |
             DENY      continue
```

The key distinction is between "is this grant structurally valid?" and "was this grant
actually issued?" The grant store answers the second question.

**Grant identity immutability.** Once a `grant_id` is registered, it must not silently
change meaning. Re-registering the same identity with different grant contents is rejected.

---

## 11. Revocation Architecture

`InMemoryRevocationStore` tracks revoked grant identities. Revocation is checked during
authorization rather than only at issuance time:

```
12:00  grant valid
12:05  action -> ALLOW
12:10  grant revoked
12:11  action -> DENY
```

Revocation is checked continuously at protected actions; backend failure fails closed;
earlier emergency revocation may supersede later scheduled revocation; and revocation records
are grant-scoped.

**Descendant limitation.** Ruhusa does not currently maintain a full descendant-revocation
graph. If a presented chain contains a revoked ancestor, the request is denied. However,
child grants are not automatically stored as revoked simply because the parent is revoked.

---

## 12. Invocation Provenance

v0.5 introduces a distinction between "who is executing?" and "who caused the execution?"
This distinction matters for confused-deputy attacks.

**Weak mode.** A request may contain `invoking_principal_id`. A simple consistency check can
compare that field with the grantor of the leaf delegation grant. However, a self-asserted
caller identity is not trusted invocation provenance — an attacker capable of constructing
the request can forge the field. Weak mode therefore provides consistency checking, not a
full provenance guarantee.

**Strong mode.** `InMemoryInvocationStore` stores canonical `InvocationRecord` objects
created by the trusted orchestration layer. A strong invocation record binds: `invocation_id`,
invoking principal, executing principal, task, action, resource, arguments digest, tool
identity, implementation identity, `recorded_at`, and `expires_at`. The authorization core
retrieves the canonical record and verifies it against the live request and delegation chain.

---

## 13. Invocation Verification

Strong-mode invocation verification conceptually performs:

```
request.invocation_id
        |
        v
canonical InvocationRecord exists?    NO --> DENY
        |
       YES
        |
        v
record expired?                       YES --> DENY
        |
        v
record.invoker == leaf grantor?       NO --> DENY
        |
        v
record.executor == request principal? NO --> DENY
        |
        v
record.task == request task?          NO --> DENY
        |
        v
record.action == request action?      NO --> DENY
        |
        v
record.resource == request resource?  NO --> DENY
        |
        v
record.arguments_digest == live?      NO --> DENY
        |
        v
continue
```

This architecture prevents a legitimate invocation identifier from becoming a reusable
bearer token for arbitrary actions.

---

## 14. Argument Binding

Invocation provenance includes a digest of canonicalized action arguments:

```
arguments -> canonical serialization -> SHA-256 -> arguments_digest
```

At authorization time, Ruhusa recomputes the digest from the live request and compares it
with the canonical invocation record. This prevents a replayed invocation (`refund amount =
250`) from being reused for a substituted one (`refund amount = 500`) even when both values
are inside ordinary policy bounds.

---

## 15. Tool Identity Architecture

v0.5 introduces a distinction between "what operation is requested?" and "which
implementation will perform it?" An action string such as `issue_refund` does not identify
executable code.

Ruhusa models tool identity using a pair such as:

```
tool_id          = billing-refund-tool
implementation_id = billing-refund-service:v1
```

`InMemoryToolRegistry` defines which canonical tool implementations are trusted and which
operations they are permitted to perform.

---

## 16. Weak vs Strong Tool Verification

**Weak registry mode.** The request presents `(tool_id, implementation_id)` and Ruhusa
checks whether the pair exists in `InMemoryToolRegistry`. This blocks an openly unregistered
implementation, but a malicious request could claim the trusted implementation identity.
Registry membership is not execution provenance.

**Strong runtime tool provenance.** The trusted orchestration layer records the actual
resolved tool identity inside `InvocationRecord`. In strong mode, Ruhusa uses
`record.tool_id` and `record.implementation_id` as the authoritative runtime identity and
checks that pair against `InMemoryToolRegistry`:

```
Trusted Orchestrator
        | resolves actual implementation
        v
InvocationRecord (tool_id + implementation_id)
        |
        v
ToolRegistry -> trusted?
```

This combines runtime provenance with canonical registry, rather than trusting request
fields alone.

---

## 17. Effective Scope

After delegation, provenance, and revocation checks, Ruhusa evaluates the requested
operation against effective delegated scope. Current scope concepts include action scope
(only delegated actions permitted), resource scope (only delegated resource prefixes
permitted), and numeric argument bounds (security-relevant arguments must remain within
delegated limits). Scope enforcement is independent from trusted invocation and tool
provenance; v0.5 preserves these earlier controls rather than replacing them.

---

## 18. Policy Architecture

`StaticPolicyStore` is the current deterministic policy implementation — intentionally small
and inspectable. A policy may evaluate principal, action, resource, request arguments, and
deterministic request context. A policy returns ALLOW, DENY, or REQUIRE_APPROVAL. No
matching policy produces DENY. Policy exceptions also produce DENY.

The policy interface is intentionally separable from the core request/decision model so
future adapters can integrate external policy-decision systems without requiring LLM
involvement in authorization. Potential future adapters include OPA/Rego,
OpenID AuthZEN-style PDP interfaces, enterprise IAM systems, and custom ABAC engines.

---

## 19. Human Approval

Ruhusa models REQUIRE_APPROVAL as a first-class authorization outcome. This allows
deterministic policy to distinguish safe-for-autonomous-execution (ALLOW), forbidden (DENY),
and allowed-only-after-human-approval (REQUIRE_APPROVAL).

The core framework does not yet provide a full durable approval workflow. A production
integration would need to address approver authentication, separation of duties, approval
TTL, approval replay, workflow pause/resume, and durable state.

---

## 20. Audit Architecture

`InMemoryAuditLog` records authorization decisions. The audit system is intended to support
security debugging, experiment analysis, authorization trace reconstruction, correlation of
denials and allows, and future evaluation metrics. The current audit log is hash-chained —
not tamper-proof. The current design does not yet provide independent signing, external
anchoring, or append-only infrastructure.

---

## 21. Authorization Plane vs Execution Plane

Ruhusa deliberately separates authorization from tool execution:

```
AUTHORIZATION PLANE                     EXECUTION PLANE
--------------------------------        --------------------------------
TaskContext                             Agent
DelegationGrant                           | proposes action
PolicyStore                               | authorization decision
GrantStore                                |
RevocationStore                           +------ DENY
InvocationStore                           +------ REQUIRE_APPROVAL
ToolRegistry                              +------ ALLOW
AuditLog                                              |
        |                                             v
        v                                          Tool/API
Ruhusa.authorize()
```

Ruhusa does not execute the protected action merely because it understands the action. The
caller remains responsible for honoring the authorization decision.

---

## 22. Fail-Closed Architecture

Fail-closed behavior is enforced around authorization-critical dependencies:

```
required security lookup
        |
        v
available?   NO --> DENY
        |
       YES
        |
        v
continue
```

Current fail-closed targets include policy evaluation, revocation lookup, canonical grant
verification, invocation provenance verification, and task validity. The security principle:
availability failure must not silently become authorization success.

---

## 23. Architectural Evolution

```
v0.1  Deterministic authorization core, default deny, delegation,
      scope constraints, policy, human approval outcome,
      hash-chained audit

v0.2  Continuous revocation, fail-closed revocation state

v0.3  Task-bound authority, cross-task replay protection

v0.4  Replanning attack suite, trusted grant provenance,
      canonical grant integrity

v0.5  Invocation provenance, confused-deputy analysis,
      tool identity, implementation identity,
      operation-bound invocation records, runtime tool provenance
```

This progression reflects an important architectural pattern: a security claim represented
as a request field → adversarial test → self-assertion found insufficient → trusted
canonical provenance introduced.

---

## 24. Current Security State: v0.5 Development

At the current v0.5 development stage, the architecture supports or is actively testing:
deterministic authorization, delegation attenuation, task binding, revocation, trusted grant
provenance, invocation provenance, confused-deputy resistance, tool registry, tool
implementation identity, operation-bound invocation records, stale invocation rejection, and
fail-closed security lookups.

Because v0.5 is still under development, these capabilities should be described together
with their configuration mode and benchmark evidence. In particular, weak / self-asserted
mode must not be described as equivalent to strong / trusted runtime provenance mode. The
attack benchmark remains the source of truth for which attack variants have actually been
demonstrated and blocked. See `docs/attack-benchmarks.md`.

---

## 25. Known Architectural Limitations

### 25.1 Production-Grade Durable Stores

Current research stores are primarily in-memory.

### 25.2 Cryptographic Agent Identity

Principal strings are not yet backed by workload identity, signatures, or remote
attestation.

### 25.3 Cryptographic Tool Attestation

A runtime tool identity is trusted because it is observed by the trusted orchestration
boundary, not because Ruhusa verifies a hardware- or signature-backed executable identity.

### 25.4 Atomic Authorization + Side Effect

Ruhusa does not yet provide a transaction that atomically combines authorization and
execution of an external side effect. This leaves future TOCTOU and concurrency research.

### 25.5 Automatic Descendant Revocation

Revocation does not yet propagate through a maintained delegation graph.

### 25.6 Information-Flow Authorization

Ruhusa currently focuses on action authority. It does not yet fully model whether an agent
is authorized to derive or disclose information produced by combining multiple individually
authorized data sources.

### 25.7 Durable Human Approval

REQUIRE_APPROVAL is a decision state, not a complete workflow engine.

### 25.8 Trusted-Orchestrator Compromise

The current strong-provenance model assumes the orchestration boundary that writes canonical
invocation records is trusted. Compromise of that boundary is outside the current guarantee.

---

## 26. Future Architecture Directions

Future work may introduce: durable GrantStore / RevocationStore / InvocationStore backends;
distributed consistency experiments; cryptographic invocation records; agent workload
identity; tool signatures or attestations; authorization-aware workflow engines; LangGraph
integration; MCP authorization adapters; A2A authorization propagation; OAuth/OIDC-backed
principal identity; AuthZEN-style policy interfaces; OPA/Rego adapters; OpenTelemetry
correlation; durable approval workflows; descendant-revocation graphs; concurrency controls;
information provenance; and derived-data authority.

These should be introduced only when tied to an explicit threat, invariant, or experiment.

---

## 27. Architectural Invariants

**INV-01 — Default Deny.** No authorization rule means no authority.

**INV-02 — Fail Closed.** Unverifiable required security state results in denial.

**INV-03 — Delegation Origin.** Delegation chains begin at the task initiator.

**INV-04 — Identity Continuity.** Delegation hops must form a continuous principal chain.

**INV-05 — No Privilege Amplification.** Delegated authority may narrow but not expand.

**INV-06 — Task Binding.** Delegated authority cannot be replayed into another task.

**INV-07 — Temporal Validity.** Expired or not-yet-valid authority cannot execute.

**INV-08 — Continuous Revocation.** Revoked authority cannot authorize subsequent protected
actions.

**INV-09 — Earlier Revocation Wins.** Revocation may move earlier, not later.

**INV-10 — Scoped Actions.** Only delegated actions are permitted.

**INV-11 — Scoped Resources.** Only delegated resources are permitted.

**INV-12 — Scoped Arguments.** Security-relevant arguments must remain within delegated
limits.

**INV-13 — Trusted Grant Provenance.** A structurally valid grant is insufficient when
trusted issuance verification is enabled.

**INV-14 — Canonical Grant Integrity.** Presented grant contents must match canonical issued
contents.

**INV-15 — Grant Identity Immutability.** A grant identity must not silently change meaning.

**INV-16 — Auditability.** Authorization decisions should be reconstructable.

**INV-17 — Trusted Invocation Provenance.** A delegated execution must correspond to trusted
runtime provenance binding the immediate invoker, executing principal, task, and protected
operation.

**INV-18 — Trusted Tool Execution Identity.** When strong runtime provenance is enabled, the
tool identity used for authorization must come from trusted runtime observation and must
correspond to a registered tool implementation.

---

## 28. Relationship to Threat Model and Benchmarks

The architecture document describes how Ruhusa is structured. The threat model describes
what Ruhusa assumes and what it protects. The attack benchmark describes what adversarial
behavior has actually been tested.

```
Architecture -> Threat Model -> Attack Benchmark -> Executable Tests
```

These documents should remain aligned. A new architectural control should not become a
documented security guarantee until its associated threat and verification experiment exist.

---

## 29. Documentation Lifecycle

`docs/architecture.md` is a living document. It should evolve as the current framework
architecture changes. Important historical snapshots may be preserved separately.

Recommended structure:

```
docs/
├── architecture.md
├── architecture/
│   └── v0.1.md
├── attack-benchmarks.md
├── threat-model.md
└── threat-model/
    ├── v0.4.md
    └── v0.5.md
```

The original v0.1 architecture should be preserved as `docs/architecture/v0.1.md` rather
than overwritten and lost. Versioned threat models should remain frozen after release. The
canonical architecture should continue to represent the current design.

---

## 30. Core Architectural Principle

```
Agent proposes
      |
      v
Trusted runtime establishes provenance
      |
      v
Ruhusa verifies authority
      |
      v
Policy decides
      |
      v
ALLOW / DENY / REQUIRE_APPROVAL
      |
      v
Protected side effect
```

Agent intelligence may determine what to attempt. Trusted deterministic authorization
determines what may execute.

As Ruhusa evolves, the framework extends that principle from isolated tool calls toward
preservation of legitimate authority across the full workflow that produced them.
