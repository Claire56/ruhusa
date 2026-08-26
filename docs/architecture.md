# Ruhusa Architecture

**Architecture status:** Living document  
**Current framework milestone:** v0.6 — validated execution-lifecycle, execution-time authority, and recovery milestone  
**Current package version:** 0.6.0  
**Release status:** Pre-1.0 research framework; v0.6.0 validated for release with a frozen security snapshot at `docs/threat-model/v0.6.md`

---

## 1. Purpose

Ruhusa is an open-source research framework for continuous, least-privilege authorization across AI agents, tools, and multi-agent workflows.

> **The LLM may propose an action, but it never decides whether that action is authorized.**

Ruhusa sits between agent intent and protected side effects. It evaluates authority using deterministic policy, delegation state, revocation state, canonical runtime provenance, resource and argument constraints, and audit controls.

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

A request field is a claim unless trusted runtime state independently establishes it.

```text
grant_id
invoking_principal_id
tool_id
implementation_id
```

Matching strings do not prove issuance, invocation, or execution identity.

### 2.4 Complete Mediation Matters

A correctly implemented security check provides no protection if a valid request path can skip it.

Experiment 15 demonstrated this directly and motivated the v0.5-C change that applies canonical invocation verification to direct and delegated requests.

### 2.5 Operation Binding Is Not Execution Uniqueness

Binding an invocation record to:

```text
action
resource
arguments digest
```

prevents modified-operation replay.

It does not prevent exact repeated authorization of the same invocation.

Experiment 16 demonstrates this distinction.

### 2.6 Execution Claiming Is Separate From Invocation Provenance

An immutable `InvocationRecord` establishes what operation was authentically created. Mutable execution lifecycle state establishes whether that operation has already been claimed, completed, cancelled, or left with an uncertain outcome.

```text
InvocationStore -> what operation was authentically created?
ExecutionStore  -> has that operation's execution authority been used?
```

This separation preserves provenance while allowing replay, retry, and concurrency semantics to evolve independently.

### 2.7 Authorization-Time Validity Is Not Execution-Time Validity

An operation may be authorized and claimed, then become invalid before the side effect because a grant is revoked, a task expires, or policy changes.

v0.6-B therefore revalidates the complete authorization path immediately before use.

### 2.8 Execution-Time Revalidation Is Not Atomic Execution

A successful final check can still be followed by an authority change before a remote side effect occurs.

```text
revalidate -> ALLOW
       |
       | authority changes
       v
external side effect
```

Experiment 35 preserves this residual TOCTOU boundary.

### 2.9 Required Security State Fails Closed

If a required authorization dependency cannot be evaluated, Ruhusa denies the request.

### 2.10 Weak Compatibility Checks Are Not Strong Guarantees

Self-asserted caller and tool identity remain useful for compatibility experiments, but they are not equivalent to canonical runtime provenance.

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
          | creates canonical runtime provenance
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
| tool verification                |
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

### Untrusted or Agent-Controlled

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

### Trusted or Canonical

```text
Ruhusa authorization core
StaticPolicyStore
InMemoryGrantStore
InMemoryRevocationStore
InMemoryInvocationStore
InMemoryToolRegistry
InMemoryExecutionStore
InMemoryAuditLog
trusted task metadata
trusted orchestration layer
```

The security value of an identifier comes from the canonical state it resolves to, not from the identifier string itself.

---

## 5. High-Level Runtime Architecture

The trusted orchestrator records what actually occurred at runtime. The tool registry separately defines which implementations are trusted. v0.6 adds a distinct execution lifecycle after authorization.

```text
                   Human / System Principal
                             |
                             v
                    Trusted Orchestrator
                             |
            +----------------+----------------+
            |                                 |
            | records invocation              | resolves actual tool
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
                            |
                            v
                   Authorization Decision
                            |
                            v
                   ExecutionController
                            |
                            v
                InMemoryExecutionStore
                            |
                    +-------+-------+
                    |               |
                  DENY            CLAIMED
                                    |
                                    v
                    revalidate_before_execution()
                                    |
                              +-----+-----+
                              |           |
                            ALLOW        DENY
                              |           |
                              v           v
                       Protected Tool   CANCELLED
                              |
                        +-----+-----+
                        |           |
                   COMPLETED      UNKNOWN
```

The orchestrator does not make a tool trusted merely by observing it. Trust registration and runtime observation are separate responsibilities.

The execution store is also distinct from invocation provenance:

```text
InvocationStore
    immutable provenance for the operation

ExecutionStore
    mutable lifecycle for the execution attempt
```

---

## 6. Current Authorization and Execution Flow

### 6.1 Authorization

The authorization flow remains deterministic:

```text
AuthorizationRequest
        |
        v
1. Task validity
        |
        v
2. Structural delegation validation, if delegated
   - chain origin
   - identity continuity
   - task binding
   - temporal validity
   - scope attenuation
        |
        v
3. Canonical invocation verification, when configured
   - applies to direct and delegated requests
   - executor
   - task
   - action
   - resource
   - arguments digest
   - expiry
   - invoker / leaf grantor consistency when delegated
        |
        v
4. Canonical tool verification, when configured
   - canonical tool identity must be present
   - implementation must be registered
   - implementation must allow action
        |
        v
5. Canonical grant provenance, when configured
        |
        v
6. Revocation
        |
        v
7. Effective delegated scope
        |
        v
8. Policy evaluation
        |
        v
ALLOW | DENY | REQUIRE_APPROVAL
        |
        v
Audit
```

This structure closes the direct/non-delegated complete-mediation gap originally demonstrated by Experiment 15.

### 6.2 Execution Claim

`ExecutionController.begin()` first calls `Ruhusa.authorize()`. Only an allowed operation can attempt to claim execution authority.

`InMemoryExecutionStore.claim()` provides process-local atomic claiming:

```text
AVAILABLE
    |
    | claim
    v
CLAIMED
```

A second claim for the same invocation is denied while the first claim remains active. A completed, cancelled, or unknown invocation is not automatically reusable.

### 6.3 Execution-Time Revalidation

Immediately before the protected side effect, a side-effecting integration can call:

```text
ExecutionController.revalidate_before_execution(request, permit)
```

The full authorization path runs again. This re-observes current revocation, task validity, policy, delegation, provenance, tool identity, and required security-store state.

If live authority is no longer valid:

```text
CLAIMED -> CANCELLED
```

`CANCELLED` is terminal for that invocation. Restored authority requires a new trusted invocation.

### 6.4 Completion, Safe Release, and Uncertain Outcome

Known successful side effect:

```text
CLAIMED -> COMPLETED
```

Failure known to occur before any side effect:

```text
CLAIMED -> AVAILABLE
```

Uncertain external result:

```text
CLAIMED -> UNKNOWN
```

`UNKNOWN` intentionally blocks automatic retry because Ruhusa cannot know whether a remote side effect already occurred.

### 6.5 Current Boundary

v0.6-B revalidation narrows the authorization-to-use TOCTOU window but does not make authorization state and a remote side effect one atomic transaction.

Experiment 35 intentionally preserves this boundary.

---

## 7. Request Model and Trust

Conceptually, `AuthorizationRequest` contains:

```text
principal
invoking_principal_id
invocation_id
task
delegation_chain
action
resource
arguments
tool_id
implementation_id
context
```

Not every field has equal trust.

Self-asserted caller and tool fields are weak claims.

An `invocation_id` becomes security-relevant because it resolves to a canonical record in `InMemoryInvocationStore`.

---

## 8. Delegation

Delegation validation enforces:

### Chain Origin

The first grant originates from the task initiator.

### Identity Continuity

```text
user -> supervisor-agent -> billing-agent
```

Each grantee must equal the next grantor.

### Scope Attenuation

Authority can narrow but not widen.

### Task Binding

Every grant must belong to the current task.

### Temporal Validity

Each grant must be active and have a valid time window.

---

## 9. Trusted Grant Provenance

v0.4 established that structural grant validity does not prove legitimate issuance.

`InMemoryGrantStore` provides canonical provenance:

```text
presented grant
      |
      v
registered?
  NO ----> DENY
      |
     YES
      |
      v
exact canonical match?
  NO ----> DENY
      |
     YES
      |
      v
continue
```

This distinguishes:

```text
valid-looking grant
```

from:

```text
actually issued grant
```

---

## 10. Revocation

`InMemoryRevocationStore` is checked during protected delegated actions.

```text
grant valid
    |
    v
ALLOW

grant revoked
    |
    v
future authorization
    |
    v
DENY
```

Revocation-store failures fail closed.

Automatic descendant revocation is not yet implemented.

---

## 11. Invocation Provenance

v0.5 separates:

```text
who executes?
```

from:

```text
who caused execution?
```

### Weak Mode

Without an invocation store, delegated requests may use `invoking_principal_id` as a consistency claim.

Experiment 9 demonstrates that this field can be forged.

### Strong Mode

The trusted orchestration layer creates a canonical `InvocationRecord` binding:

```text
invocation_id
invoking principal
executing principal
task
action
resource
arguments digest
tool identity
implementation identity
recorded_at
expires_at
```

The executing agent may know the identifier and record contents. Security depends on the agent being unable to alter canonical trusted state, not on secrecy.

---

## 12. Canonical Invocation Verification

With an invocation store configured, canonical verification now applies to both direct and delegated requests.

Ruhusa verifies:

```text
record exists
record unexpired
record.executor == request principal
record.task == request task
record.action == request action
record.resource == request resource
record.arguments_digest == live digest
```

For delegated requests, it additionally verifies:

```text
record.invoker == leaf grantor
```

This separation is important.

Invocation verification is no longer dependent on the existence of a delegation chain.

That change is what closes Experiment 15.

---

## 13. Argument Binding

Arguments are canonically serialized and hashed.

```text
arguments
   |
   v
canonical representation
   |
   v
SHA-256
   |
   v
arguments_digest
```

The live request digest must match the canonical invocation record.

This blocks operation substitution such as:

```text
recorded: refund 250
replayed: refund 500
```

---

## 14. Tool Identity

An action string does not identify executable code.

```text
action = issue_refund
```

may be implemented by multiple tools.

`InMemoryToolRegistry` models trusted identity using:

```text
(tool_id, implementation_id)
```

and associates that pair with allowed actions.

Ruhusa does not currently provide cryptographic executable attestation.

---

## 15. Weak Tool Verification

Without an invocation store, request-provided:

```text
tool_id
implementation_id
```

can be checked against the registry.

This detects openly unregistered implementations.

Experiment 11 demonstrates that a compromised agent can still forge a registered identity in weak mode.

Therefore:

> **Registry membership is not execution provenance.**

---

## 16. Strong Tool Verification

When canonical invocation provenance and a tool registry are configured, the authoritative tool identity comes from the `InvocationRecord`.

```text
trusted runtime
    |
    v
InvocationRecord
    |
    v
Ruhusa
    |
    v
ToolRegistry
```

Request-supplied tool identity cannot override canonical runtime identity.

### Experiment 15 — Resolved

The original implementation applied strong invocation/tool verification only inside the delegated path.

That created a direct-request bypass.

v0.5-C moved canonical invocation verification outside the delegated-only branch.

**Current result:**

```text
BLOCKS
```

### Experiment 17 — Resolved

If `ToolRegistry` is configured but canonical tool identity is missing, Ruhusa now fails closed.

**Current result:**

```text
BLOCKS
```

---

## 17. Exact Invocation Replay and Execution Claiming

Experiment 16 established the v0.5 baseline:

```text
same invocation
same operation
    |
    +--> authorize: ALLOW
    +--> authorize: ALLOW
```

v0.6 intentionally preserves this behavior in `Ruhusa.authorize()` so authorization remains a non-consuming query and the historical baseline stays reproducible.

v0.6-A adds a separate execution lifecycle:

```text
same invocation
    |
    +--> begin: CLAIMED
    +--> begin again: DENY
```

Experiments 18–27 show that process-local execution claiming blocks duplicate active claims, replay after completion, expired authority, and stale/forged permits while preserving safe pre-side-effect retry.

Therefore:

> **Operation-bound provenance is not execution uniqueness; execution uniqueness requires lifecycle state beyond provenance.**

Ruhusa still does not claim exactly-once external side effects.

---

## 18. Scope Enforcement

Delegation scope may restrict:

- actions
- resources
- numeric or supported argument values

These controls remain independent of provenance.

A request with correct provenance can still be denied for exceeding delegated scope.

---

## 19. Policy

`StaticPolicyStore` is intentionally deterministic and inspectable.

Policy outcomes are:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

No matching policy returns `DENY`.

Policy failures return `DENY`.

The policy interface is designed so future external PDP integrations can be added without moving authorization into LLM judgment.

---

## 20. Human Approval

`REQUIRE_APPROVAL` is a first-class authorization decision.

Ruhusa does not yet provide a complete durable approval workflow.

Future production-like integration would need:

- authenticated approvers
- separation of duties
- approval TTL
- approval replay protection
- durable workflow pause/resume
- durable approval evidence

---

## 21. Audit

`InMemoryAuditLog` is hash-chained.

It should be described as:

```text
hash-chained
```

not:

```text
tamper-proof
```

It is not independently signed or externally anchored.

---

## 22. Authorization vs Execution

Ruhusa v0.6 separates immutable invocation provenance from mutable execution
lifecycle state.

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
ExecutionController
        |
        +--> begin()
        |      authorize + claim
        |
        +--> revalidate_before_execution()
        |      live authority check
        |
        +--> complete()
        |
        +--> mark_unknown()
        |
        +--> mark_stale_claim_unknown()
        |
        +--> reconcile_unknown()
```

The execution lifecycle is:

```text
AVAILABLE --claim--> CLAIMED --complete--> COMPLETED
    ^                   |
    |                   +--uncertain/stale--> UNKNOWN
    |                                       /       \
    |                        confirmed no effect    confirmed effect
    |                                  |               |
    +----------------------------------+               v
                                                  COMPLETED

CLAIMED --live authority invalid--> CANCELLED
```

v0.6 establishes process-local lifecycle controls. It does not establish
transactional atomicity with an external system.

A critical recovery trust boundary remains:

```text
self-asserted recovery outcome
    !=
trusted execution evidence
```

`reconcile_unknown()` is intended for trusted reconciliation infrastructure.
Ruhusa v0.6 does not authenticate that infrastructure or independently prove
the outcome it supplies.

---

## 23. Fail-Closed Behavior

Security backend failures are denied when the relevant check is required and reached.

Examples include:

```text
policy failure
revocation-store failure
grant-store failure
invocation-store failure
tool-registry failure
execution-store failure
```

v0.5 also reinforces an important distinction:

> **Fail closed is not the same as complete mediation.**

Experiment 15 was originally possible because a security path was skipped, not because a security backend failed open.

---

## 24. v0.6 Experiment Status

The current benchmark contains **44 implemented experiments**.

```text
v0.5
Exp 15  direct/non-delegated mediation bypass       BLOCKS after mitigation
Exp 16  exact authorize() replay                     GAP / preserved baseline
Exp 17  missing canonical tool identity              BLOCKS

v0.6-A
Exp 18                                               GAP / preserved baseline
Exp 19-21                                           BLOCKS
Exp 22                                              CONTROL
Exp 23-25                                           BLOCKS
Exp 26                                              CONTROL
Exp 27                                              BLOCKS

v0.6-B
Exp 28                                              BLOCKS
Exp 29                                              GAP / temporal baseline
Exp 30-34                                           BLOCKS
Exp 35                                              GAP / residual TOCTOU

v0.6-C
Exp 36-38                                           BLOCKS / completed recovery
Exp 39                                              CONTROL
Exp 40-44                                           BLOCKS
```

The v0.6-C tests establish fail-closed stale-claim handling and process-local
UNKNOWN reconciliation. They do not establish authenticated provenance for a
reconciliation outcome.

---

## 25. Architectural Invariants

**INV-01 — Default deny.** No matching authorization rule means no authority.

**INV-02 — Fail closed.** Unverifiable required security state yields `DENY`.

**INV-03 — Delegation origin.** Delegation chains begin at the task initiator.

**INV-04 — Identity continuity.** Delegation hops form a continuous principal chain.

**INV-05 — No privilege amplification.** Delegation may narrow but never widen.

**INV-06 — Task binding.** Delegated authority cannot be replayed into another task.

**INV-07 — Temporal validity.** Expired or not-yet-valid authority cannot execute.

**INV-08 — Continuous revocation.** A chain containing revoked authority cannot authorize subsequent protected actions.

**INV-09 — Earlier revocation wins.** Revocation may move earlier, not later.

**INV-10 — Scoped actions.** Requested actions must fit effective authority.

**INV-11 — Scoped resources.** Requested resources must fit effective authority.

**INV-12 — Scoped arguments.** Security-relevant arguments must fit effective authority.

**INV-13 — Trusted grant provenance.** Structural validity is insufficient when canonical issuance verification is configured.

**INV-14 — Canonical grant integrity.** Presented grants must match canonical issued contents.

**INV-15 — Grant identity immutability.** A grant identity cannot silently change meaning.

**INV-16 — Auditability.** Authorization outcomes are recorded.

**INV-17 — Trusted invocation provenance.** Canonical runtime provenance binds the executor, task, protected operation, and, for delegated requests, the immediate invoker.

**INV-18 — Trusted tool execution identity.** When tool verification is required, canonical runtime tool identity must be present, registered, and authorized for the action.

**EXE-01 — Single active execution claim.** Within the configured execution store, one invocation may have at most one active claimed attempt.

**EXE-02 — Live authority at execution boundary.** Side-effecting integrations can re-run the complete authorization path immediately before use.

**EXE-03 — Uncertain outcomes fail closed.** An uncertain or stale execution is quarantined in `UNKNOWN`, not silently made retryable.

**EXE-04 — Recovery transitions are state-bound.** Reconciliation is accepted only from `UNKNOWN`; terminal `COMPLETED` and `CANCELLED` state is not resurrected by that path.

There is intentionally **no v0.6 invariant claiming distributed exactly-once execution, authenticated recovery-evidence provenance, or transactional authorization plus side effect**.

---

## 26. Known Limitations

v0.6.0 does not provide:

- production-grade durable security stores;
- cryptographic agent identity;
- cryptographic tool attestation;
- automatic descendant revocation;
- distributed execution-claim consensus;
- durable execution-state recovery;
- authenticated/provenanced reconciliation evidence;
- exactly-once external execution;
- downstream idempotency;
- atomic authorization/revocation + external side effect;
- automatic recovery when the external outcome remains unknowable;
- prevention of authority change after the final revalidation instant;
- complete information-flow authorization;
- durable approval workflows;
- protection from trusted-orchestrator compromise;
- independently anchored audit records.

The current execution and recovery stores demonstrate process-local semantics.

---

## 27. Evolution

```text
v0.1
deterministic authorization
delegation
scope
policy
audit

v0.2
continuous revocation

v0.3
task binding
cross-task replay protection

v0.4
attack-driven replanning analysis
trusted grant provenance

v0.5
trusted invocation provenance
tool and implementation identity
operation binding
complete invocation mediation
missing-tool fail-closed behavior
documented exact-replay limitation

v0.6-A
execution lifecycle
atomic process-local claiming
completion / safe release / UNKNOWN
replay and concurrency controls

v0.6-B
execution-time authority revalidation
CANCELLED terminal state
post-claim revocation / task expiry / policy change checks
documented residual post-revalidation TOCTOU gap

v0.6
execution lifecycle and process-local atomic claims
execution-time authority revalidation
fail-closed UNKNOWN and CANCELLED states
stale-claim quarantine
explicit UNKNOWN reconciliation
documented recovery-evidence trust boundary
```

---

## 28. Relationship to Research Documents

```text
architecture.md
    -> how Ruhusa is structured

threat-model.md
    -> what Ruhusa trusts and claims

attack-benchmarks.md
    -> adversarial evidence

tests/
    -> executable verification
```

A security claim should not become a guarantee until its threat, assumptions, implementation, and test evidence align.

---

## 29. Core Principle

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
Execution lifecycle claims authority
      |
      v
Live authority is revalidated
      |
      v
Protected side effect
```

> **Agent intelligence may determine what to attempt. Trusted deterministic authorization determines what may execute.**
