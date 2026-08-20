# Ruhusa Threat Model

**Version:** v0.4  
**Status:** Research framework — pre-1.0  
**Document status:** Canonical threat model  
**Last updated:** August 20, 2026

---

## 1. Purpose

Ruhusa is an open-source research framework for studying continuous, least-privilege authorization across AI agents, tools, and multi-agent workflows.

This threat model defines what the framework protects, what it explicitly does not protect, the attacker capabilities it is designed to resist, the trust assumptions on which its security claims depend, the authorization invariants it enforces, and the experimental evidence used to verify those claims.

Ruhusa is built around two core principles:

> LLMs and agents may propose actions, but deterministic authorization logic outside the model decides whether those actions may execute.

> Authority should narrow as agents delegate, not expand.

Ruhusa is not intended to determine whether an agent's reasoning is correct. It is intended to determine whether the authority exercised by an agent remains valid, sufficiently constrained, and traceable as a workflow evolves.

The broader research focus is authorization correctness across task execution, multi-hop delegation, revocation, replay, replanning, trusted grant provenance, tool invocation, and eventually information propagation.

---

## 2. Security Goals

Ruhusa aims to preserve authorization correctness even when an AI agent is unreliable, compromised, manipulated by untrusted input, or actively attempting to obtain more authority than was delegated to it.

The framework aims to ensure that:

1. Protected actions are evaluated by a deterministic authorization boundary before execution.
2. Authorization fails closed when required security state cannot be safely evaluated.
3. Delegated authority cannot exceed the authority from which it was derived.
4. Delegation chains preserve identity continuity.
5. Delegated authority is bound to the task for which it was issued.
6. Revoked authority cannot authorize subsequent protected actions.
7. Expired or not-yet-active authority cannot be exercised.
8. Protected actions remain constrained by action, resource, and argument-level scope.
9. Presented delegation grants can be compared with canonical grants issued through a trusted boundary.
10. A known grant identity cannot be reused with modified authority.
11. Authorization decisions are recorded for later audit and reconstruction.
12. Authorization logic remains outside LLM-controlled prompt content.

Ruhusa does not assume that the agent itself will voluntarily obey these rules.

---

## 3. System Boundary

Ruhusa sits between an agent's proposed action and the protected operation.

```text
User / System
      |
      v
AI Agent or Multi-Agent Workflow
      |
      | proposes protected action
      v
+-------------------------------+
|            Ruhusa             |
|                               |
| task validation               |
| delegation validation         |
| trusted grant verification    |
| revocation check              |
| scope enforcement             |
| policy decision               |
| audit recording               |
+---------------+---------------+
                |
        +-------+-------+
        |               |
      ALLOW           DENY
        |
        +------ REQUIRE_APPROVAL
                |
                v
         Human / external
         approval process
```

Ruhusa treats the agent and agent-controlled context as potentially untrusted.

The authorization boundary is the call to `Ruhusa.authorize()`. The authorization layer is expected to operate outside the LLM's reasoning loop and before a protected tool, API, or resource is invoked.

---

## 4. Protected Assets

The primary assets protected by Ruhusa are not model outputs themselves. They are the authorities and resources that agent outputs may cause to be exercised.

### 4.1 Protected Action Execution

Only actions authorized by current, valid policy and delegation state should execute.

Examples include:

- issuing a refund
- modifying an account
- granting access
- deleting or changing data
- sending messages
- writing files
- invoking privileged APIs
- calling administrative tools
- triggering external workflows

### 4.2 Resource Access

Resources may include customer records, accounts, files, services, databases, applications, or other objects addressed by an authorization request.

Ruhusa constrains resource access using delegated resource scope.

### 4.3 Action Arguments

Arguments can materially change the privilege of an otherwise allowed operation.

For example:

```text
issue_refund(amount=50)
```

and:

```text
issue_refund(amount=5000)
```

are the same nominal action but may require very different authority.

### 4.4 Delegated Authority

Delegation grants represent authority transferred from one principal to another. Ruhusa protects against unauthorized expansion, replay, mutation, and reuse of this authority.

### 4.5 Delegation Provenance

When trusted issuance enforcement is configured, only grants that exactly match canonical grants registered through the trusted issuance boundary are accepted.

### 4.6 Task Authority

Task identity binds delegated authority to the workflow for which that authority was issued.

### 4.7 Revocation State

Revocation state determines whether authority that was previously valid may still be exercised.

### 4.8 Canonical Grant State

`InMemoryGrantStore` represents the canonical record of delegation grants issued through the trusted boundary in the current v0.4 research implementation.

### 4.9 Audit Records

Authorization decisions are recorded in the hash-chained audit log to support security debugging, attack analysis, and later reconstruction.

---

## 5. Actors and Principals

### 5.1 Human or System Task Initiator

The task initiator originates the workflow and is the expected root of the first delegation chain.

### 5.2 AI Agent

An AI agent proposes actions and may receive delegated authority. An agent is not inherently trusted simply because it is part of the application.

### 5.3 Supervisor Agent

A supervisor may delegate narrower authority to a sub-agent. Its role does not permit it to exceed the authority it received.

### 5.4 Sub-Agent

A sub-agent may act only within the effective scope of the full delegation chain.

### 5.5 Policy Administrator

A trusted operator or system component defines deterministic authorization policies.

### 5.6 Revocation Authority

A trusted component may revoke previously issued grants.

### 5.7 Grant Issuer

A trusted issuance boundary registers canonical delegation grants. A grant presented by an agent is not considered trustworthy merely because its fields are structurally valid.

### 5.8 Attacker

An attacker may be:

- a malicious agent
- a compromised agent
- an agent manipulated through prompt injection
- an untrusted user attempting to induce privileged behavior
- a compromised workflow component
- a malicious sub-agent
- an actor replaying, modifying, or fabricating previously valid-looking authority

---

## 6. Trust Model

### 6.1 Trusted Components

The current model treats the following as trusted when correctly configured:

- Ruhusa authorization core
- `StaticPolicyStore`
- `InMemoryRevocationStore`
- `InMemoryGrantStore`
- `InMemoryAuditLog`
- delegation-chain validation logic
- task metadata supplied through a trusted execution path
- principal identity supplied through a trusted execution path
- policy rules supplied through a trusted administration path
- grant registration performed through the trusted issuance path

### 6.2 Untrusted or Potentially Hostile Components

The following must not be trusted to determine authorization:

- LLM-generated reasoning
- prompts
- retrieved documents
- tool descriptions supplied by untrusted sources
- agent-constructed `AuthorizationRequest` objects
- delegation chains presented by agents
- `DelegationGrant` objects presented at runtime
- model-generated delegation claims
- agent assertions that an action is authorized
- arbitrary `grant_id` values supplied by an agent
- agent-controlled arguments and resource strings
- agent-generated task identifiers
- model-generated explanations of policy

A key assumption is that trusted identity, task, canonical grant, revocation, and policy state cannot be rewritten by the LLM through natural-language prompt content.

The attacker is assumed not to have direct write access to the trusted stores or arbitrary code execution inside the Ruhusa authorization process.

---

## 7. Attacker Capabilities

The threat model assumes an attacker may be able to:

1. Construct arbitrary `AuthorizationRequest` objects.
2. Cause an agent to propose an unauthorized action.
3. Manipulate action arguments.
4. Select a different resource than the one intended.
5. Present forged or altered delegation chains.
6. Present `DelegationGrant` objects with attacker-controlled fields.
7. Trigger repeated attempts after a denial.
8. Cause an agent to replan after authorization failure.
9. Delegate to another agent.
10. Construct alternate delegation paths.
11. Attempt to widen authority in a child grant.
12. Replay grants that were valid in earlier tasks or workflow steps.
13. Reuse expired or revoked authority.
14. Omit an ancestor from a delegation chain.
15. Present a fresh grant identifier after revocation.
16. Present a known legitimate `grant_id` with modified contents.
17. Observe denial reasons and adapt subsequent attempts.
18. Exploit unavailable authorization dependencies in an attempt to fail open.
19. Attempt to exploit inconsistencies among agents participating in the same workflow.

The attacker is not assumed to be able to:

- modify the policy store directly
- modify the revocation store directly
- modify the canonical grant store directly
- forge a grant that passes canonical equality verification without matching the registered copy
- modify Python source at runtime
- compromise the Ruhusa host process itself

Those assumptions define the current trusted computing boundary and are revisited under Known Limitations and Out of Scope.

---

## 8. Authorization Context

A Ruhusa authorization decision is conceptually derived from:

```text
Principal
    +
Task Context
    +
Delegation Chain
    +
Canonical Grant State
    +
Current Revocation State
    +
Action
    +
Resource
    +
Arguments
    +
Policy
    |
    v
ALLOW | DENY | REQUIRE_APPROVAL
```

Authorization is evaluated at the protected-action boundary rather than being assumed valid for the entire lifetime of a workflow.

This allows the outcome to change as authorization state changes.

For example:

```text
12:00  grant valid
12:05  protected action -> ALLOW
12:10  grant revoked
12:11  protected action -> DENY
```

---

## 9. Authorization Decision Flow

The current authorization path evaluates security checks before returning the policy decision.

```text
Request arrives at Ruhusa.authorize()
             |
             v
   Task expired?  --YES-->  DENY
             |
             v
   Delegation chain valid?
   |-- origin is task initiator?
   |-- identity continuous?
   |-- each grant bound to current task?
   |-- time window valid?
   |-- scope non-increasing at each hop?
             |
   chain invalid ----------> DENY
             |
             v
   Grant store configured?
             |
             +-- YES: for each grant
             |      |
             |      +-- grant_id unknown? ------> DENY
             |      |
             |      +-- canonical contents differ? -> DENY
             |      |
             |      +-- backend error? ----------> DENY
             |
             v
   Grant revoked? ----------> DENY
   Revocation check fails? -> DENY
             |
             v
   Action within effective scope? ----NO----> DENY
   Resource within effective scope? ---NO----> DENY
   Arguments within effective scope? --NO----> DENY
             |
             v
   Policy evaluation
             |
             +-- backend/evaluation error? ---> DENY
             |
             +-- no matching policy? --------> DENY
             |
             v
   Policy decision
   ALLOW | DENY | REQUIRE_APPROVAL
             |
             v
        Record audit event
             |
             v
   Return AuthorizationDecision
```

When a grant store is configured, the presented grant must exactly match the canonical registered grant before authorization may continue. The framework verifies canonical equality; it does not rely on the agent's claim that the grant is legitimate.

---

## 10. Security Invariants

### INV-01: Default Deny

If no policy authorizes an action, the result is `DENY`.

### INV-02: Fail Closed

If policy evaluation, revocation verification, or trusted issuance verification cannot be safely completed, authorization must not fail open.

### INV-03: Delegation Origin

The first delegation grant must originate from the task initiator.

### INV-04: Identity Continuity

For a multi-hop chain, each downstream grant must be issued by the grantee of the preceding grant.

```text
User -> Agent A -> Agent B
```

A disconnected chain must be denied.

### INV-05: No Privilege Amplification

A child delegation may be equal to or narrower than its parent's authority, but must never widen it.

```text
Parent: refund <= $500
Child:  refund <= $300     VALID

Parent: refund <= $500
Child:  refund <= $1000    DENY
```

### INV-06: Task Binding

Every grant in a delegation chain must be bound to the current task.

A grant issued for Task A must not authorize Task B.

### INV-07: Temporal Validity

A grant must not be usable:

- before `issued_at`
- after `expires_at`
- when its validity window is internally invalid

### INV-08: Continuous Revocation

Revocation is checked again before a protected delegated action. Authority valid earlier in a workflow may therefore become invalid later.

### INV-09: Revocation Moves Toward Earlier Enforcement

A scheduled revocation may be superseded by an earlier emergency revocation. A later revocation must not delay an already effective or earlier scheduled revocation.

### INV-10: Scoped Actions

The requested action must be within the effective delegated action scope.

### INV-11: Scoped Resources

The requested resource must be within the effective delegated resource scope.

### INV-12: Scoped Arguments

Security-relevant action arguments must remain within effective delegated constraints.

### INV-13: Trusted Grant Provenance

When trusted grant issuance enforcement is configured, a delegation grant must have been registered through the trusted grant boundary.

A structurally valid but unknown grant is not sufficient evidence of authority.

### INV-14: Canonical Grant Integrity

A presented grant must exactly match the canonical issued grant associated with its grant identity.

A known `grant_id` with altered scope, task, grantor, grantee, timestamps, or other contents must be rejected.

### INV-15: Grant Identity Immutability

A canonical grant identity must not be silently overwritten with different authority.

### INV-16: Auditability

Authorization decisions must be recorded so that security-relevant workflow activity can later be reconstructed.

---

## 11. Threats and Current Mitigations

| ID | Threat | Example | Current Mitigation |
|---|---|---|---|
| T01 | Unauthorized action | Agent invokes operation outside its authority | Default deny + deterministic policy |
| T02 | Resource escape | Valid action used against unauthorized resource | Resource scope validation |
| T03 | Argument escalation | Refund amount exceeds delegated limit | Argument constraints |
| T04 | Delegation amplification | Child receives more authority than parent | Scope attenuation |
| T05 | Broken delegation chain | Unrelated grants presented as one chain | Identity continuity validation |
| T06 | Cross-task replay | Task A grant reused in Task B | Required task binding |
| T07 | Expired authority replay | Agent reuses expired grant | Temporal validation |
| T08 | Future-dated authority | Agent uses grant before activation | Temporal validation |
| T09 | Revoked authority reuse | Agent continues after revocation | Per-action revocation check |
| T10 | Revoked-parent omission | Agent removes revoked ancestor from presented chain | Task-initiator origin + chain continuity |
| T11 | Alternate-path scope widening | Agent replans through another delegation path | Effective-scope attenuation |
| T12 | Fresh-grant remint | Revoked authority recreated using new grant ID | Trusted canonical grant store |
| T13 | Grant-content tampering | Known grant ID reused with widened contents | Exact canonical grant comparison |
| T14 | Authorization backend failure | Policy/revocation/grant verification unavailable | Fail-closed behavior |
| T15 | Human approval bypass | Agent attempts action requiring approval | `REQUIRE_APPROVAL`; durable enforcement remains external |
| T16 | Tool substitution / confused deputy | Authorized intent redirected to different tool | Not fully addressed in v0.4 |
| T17 | Information-flow escalation | Allowed data combined into unauthorized derived information | Not addressed in v0.4 |
| T18 | Concurrent authorization race | Authority changes between check and side effect | Not fully addressed in v0.4 |

The presence of T16–T18 is deliberate. They are documented threats, not claimed protections.

---

## 12. Delegation Assumptions

Ruhusa's delegation model rests on the following assumptions.

### Assumption 1: Task Initiators Are Trusted Principals

`task.initiated_by` identifies the human or trusted system that originated the task. Ruhusa uses this as the required root of the delegation chain.

### Assumption 2: Scope Can Only Narrow

Each delegation hop may grant a subset of the authority it received; it cannot grant a superset.

### Assumption 3: Identity Must Be Continuous

The grantee of one grant must be the grantor of the next grant.

### Assumption 4: Grants Are Task-Bound

A grant carries the `task_id` of the task for which it was issued and cannot be replayed under another task context.

### Assumption 5: Registered Grant Contents Are Canonical

When a grant store is configured, the presented grant must exactly match the canonical registered grant before authorization continues.

---

## 13. Revocation Semantics

Ruhusa supports mid-workflow revocation through `InMemoryRevocationStore`.

Key properties:

- **Continuous re-evaluation:** Revocation is checked at every protected delegated action.
- **Earlier emergency revocation wins:** An earlier revocation may supersede a later scheduled revocation.
- **Grant-scoped records:** Revocation records target individual `grant_id` values.
- **Fail closed:** If revocation state cannot be evaluated, authorization is denied.

### Descendant Revocation Limitation

Ruhusa does not currently maintain an explicit parent-to-child revocation graph or automatically mark descendant grants revoked when a parent is revoked.

However, if an authorization request presents a chain containing a revoked ancestor, the request is denied because every presented grant is checked.

This distinction matters:

```text
Parent revoked
     |
     +-- request includes parent -> DENY
     |
     +-- child grant is not automatically written
         into revocation store as independently revoked
```

---

## 14. Task Binding and Replay Protection

Each `DelegationGrant` carries a `task_id` that must equal the `task_id` of the current `TaskContext`.

This enforces two core protections.

### Cross-Task Replay Prevention

A grant issued for Task A cannot authorize an action under Task B.

### Multi-Hop Task Consistency

Every grant in the delegation chain must belong to the current task. A chain that splices grants from different tasks is rejected even if the grants would otherwise be structurally valid.

---

## 15. Trusted Grant Issuance

`InMemoryGrantStore` acts as the current v0.4 trusted issuance registry when configured.

### 15.1 Provenance

A structurally valid delegation grant is not, by itself, proof that authority was legitimately issued.

The key distinction is:

```text
Is this grant structurally valid?
```

versus:

```text
Was this grant actually issued through a trusted authority boundary?
```

Ruhusa v0.4 introduced canonical grant registration to distinguish these questions.

### 15.2 Canonical Equality

The presented grant must exactly equal its canonical registered representation.

A known `grant_id` with modified scope, task, grantor, grantee, timestamps, or other fields is rejected.

### 15.3 Immutable Grant Identity

Once a `grant_id` is registered, attempting to register another grant with the same ID is rejected rather than silently overwriting the canonical authority.

### 15.4 Configuration Dependence

Trusted issuance enforcement is currently configuration-dependent.

When no grant store is configured, Ruhusa retains compatibility behavior in which structurally valid delegation chains may be evaluated without canonical grant provenance verification.

A future hardening milestone should consider making trusted issuance the secure default.

---

## 16. v0.4 Attack-Driven Finding

v0.4 introduced an attack-first development process.

The v0.3 baseline was tested against replanning and delegation-bypass scenarios.

Existing controls already blocked:

- delegation-based scope widening
- cross-task replay
- invalid delegation-chain reconstruction
- reuse of revoked authority when the revoked ancestor remained in the presented chain
- alternate delegation paths that attempted to expand effective authority

The attack suite also exposed a real gap.

### Fresh-Grant Remint Attack

A previously valid grant could be revoked, but an attacker could construct another `DelegationGrant` using a fresh `grant_id` and otherwise valid-looking authority.

```text
Valid grant
    |
    v
Revoked
    |
    v
Attacker constructs fresh grant ID
with equivalent authority
    |
    v
Structural checks succeed
but provenance is unknown
```

### Root Cause

Grant validity and grant provenance were treated as the same question.

Structural validation could determine whether a grant's fields were internally acceptable, but could not establish whether that authority had actually been issued.

### Mitigation

Ruhusa introduced `InMemoryGrantStore` as a canonical issuance registry.

```text
Presented Grant
      |
      v
Known canonical grant?
   |            |
  NO           YES
   |            |
 DENY       Exact match?
              |     |
             NO    YES
              |     |
            DENY   continue
```

### Follow-On Attack: Known-ID Content Tampering

An attacker could also present a legitimate `grant_id` while changing the grant's scope or other fields.

An ID-only lookup would be insufficient.

Canonical equality verification closes this variant by requiring the presented grant to match the registered grant exactly.

---

## 17. Attack → Mitigation → Verification Mapping

Each implemented v0.4 security claim is tied to an executable test.

| # | Attack | Violated Invariant | Mitigation | Verification Test |
|---|---|---|---|---|
| 1 | Denied agent delegates to a sub-agent rooted at itself | Chain must originate from task initiator | Chain-origin validation | `test_denied_agent_cannot_delegate_to_bypass_denial` |
| 2 | Child grant widens scope beyond parent | Authority cannot expand | Per-hop scope attenuation | `test_child_grant_cannot_widen_scope` |
| 3 | Revoked authority reused via fabricated fresh `grant_id` | Grant provenance must be established | Trusted canonical grant registry | `test_revoked_grant_reuse_via_fresh_chain_is_blocked_by_grant_store` |
| 4 | Denied grant replayed against another task | Grant must remain task-bound | Task-binding validation | `test_cross_task_replay_after_denial` |
| 5 | Alternate delegation path widens effective authority | Authority cannot expand through indirection | Scope attenuation at each hop | `test_alternate_delegation_path_does_not_widen_effective_authority` |
| 6 | Registered `grant_id` presented with modified scope | Canonical grant contents are immutable | Full `is_registered()` equality check | `test_registered_id_with_tampered_scope_is_denied` |
| 7 | Grant-store backend becomes unavailable | Authorization must fail closed | Exception handling around issuance verification | `test_grant_store_failure_is_fail_closed` |

This table provides the traceability chain:

```text
Security Claim
      |
      v
Threat / Attack
      |
      v
Invariant
      |
      v
Implementation Control
      |
      v
Executable Test
```

---

## 18. Fail-Closed Behavior

Fail-closed behavior is a core design requirement.

The authorization layer prefers denial over execution when required security state is unavailable or cannot be trusted.

| Check | Failure Mode | Response |
|---|---|---|
| Policy evaluation | Exception from policy store | `DENY` — `"policy evaluation failed; default deny"` |
| Revocation check | Exception from revocation store | `DENY` — `"revocation status unavailable; default deny"` |
| Grant issuance check | Exception from grant store | `DENY` — `"grant issuance status unavailable; default deny"` |
| Task validity | Expired task context | `DENY` — `"task expired"` |

This behavior intentionally favors authorization integrity over availability.

---

## 19. Human Approval

Ruhusa supports three high-level decision outcomes:

```text
ALLOW
DENY
REQUIRE_APPROVAL
```

`REQUIRE_APPROVAL` allows policy to distinguish among:

- actions safe for autonomous execution
- actions that are forbidden
- actions that may proceed only after external human approval

At the current framework stage, Ruhusa models the authorization decision and associated obligations.

A production-grade durable approval workflow, authenticated approver identity, approval TTL, separation-of-duties enforcement, and replay-resistant approval evidence are not yet part of the core implementation.

---

## 20. Audit Model

Ruhusa records authorization decisions in a hash-chained audit log.

The audit mechanism is intended to support:

- correlation of authorization events
- security debugging
- reconstruction of agent actions
- analysis of attack experiments
- comparison between intended and observed authorization behavior

The current audit mechanism must not be described as fully tamper-proof.

It is hash-chained, but it is not yet independently signed, externally checkpointed, or anchored in a separate trusted system.

The threat model assumes the attacker does not have direct control over the trusted audit store or Ruhusa host process.

Future work may introduce:

- HMAC or digital signatures
- append-only external storage
- external checkpoints
- independent audit sinks
- distributed trace correlation

---

## 21. Known Limitations

### 21.1 In-Memory Security State

The current research implementation uses in-memory policy, revocation, grant, and audit state.

These implementations are appropriate for tests and controlled experiments but do not provide production guarantees for durability, replication, consistency, or availability.

### 21.2 Trusted Grant Enforcement Is Configuration-Dependent

`grant_store=None` remains a supported configuration.

When the grant store is not configured, canonical provenance verification is not enforced.

### 21.3 No Cryptographic Grant Authenticity

Canonical registration establishes trusted provenance within the framework boundary, but grants are not yet cryptographically signed capabilities.

### 21.4 No Cryptographic Agent Identity

Principal identity is currently represented within application state. Ruhusa does not yet provide cryptographic proof that the actor presenting a request is the principal it claims to be.

### 21.5 Revocation Does Not Automatically Cascade

Revocation records are grant-scoped. Ruhusa does not yet maintain an explicit descendant revocation graph.

A presented chain containing a revoked ancestor is denied, but descendants are not independently marked revoked solely because their parent was revoked.

### 21.6 Tool Identity Is Not Yet Bound

Ruhusa currently reasons primarily about:

```text
principal
task
delegation
action
resource
arguments
policy
```

It does not yet distinguish:

```text
authorized operation
```

from:

```text
authorized operation through this specific trusted tool
```

This is required to address tool-substitution and confused-deputy attacks.

### 21.7 Check-to-Use Race Conditions

Ruhusa does not yet claim atomicity between authorization and external side-effect execution.

Authority could theoretically change after authorization but before an external system performs the action.

### 21.8 Information-Flow Authorization

Ruhusa does not yet track how information read by one agent is transformed, combined, derived, or propagated to another agent or eventual recipient.

### 21.9 Human Approval Enforcement Is External

`REQUIRE_APPROVAL` is a decision state. Ruhusa does not yet provide a complete durable approval workflow.

### 21.10 Resource Semantics Are Application-Defined

Resource scope is currently represented through framework-level resource matching. Ownership, tenancy, cross-user access, and object-specific semantics must be encoded by policy or future integrations.

### 21.11 Model Behavior Is Not Contained by Authorization Alone

Ruhusa does not itself prevent:

- hallucination
- prompt injection
- jailbreaks
- harmful natural-language responses
- model extraction
- denial-of-service
- privacy leakage in unmediated outputs
- sandbox escape

Ruhusa is intended to prevent unauthorized protected actions when those actions pass through its authorization boundary.

---

## 22. Out of Scope for v0.4

The following are explicitly outside Ruhusa v0.4 guarantees:

- compromise of the Ruhusa host process
- modification of Python source at runtime
- Python interpreter vulnerabilities
- network-layer attacks between agents and authorization infrastructure
- side-channel attacks
- general LLM alignment
- model training security
- jailbreak prevention
- content moderation
- malware detection
- infrastructure security
- credential storage
- full enterprise IAM replacement
- OAuth/OIDC protocol implementation
- cryptographic workload identity
- distributed consensus
- production-grade high availability
- comprehensive information-flow control
- tool identity attestation
- social engineering of trusted human principals

Some of these may become integration points or future research areas, but they are not current framework guarantees.

---

## 23. Security Testing Strategy

Ruhusa uses two complementary classes of tests.

### 23.1 Invariant Tests

Invariant tests verify individual authorization properties directly.

Examples include:

- default deny
- scope attenuation
- task binding
- temporal validity
- revocation
- fail-closed backend failures
- canonical grant matching

### 23.2 Adversarial Workflow Tests

Adversarial tests model attacker behavior across multiple attempts or workflow transformations.

Examples include:

- retry after denial
- delegation after denial
- replanning through another agent
- widening child authority
- replaying authority across tasks
- dropping a revoked or invalid ancestor
- reminting authority under a fresh grant identity
- mutating canonical grant contents
- using alternate delegation paths

The intended research workflow is:

```text
Define Attack
     |
     v
Run Against Baseline
     |
     v
Observe Result
     |
     +---- blocked ----> document existing invariant
     |
     +---- succeeds ---> identify violated invariant
                           |
                           v
                      implement smallest
                      targeted control
                           |
                           v
                      rerun benchmark
```

This methodology keeps Ruhusa development tied to demonstrated authorization failures rather than feature accumulation.

---

## 24. Current Validation Baseline

At completion of the v0.4 milestone, the validation baseline was:

```text
Ruff formatting: passed
Ruff linting:    passed
Tests:           29 passed
Package build:   passed
```

The test count is a point-in-time engineering metric, not a security guarantee.

Security claims must remain tied to the threats, invariants, and experiments represented by those tests.

---

## 25. Research Progression

```text
v0.1  Deterministic authorization core
      Default deny
      Policy evaluation
      Scoped delegation
      Human approval state
      Hash-chained audit log
      Fail-closed policy checks

v0.2  Continuous revocation
      Mid-workflow grant revocation
      Fail-closed revocation checks
      Earlier emergency revocation supersedes later scheduled revocation

v0.3  Task-bound authority and replay protection
      DelegationGrant.task_id
      Multi-hop task consistency
      Cross-task replay rejection

v0.4  Replanning attacks and trusted grant provenance
      Adversarial workflow tests
      Fresh-grant remint bypass discovered
      Canonical grant registry introduced
      Grant-content tampering blocked
      Fail-closed grant issuance checks

v0.5  Planned: tool identity and substitution
      Confused-deputy attacks
      Tool-identity binding
      Tool substitution
      Dynamic tool registry behavior
```

---

## 26. Experimental Security Result: v0.4

The v0.4 development cycle produced Ruhusa's first explicit attack-driven security result.

### Observation

Revocation in v0.3 was grant-scoped.

An adversary could respond to revocation by fabricating a fresh `DelegationGrant` with a new `grant_id` but otherwise plausible authority.

### Root Cause

Grant provenance had not been established.

Ruhusa could answer:

```text
Is this grant structurally valid?
```

but could not answer:

```text
Was this authority actually issued?
```

### Control

`InMemoryGrantStore` was introduced as the canonical trusted issuance registry.

A grant is accepted under trusted issuance enforcement only when:

1. its grant identity is registered, and
2. its complete presented contents match the canonical registered grant.

### Follow-On Variant

A known `grant_id` with modified scope was tested and rejected through canonical equality verification.

### Verification

The v0.4 suite verifies both the fresh-grant and modified-content variants while preserving legitimate re-issuance when a new grant is intentionally registered through the trusted path.

The resulting development sequence was:

```text
Baseline attack suite
        |
        v
Gap reproduced
        |
        v
Root cause identified
        |
        v
Smallest targeted control implemented
        |
        v
Attack benchmark rerun
        |
        v
Control verified
```

This is the intended development method for future Ruhusa milestones.

---

## 27. Future Threat-Model Extensions

Future versions are expected to expand this threat model in several directions.

### 27.1 Tool Identity and Tool Substitution

A future invariant is likely to be:

> Authorization for an operation through Tool A must not implicitly authorize an equivalent operation through Tool B.

### 27.2 Confused-Deputy Attacks

Ruhusa should evaluate whether a less-privileged principal can induce a more-privileged agent or tool to exercise authority on its behalf.

### 27.3 Replanning State

Future experiments should distinguish retries that preserve the same effective authorization intent from legitimate new workflows.

### 27.4 Authorization Propagation

Ruhusa should evaluate whether authority remains correct when workflows branch, merge, retry, recover, and delegate.

### 27.5 Information Provenance

Future work may track how information from separately authorized sources is combined, transformed, or released.

### 27.6 Concurrency and TOCTOU

Future experiments should examine policy and revocation changes that occur between authorization and side-effect execution.

### 27.7 Durable Authorization State

Research backends may replace in-memory stores to measure revocation propagation, consistency, latency, and failure behavior.

### 27.8 Framework and Standards Integrations

Potential integrations include:

- LangGraph
- Model Context Protocol (MCP)
- Agent2Agent (A2A)
- OAuth/OIDC-based identity and delegation
- OpenID AuthZEN-style authorization interfaces
- OPA/Rego or comparable policy engines
- OpenTelemetry-based tracing

---

## 28. Research Position

Ruhusa should not claim novelty merely for providing:

- least-privilege authorization
- task-bound grants
- revocation
- delegation attenuation
- deterministic policy enforcement

These are foundational controls.

The broader research question is:

> Under what workflow transformations does authorization cease to represent the authority originally delegated by a principal, and what runtime invariants are required to preserve that authority across delegation, revocation, replanning, concurrency, tool invocation, and information propagation?

Ruhusa is intended to provide an experimental framework in which those questions can be tested systematically.

The long-term objective is not only to answer:

> Is this individual tool call allowed?

but also:

> Has the authority represented by this action remained valid throughout the workflow transformations that produced it?

That distinction is central to Ruhusa's research direction.

---

## 29. Threat Model Maintenance

This document must evolve with the framework.

Each future security milestone should update:

1. attacker capabilities
2. newly identified threats
3. affected security invariants
4. implemented mitigations
5. executable verification tests or experiments
6. known limitations
7. out-of-scope assumptions
8. experimental results

The project should maintain the following rule:

> A security control should not be documented as a guarantee until it is both implemented and represented by an appropriate test or experiment.

This keeps the code, security claims, documentation, and research evidence aligned.
