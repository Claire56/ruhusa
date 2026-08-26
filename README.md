# Ruhusa

**Continuous authorization for multi-agent AI systems.**

Ruhusa means **permission** in Swahili.

> **LLMs decide what action to propose. Ruhusa determines whether they have permission to execute it.**

> **Authority should narrow as agents delegate—not expand.**

## Overview

Ruhusa is an open-source research framework for studying continuous, least-privilege authorization across AI agents, tools, and multi-agent workflows.

The framework separates agent reasoning from authorization:

```text
Agent / LLM
    |
    | proposes an action
    v
Ruhusa
    |
    | deterministic authorization
    v
ALLOW | DENY | REQUIRE_APPROVAL
    |
    v
Protected Tool / API / Resource
```

Ruhusa is not an agent framework, workflow engine, identity provider, LLM gateway, or production IAM replacement. Its purpose is to provide a small, inspectable authorization layer for studying how authority behaves as agent workflows delegate, replan, invoke tools, encounter revocation, and cross trust boundaries.

## Project Status

**Current package version:** `0.6.0`
**Current research milestone:** `v0.6` — execution lifecycle, execution-time authority, and recovery
**Milestone status:** validated release candidate
**Release status:** pre-1.0 research framework

v0.6 closes the execution-lifecycle research milestone while retaining explicit boundaries around distributed execution, downstream idempotency, recovery-evidence provenance, and exactly-once external side effects.

APIs and security guarantees may change before 1.0.

## Current Capabilities

Ruhusa currently includes research implementations for:

- deterministic default-deny authorization
- least-privilege, multi-hop delegation
- delegation-chain identity continuity
- task-bound authority
- cross-task replay protection
- action, resource, and argument constraints
- human-approval decisions
- continuous grant revocation
- fail-closed policy and security-store failures
- hash-chained authorization audit records
- trusted canonical grant issuance via `InMemoryGrantStore`
- canonical grant-content integrity checks
- invocation provenance via `InMemoryInvocationStore`
- operation-bound invocation records
- invocation expiry
- tool identity and implementation identity via `InMemoryToolRegistry`
- canonical invocation verification for delegated and direct requests
- fail-closed handling of missing canonical tool identity when tool verification is required
- execution lifecycle state via `InMemoryExecutionStore`
- atomic process-local execution claims and `ExecutionPermit`
- replay blocking after a claimed invocation is completed
- safe release when failure is known to occur before an external side effect
- fail-closed `UNKNOWN` state for uncertain external outcomes
- execution-time authorization revalidation before protected side effects
- terminal `CANCELLED` state when live authority becomes invalid before execution
- stale-claim quarantine from `CLAIMED` to fail-closed `UNKNOWN`
- explicit `UNKNOWN` reconciliation to `COMPLETED` or `AVAILABLE` through trusted recovery infrastructure
- process-local single-winner reconciliation semantics
- stale-permit protection across recovered execution attempts
- adversarial attack benchmarks

Not every configuration provides the same security guarantees. Self-asserted identity fields in weak mode remain intentionally benchmarked as forgeable.

## Research Method

Ruhusa uses an attack-first development process.

```text
Define attack
    |
    v
Run against baseline
    |
    +---- blocked ----> document existing invariant
    |
    +---- succeeds ---> record GAP
                         |
                         v
                    identify root cause
                         |
                         v
                    implement smallest
                    targeted control
                         |
                         v
                    rerun attack
```

A passing test can represent either a blocked attack or a successfully reproduced vulnerability. See `docs/attack-benchmarks.md` for the `GAP`, `BLOCKS`, and `CONTROL` conventions.

## Security Model

The central architectural distinction is between agent-controlled claims and trusted authorization state.

```text
UNTRUSTED / SELF-ASSERTED
--------------------------------
LLM reasoning
AuthorizationRequest fields
caller identity claims
tool identity claims
action/resource/arguments
presented delegation objects

TRUSTED / CANONICAL
--------------------------------
Ruhusa authorization core
StaticPolicyStore
InMemoryGrantStore
InMemoryRevocationStore
InMemoryInvocationStore
InMemoryToolRegistry
InMemoryExecutionStore
InMemoryAuditLog
trusted orchestration state
```

A recurring research finding is:

> **Security-relevant identity claims must be grounded in trusted provenance, not merely represented as matching strings inside an agent-controlled request.**

This principle emerged first with grant provenance in v0.4 and now extends to invocation and tool identity in v0.5.

## Weak and Strong Provenance Modes

### Weak mode

Without an invocation store, Ruhusa may evaluate self-asserted request fields such as:

```text
invoking_principal_id
tool_id
implementation_id
```

These checks can detect missing or obviously unregistered values, but a compromised executing agent can forge values that look legitimate.

Weak mode is therefore a compatibility and consistency mode, not a trusted provenance boundary.

### Strong mode

With `InMemoryInvocationStore`, a trusted orchestration layer creates a canonical `InvocationRecord` that binds:

```text
invoker
executor
task
action
resource
arguments digest
tool identity
implementation identity
recorded_at
expires_at
```

Canonical invocation verification applies to both delegated and direct/non-delegated requests.

For delegated requests, Ruhusa additionally verifies that the canonical invoking principal matches the grantor of the leaf delegation grant.

When a tool registry is configured, canonical tool identity must be present and trusted for the requested action.

## Authorization Flow

The current `Ruhusa.authorize()` flow is approximately:

```text
AuthorizationRequest
        |
        v
1. Task validity
        |
        v
2. Structural delegation validation
   - chain origin
   - identity continuity
   - task binding
   - temporal validity
   - scope attenuation
        |
        v
3. Canonical invocation verification
   - applies to direct and delegated requests
   - invoker
   - executor
   - task
   - action
   - resource
   - arguments digest
   - expiry
        |
        v
4. Tool identity verification
   - canonical runtime identity
   - fail closed if required identity is missing
   - registered implementation
   - action permitted by implementation
        |
        v
5. Canonical grant provenance
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
Audit decision
```

See `docs/architecture.md` for the detailed architecture.

## v0.6 Experimental State

The current benchmark contains **44 implemented experiments** across delegation, provenance, tool identity, execution lifecycle, execution-time authority, and recovery.

### v0.6-A — Execution Lifecycle

Experiments 18–27 preserve the v0.5 exact-replay baseline and add a separate execution lifecycle.

Key observed results:

```text
Exp 18  exact replay through authorize()                   GAP
Exp 19  second execution claim                            BLOCKS
Exp 20  concurrent process-local claim race               BLOCKS
Exp 21  replay after completion                           BLOCKS
Exp 22  known pre-side-effect release and retry           CONTROL
Exp 23  uncertain external outcome retry                  BLOCKS
Exp 24  stale/forged execution permit                     BLOCKS
Exp 25  expired execution authority                       BLOCKS
Exp 26  authorization DENY does not consume execution     CONTROL
Exp 27  execution-store failure                           BLOCKS
```

The research distinction is:

> **Operation-bound provenance is not execution uniqueness.**

`Ruhusa.authorize()` intentionally remains non-consuming so the v0.5 baseline stays reproducible. Side-effecting integrations opt into the execution lifecycle through `ExecutionController`.

### v0.6-B — Execution-Time Authority Validity

Experiments 28–35 test whether authority that was valid when execution was claimed is still valid immediately before an external side effect.

Observed results:

```text
Exp 28  revocation before execution claim                 BLOCKS
Exp 29  revocation after claim without revalidation       GAP
Exp 30  post-claim revocation with revalidation           BLOCKS
Exp 31  task expiry after claim                           BLOCKS
Exp 32  policy change after claim                         BLOCKS
Exp 33  stale/forged permit at revalidation               BLOCKS
Exp 34  execution-state failure during revalidation       BLOCKS
Exp 35  revocation after successful revalidation          GAP
```

Experiment 35 is intentionally preserved as a residual TOCTOU boundary. v0.6-B narrows the authorization-to-use window but does not make authorization state atomic with a remote side effect.

The research distinction is:

> **Authorization-time validity is not execution-time validity, and execution-time revalidation is not atomic authorization plus side effect.**

### v0.6-C — Fail-Closed Recovery for Uncertain Execution

Experiments 36–44 evaluate stale execution claims and explicit recovery from `UNKNOWN`.

Observed results:

```text
Exp 36  stale CLAIMED execution becomes UNKNOWN             BLOCKS unsafe retry
Exp 37  live claim cannot be recovered before threshold     BLOCKS claim stealing
Exp 38  confirmed side effect resolves UNKNOWN              COMPLETED / replay blocked
Exp 39  confirmed no side effect permits a fresh claim      CONTROL
Exp 40  reconciliation outside UNKNOWN                      BLOCKS
Exp 41  concurrent reconciliation                           BLOCKS / one winner
Exp 42  old permit after recovery                           BLOCKS
Exp 43  invalid stale-recovery window                       BLOCKS invalid configuration
Exp 44  empty reconciliation reason                         BLOCKS malformed recovery
```

v0.6-C establishes a fail-closed recovery lifecycle, but it does **not** authenticate the source of a reconciliation outcome. `reconcile_unknown()` is therefore a trusted-infrastructure API: an agent must not be allowed to self-assert `SIDE_EFFECT_CONFIRMED` or `SIDE_EFFECT_NOT_APPLIED`.

The research distinction is:

> **Execution-attempt uniqueness does not imply side-effect uniqueness, and safe recovery requires trustworthy knowledge of the external outcome.**

## Validation Baselines

Frozen v0.5.0 release baseline:

```text
ruff format: 27 files left unchanged
ruff check:  All checks passed
pytest:      91 passed
build:       dist/ruhusa-0.5.0.tar.gz
build:       dist/ruhusa-0.5.0-py3-none-any.whl
```

Validated v0.6-C development baseline before the release-version bump:

```text
ruff check:  All checks passed
pytest:      118 passed
build:       dist/ruhusa-0.5.0.tar.gz
build:       dist/ruhusa-0.5.0-py3-none-any.whl
```

Final v0.6.0 release validation is recorded after this release preparation script completes successfully.

## v0.6.0 Release Validation

```text
ruff check:  All checks passed\npytest:      118 passed\nbuild:       dist/ruhusa-0.6.0.tar.gz\nbuild:       dist/ruhusa-0.6.0-py3-none-any.whl
```

The v0.6 threat model is frozen at `docs/threat-model/v0.6.md`.

## Documentation

The repository separates architecture, security assumptions, and experimental evidence:

- [`docs/architecture.md`](docs/architecture.md) — how Ruhusa is structured
- [`docs/threat-model.md`](docs/threat-model.md) — current trust assumptions, threats, and security claims
- [`docs/attack-benchmarks.md`](docs/attack-benchmarks.md) — executable adversarial experiments and outcomes
- [`docs/threat-model/v0.4.md`](docs/threat-model/v0.4.md) — frozen v0.4 threat-model snapshot
- [`docs/threat-model/v0.5.md`](docs/threat-model/v0.5.md) — frozen v0.5 threat-model snapshot
- [`docs/threat-model/v0.6.md`](docs/threat-model/v0.6.md) — frozen v0.6 threat-model snapshot
- [`docs/research/v0.6-A-execution-lifecycle.md`](docs/research/v0.6-A-execution-lifecycle.md) — execution-lifecycle research note
- [`docs/research/v0.6-B-execution-time-authority.md`](docs/research/v0.6-B-execution-time-authority.md) — execution-time authority research note
- [`docs/research/v0.6-C-idempotency-recovery.md`](docs/research/v0.6-C-idempotency-recovery.md) — uncertain-execution recovery research note
- [`docs/architecture/v0.1.md`](docs/architecture/v0.1.md) — historical v0.1 architecture

## Requirements

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/)

## Development

Clone and install:

```bash
git clone https://github.com/Claire56/ruhusa.git
cd ruhusa
uv sync
```

Run the test suite:

```bash
uv run pytest
```

Run the attack benchmarks:

```bash
uv run pytest tests/test_replanning_attacks.py -v
uv run pytest tests/test_tool_identity_attacks.py -v
uv run pytest tests/test_execution_lifecycle_attacks.py -v
uv run pytest tests/test_execution_time_authority_attacks.py -v
uv run pytest tests/test_idempotency_recovery.py -v
```

Format and lint:

```bash
uv run ruff format .
uv run ruff check .
```

Build:

```bash
uv build
```

Before committing:

```bash
uv run ruff format .
uv run ruff check .
uv run pytest
uv build
```

## Core Usage

At its simplest:

```python
from ruhusa import Ruhusa

gate = Ruhusa(policy_store=policies)
decision = gate.authorize(request)

if decision.allowed:
    execute_tool()
```

Strong provenance requires a trusted orchestration layer to populate canonical runtime state rather than allowing executing agents to self-assert that state.

For side-effecting integrations using the v0.6 execution lifecycle:

```python
from ruhusa import ExecutionController

controller = ExecutionController(gate)

claim = controller.begin(request)
if claim.allowed and claim.permit is not None:
    live = controller.revalidate_before_execution(request, claim.permit)
    if live.allowed:
        # Execute the protected side effect here.
        controller.complete(claim.permit)
```

If the external outcome becomes uncertain after the request is sent, use `mark_unknown()` rather than automatically retrying. v0.6 does not claim atomic authorization plus external side effect or exactly-once downstream execution.

## Milestones

### v0.1 — Deterministic Authorization Core

Established default-deny authorization, scoped delegation, human-approval decisions, fail-closed policy evaluation, and hash-chained audit logging.

### v0.2 — Continuous Revocation

Added mid-workflow revocation, fail-closed revocation checks, and earlier emergency revocation semantics.

### v0.3 — Task-Bound Delegation

Bound grants to originating tasks and blocked cross-task replay and chain splicing.

### v0.4 — Replanning and Trusted Grant Provenance

Introduced adversarial replanning tests, discovered the fresh-grant-remint gap, and added canonical grant issuance and content-integrity verification.

### v0.5 — Invocation Provenance and Tool Identity

Added trusted invocation provenance, tool/implementation identity, operation binding, direct-request mediation, and fail-closed canonical tool identity verification.

The v0.5 milestone intentionally retains one documented limitation: exact same-operation invocation replay is not prevented by one-shot authorization consumption.

### v0.6 — Execution Lifecycle, Execution-Time Authority, and Recovery

v0.6-A adds execution claims, replay controls, completion/unknown/cancelled lifecycle state, and process-local concurrency protection.

v0.6-B adds execution-time revalidation so revocation, task expiry, and policy changes that occur after a claim can be observed immediately before use.

v0.6-C adds fail-closed stale-claim recovery and explicit reconciliation of `UNKNOWN` outcomes. A confirmed external effect becomes `COMPLETED`; confirmed non-execution may return the invocation to `AVAILABLE` for a newly authorized claim.

The remaining boundary is deliberate: Ruhusa does not make authorization, recovery state, and a remote side effect transactionally atomic. It also does not authenticate reconciliation evidence, provide durable distributed recovery, or guarantee downstream idempotency or exactly-once execution.

## Research Direction

The working research question is:

> **Under what workflow transformations does authorization cease to represent the authority originally delegated by a principal, and what runtime invariants are required to preserve that authority across delegation, revocation, replanning, concurrency, tool invocation, and information propagation?**

The research progression now extends beyond provenance into execution semantics:

```text
identity claim != provenance
provenance != complete mediation
operation binding != execution uniqueness
authorization-time validity != execution-time validity
execution-time revalidation != atomic authorization + side effect
```

Current and future research areas include:

- authorization/execution atomicity
- downstream idempotency and side-effect deduplication
- distributed concurrency and durable execution state
- authenticated/provenanced recovery evidence
- durable reconciliation of uncertain outcomes
- authority leases / epochs and TOCTOU
- authorization propagation across branch/merge workflows
- multi-agent collusion
- descendant revocation
- durable approval evidence
- cryptographic agent and tool identity
- information provenance and derived-data authority
- LangGraph, MCP, and A2A integrations
- external PDP and IAM integrations

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

See [`SECURITY.md`](SECURITY.md).

Ruhusa is a research framework and should not be treated as a production security boundary.

## License

Apache License 2.0.
