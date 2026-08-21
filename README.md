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

**Current package version:** `0.5.0`  
**Current research milestone:** `v0.5` — invocation provenance and tool identity  
**Release status:** pre-1.0 research framework

APIs and security guarantees may change before 1.0.

## Current Capabilities

Ruhusa v0.5.0 includes research implementations for:

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

## v0.5 Experimental State

The current tool/invocation benchmark contains **17 implemented experiments**.

### Experiment 15 — Resolved

Experiment 15 originally demonstrated a complete-mediation gap in which a direct/non-delegated request could bypass strong tool verification.

v0.5-C moved canonical invocation verification outside the delegated-only path.

**Current result:**

```text
BLOCKS — DENY
```

### Experiment 16 — Known v0.5 Limitation

Experiment 16 tests exact reuse of a valid invocation ID for the exact same operation.

Operation binding prevents a valid invocation ID from being reused for a different action, resource, or argument set, but Ruhusa v0.5.0 does not provide one-shot invocation consumption.

**Current result:**

```text
GAP — repeated ALLOW
```

Ruhusa v0.5.0 therefore does **not** claim exactly-once execution semantics. Duplicate-side-effect prevention remains an execution-layer/idempotency concern unless a future version introduces authorization-consumption semantics.

### Experiment 17 — Resolved

Experiment 17 tests a canonical `InvocationRecord` whose tool identity is missing while `ToolRegistry` is configured.

v0.5-C now fails closed when required canonical tool identity is absent.

**Current result:**

```text
BLOCKS — DENY
```

## Validation Baseline

The v0.5.0 release candidate was validated with:

```text
ruff format: 27 files left unchanged
ruff check:  All checks passed
pytest:      91 passed
build:       dist/ruhusa-0.5.0.tar.gz
build:       dist/ruhusa-0.5.0-py3-none-any.whl
```

## Documentation

The repository separates architecture, security assumptions, and experimental evidence:

- [`docs/architecture.md`](docs/architecture.md) — how Ruhusa is structured
- [`docs/threat-model.md`](docs/threat-model.md) — current trust assumptions, threats, and security claims
- [`docs/attack-benchmarks.md`](docs/attack-benchmarks.md) — executable adversarial experiments and outcomes
- [`docs/threat-model/v0.4.md`](docs/threat-model/v0.4.md) — frozen v0.4 threat-model snapshot
- [`docs/threat-model/v0.5.md`](docs/threat-model/v0.5.md) — frozen v0.5 threat-model snapshot after release
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

## Research Direction

The working research question is:

> **Under what workflow transformations does authorization cease to represent the authority originally delegated by a principal, and what runtime invariants are required to preserve that authority across delegation, revocation, replanning, concurrency, tool invocation, and information propagation?**

The v0.5 experiments extend that question beyond provenance:

```text
identity claim != provenance
provenance != complete mediation
operation binding != execution uniqueness
```

Future research areas include:

- authorization/execution atomicity
- idempotency and one-shot authority
- concurrency and TOCTOU
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
