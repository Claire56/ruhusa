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

**Published package version:** `0.5.0`  
**Current milestone:** `v0.5` — invocation provenance and tool identity  
**Release status:** pre-1.0 research framework

APIs and security guarantees may change before 1.0.

## Current Development Capabilities

The current development branch includes research implementations for:

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
- grant-content integrity checks
- invocation provenance via `InMemoryInvocationStore`
- operation-bound invocation records
- invocation expiry
- tool identity and implementation identity via `InMemoryToolRegistry`
- weak and strong provenance modes
- adversarial attack benchmarks

Not every configuration provides the same security guarantees. In particular, self-asserted identity fields in weak mode are intentionally retained as compatibility behavior and are explicitly benchmarked as forgeable.

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

For **all** requests (delegated and direct), Ruhusa retrieves this canonical record and verifies executor, task, operation, and expiry. For delegated requests, the authenticated invoker must match the leaf grant grantor. When a tool registry is also configured, the canonical tool identity is checked against trusted registrations; a missing `tool_id` in the record is fail-closed.

The v0.5-C architectural fix extended the strong-mode guarantee from delegated requests to all requests.

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
3. Invocation provenance and tool identity (ALL requests when InvocationStore configured)
   - strong mode: canonical InvocationRecord (executor, task, operation, expiry, tool)
   - invoker==leaf-grantor check applies only when delegation chain is present
   - weak mode: self-asserted invoker consistency for delegated requests only
        |
        v
4. Weak-mode tool verification
   - only when ToolRegistry exists
   - and InvocationStore does not (strong mode handles tool identity in step 3)
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

See `docs/architecture.md` for the detailed architecture and current limitations.

## v0.5 Experimental State

The v0.5 benchmark contains **17 implemented experiments**. Experiment 16 is the one remaining confirmed `GAP`; Experiments 15 and 17 are `BLOCKS` after the v0.5-C architectural fix.

### Resolved — Experiment 15 (v0.5-C)

Before v0.5-C, a direct/non-delegated request with both `InvocationStore` and `ToolRegistry` configured could skip both the strong invocation/tool check (gated on `if request.delegation_chain:`) and the weak tool check (skipped when an invocation store exists). Policy decided alone — `ALLOW`.

The v0.5-C fix decouples the invocation-store check from the delegation-chain check. All requests now require a canonical `InvocationRecord` when an invocation store is configured. Direct requests without an `invocation_id` are denied immediately:

```text
non-delegated request
InvocationStore configured
ToolRegistry configured
no invocation_id
        |
        v
DENY (BLOCKS — v0.5-C)
```

### Confirmed Gap — Experiment 16

Operation binding blocks reuse of an invocation ID for a *different* action, resource, or arguments.

It does not currently provide one-shot invocation consumption.

The same valid `invocation_id` can be reused for the exact same operation:

```text
request #1 -> ALLOW
request #2 -> ALLOW
request #3 -> ALLOW
```

The benchmark establishes the current contract:

> Ruhusa does not currently enforce one-shot invocation semantics.

Duplicate-side-effect protection is an execution-layer responsibility. Whether to add `consume()`-style semantics is deferred to v0.6 research.

### Resolved — Experiment 17 (v0.5-C)

Before v0.5-C, strong tool verification ran only when `record.tool_id is not None`. A `None` `tool_id` in the invocation record silently skipped the registry check — policy decided alone.

The v0.5-C fix makes a missing `tool_id` fail-closed when a tool registry is configured:

```text
InvocationStore configured
ToolRegistry configured
InvocationRecord.tool_id = None
        |
        v
DENY (BLOCKS — v0.5-C)
```

This closes T16 from the threat model. The security contract is explicit: a configured registry requires tool identity in the canonical record.

## Documentation

The repository separates architecture, security assumptions, and experimental evidence:

- [`docs/architecture.md`](docs/architecture.md) — how Ruhusa is structured
- [`docs/threat-model.md`](docs/threat-model.md) — current trust assumptions, threats, and security claims
- [`docs/attack-benchmarks.md`](docs/attack-benchmarks.md) — executable adversarial experiments and outcomes
- [`docs/threat-model/v0.4.md`](docs/threat-model/v0.4.md) — frozen v0.4 threat-model snapshot
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

Run the example:

```bash
uv run python examples/refund_demo.py
```

Build the package:

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

When dependencies change, commit both:

```text
pyproject.toml
uv.lock
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

Production-like strong provenance requires a trusted orchestration layer to populate canonical security state rather than allowing executing agents to self-assert that state.

## Milestones

### v0.1 — Deterministic Authorization Core

Established default-deny authorization, scoped delegation, human-approval decisions, fail-closed policy evaluation, and hash-chained audit logging.

### v0.2 — Continuous Revocation

Added mid-workflow revocation, fail-closed revocation checks, and earlier emergency revocation semantics.

### v0.3 — Task-Bound Delegation

Bound grants to originating tasks and blocked cross-task replay and chain splicing.

### v0.4 — Replanning and Trusted Grant Provenance

Introduced adversarial replanning tests, discovered the fresh-grant remint gap, and added canonical grant issuance and content-integrity verification.

### v0.5 — Invocation Provenance and Tool Identity — in development

v0.5 studied and resolved:

- confused-deputy attacks
- forged caller identity
- tool substitution
- implementation spoofing
- operation-bound invocation records
- stale invocation replay
- non-delegated strong-mode tool enforcement (Experiment 15 — BLOCKS v0.5-C)
- missing canonical tool identity (Experiment 17 — BLOCKS v0.5-C)

v0.5 confirmed gap (deferred to v0.6):

- exact invocation replay semantics (Experiment 16 — GAP, one-shot semantics deferred)

## Research Direction

The working research question is:

> **Under what workflow transformations does authorization cease to represent the authority originally delegated by a principal, and what runtime invariants are required to preserve that authority across delegation, revocation, replanning, concurrency, tool invocation, and information propagation?**

Future benchmark areas include:

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

Ruhusa is currently a research framework and should not be treated as a production security boundary.

## License

Apache License 2.0.
