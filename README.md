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

**Published package version:** `0.3.0`  
**Current development milestone:** `v0.5` — invocation provenance and tool identity  
**Release status:** pre-1.0 research framework

The package version intentionally remains `0.3.0` while v0.5 is under active adversarial testing. The version will be bumped in a dedicated release step after the v0.5 implementation, tests, documentation, and threat-model snapshot are frozen.

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

### Strong delegated mode

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

For delegated requests, Ruhusa retrieves this canonical record and verifies it against the live request. When a tool registry is also configured and the record contains tool identity, the runtime-observed tool identity is checked against canonical trusted registrations.

The phrase **strong delegated mode** is deliberate. Current v0.5 testing has confirmed that the same strong-tool guarantee does not yet extend automatically to direct/non-delegated requests.

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
3. Invocation provenance for delegated requests
   - strong mode: canonical InvocationRecord
   - weak mode: self-asserted invoker consistency
        |
        v
4. Weak-mode tool verification
   - only when ToolRegistry exists
   - and InvocationStore does not
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

## Current v0.5 Experimental State

The current tool/invocation benchmark contains **16 implemented experiments**. Experiments 15 and 16 are confirmed `GAP` results; Experiment 17 remains a candidate.

### Confirmed Gap — Experiment 15

A direct/non-delegated request with both `InvocationStore` and `ToolRegistry` configured can currently skip both:

- strong invocation/tool verification, because that path is inside the delegated-request branch; and
- weak tool verification, because weak mode is skipped whenever an invocation store exists.

The benchmark currently reproduces:

```text
non-delegated request
InvocationStore configured
ToolRegistry configured
unregistered substitute tool
        |
        v
ALLOW
```

This is a confirmed v0.5 gap, not a theoretical concern.

### Confirmed Gap — Experiment 16

Operation binding blocks reuse of an invocation ID for a *different* action, resource, or arguments.

It does not currently provide one-shot invocation consumption.

The same valid `invocation_id` can be reused for the exact same operation:

```text
request #1 -> ALLOW
request #2 -> ALLOW
request #3 -> ALLOW
```

The benchmark therefore establishes the current contract:

> Ruhusa does not currently enforce one-shot invocation semantics.

Whether Ruhusa should add `consume()`-style semantics or explicitly delegate duplicate-side-effect protection to an idempotent execution layer remains an architectural decision for v0.5.

### Remaining Candidate — Experiment 17

Strong tool verification currently runs when the canonical `InvocationRecord` contains a non-`None` `tool_id`.

The remaining question is what Ruhusa should do when:

```text
InvocationStore configured
ToolRegistry configured
protected operation expected to be tool-mediated
InvocationRecord.tool_id = None
```

This case is identified but not yet represented by an executable experiment.

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

Current work studies:

- confused-deputy attacks
- forged caller identity
- tool substitution
- implementation spoofing
- operation-bound invocation records
- stale invocation replay
- non-delegated strong-mode tool enforcement
- exact invocation replay semantics
- missing canonical tool identity

The milestone is not frozen while confirmed GAP results remain unresolved or intentionally unclassified as part of the final security contract.

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
