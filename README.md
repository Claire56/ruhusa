# Ruhusa

**Continuous authorization for multi-agent AI systems.**

Ruhusa means **permission** in Swahili.

LLMs decide what action to propose. Ruhusa determines whether they have permission to execute it.

> **Authority should narrow as agents delegate—not expand.**

## Overview

Ruhusa is an open-source research framework for studying continuous, least-privilege authorization across AI agents, tools, and multi-agent delegation workflows.

The project focuses on a simple security principle:

> The model may propose an action, but a deterministic authorization layer must decide whether that action is allowed.

Ruhusa is designed to explore security questions involving agent identity, delegation, authorization propagation, resource constraints, argument-level controls, human approval, revocation, task binding, replay protection, and auditability.

## v0.3.0 Capabilities

Ruhusa v0.3.0 provides a deterministic authorization core for experimenting with:

- default-deny authorization
- least-privilege delegation
- multi-hop delegation validation
- delegated-scope attenuation
- resource and argument constraints
- human approval decisions
- fail-closed policy evaluation
- hash-chained audit logging
- mid-workflow grant revocation
- fail-closed revocation checks
- task-bound delegation
- cross-task replay protection
- multi-hop task consistency

The authorization core intentionally remains independent of LangGraph, MCP, and A2A. Framework integrations can be added after the core security invariants and experimental benchmarks are established.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Development

Ruhusa uses `uv` for Python environment, dependency, and package management.

### Clone the Repository

```bash
git clone https://github.com/Claire56/ruhusa.git
cd ruhusa
```

### Install Dependencies

```bash
uv sync
```

### Run Tests

```bash
uv run pytest
```

For quieter output:

```bash
uv run pytest -q
```

### Lint

```bash
uv run ruff check .
```

Automatically fix safe lint issues:

```bash
uv run ruff check . --fix
```

### Format

```bash
uv run ruff format .
```

### Run the Example

```bash
uv run python examples/refund_demo.py
```

### Build the Package

```bash
uv build
```

The wheel and source distribution will be written to `dist/`.

### Before Committing

```bash
uv run ruff format .
uv run ruff check .
uv run pytest
uv build
```

## Adding Dependencies

Add a runtime dependency:

```bash
uv add pydantic
```

Add a development dependency:

```bash
uv add --dev pytest-cov
```

When dependencies change, commit both:

```text
pyproject.toml
uv.lock
```

## Core Usage

```python
from ruhusa import Ruhusa

gate = Ruhusa(policy_store=policies)
decision = gate.authorize(request)

if decision.allowed:
    execute_tool()
```

Ruhusa evaluates authorization at the protected action boundary:

```text
Agent proposes action
        |
        v
      Ruhusa
        |
        +-- Task valid?
        +-- Delegation valid and active?
        +-- Grant bound to current task?
        +-- Delegated authority narrowed?
        +-- Grant currently revoked?
        +-- Resource allowed?
        +-- Arguments allowed?
        +-- Policy matched?
        |
        v
ALLOW | DENY | REQUIRE_APPROVAL
```

Authorization is evaluated for each protected action. A grant that was valid earlier in a workflow can therefore be denied later if it has been revoked or if it is presented in a different task context.

## Security Principles

Ruhusa v0.3.0 aims to preserve these invariants:

1. Fail closed when authorization cannot be evaluated safely.
2. Prevent delegated authority from expanding.
3. Keep authorization decisions deterministic and outside the LLM.
4. Mediate protected actions before execution.
5. Record authorization decisions in a hash-chained audit log.
6. Keep trusted authorization context outside agent-controlled prompt data.
7. Reject delegation grants that are expired, not yet active, or have invalid validity windows.
8. Re-check current revocation state before protected delegated actions.
9. Deny when revocation state cannot be safely determined.
10. Bind delegated authority to the task for which it was issued.
11. Reject cross-task replay and cross-task delegation-chain splicing.
12. Cover security-relevant behavior with tests.

> Note: the current audit log is hash-chained, not cryptographically anchored or independently signed. It should not yet be treated as a production tamper-evident audit system.

## Milestones

### v0.1 — Deterministic Authorization Core

Established the initial authorization boundary with default deny, scoped delegation, human approval, fail-closed policy evaluation, and hash-chained audit logging.

### v0.2 — Mid-Workflow Revocation

Added revocation records, continuous revocation checks, fail-closed revocation behavior, and support for earlier emergency revocation superseding a later scheduled revocation.

### v0.3 — Task-Bound Delegation and Replay Protection

Bound delegation grants to their originating task and added checks that reject cross-task replay and inconsistent multi-hop task chains.

## Research Direction

Ruhusa is intended to support research into authorization preservation across dynamic multi-agent workflows.

The current implementation establishes foundational authorization invariants. Future research milestones are expected to evaluate behavior under:

- retry-induced privilege escalation
- replanning after authorization denial
- delegation-chain mutation
- stale or replayed authority
- tool substitution and tool-identity confusion
- cross-user and cross-resource access
- approval bypass
- policy mutation
- authorization propagation across dynamic workflows
- audit reconstruction

Future versions may also explore integrations with:

- LangGraph
- Model Context Protocol (MCP)
- Agent2Agent (A2A)
- OAuth/OIDC and token exchange
- enterprise policy decision points
- OpenID AuthZEN-compatible authorization APIs
- OPA/Rego or comparable policy engines
- OpenTelemetry-based tracing and observability

## Project Status

Ruhusa is a pre-1.0 research framework. APIs and security models may change as new authorization invariants and adversarial benchmarks are added.

It is not yet intended to replace a production IAM, authorization server, or policy decision point.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and security principles.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## License

Ruhusa is licensed under the Apache License 2.0.
