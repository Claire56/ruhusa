# Ruhusa

**Continuous authorization for multi-agent AI systems.**

Ruhusa means **permission** in Swahili.

LLMs decide what action to propose. Ruhusa determines whether they have permission to execute it.

> **Authority should narrow as agents delegate—not expand.**

## Overview

Ruhusa is an open-source research framework for studying continuous, least-privilege authorization across AI agents, tools, and multi-agent delegation workflows.

The project focuses on a simple security principle:

> The model may propose an action, but a deterministic authorization layer must decide whether that action is allowed.

Ruhusa is designed to explore security questions involving agent identity, delegation, authorization propagation, resource constraints, argument-level controls, human approval, revocation, and auditability.

## v0.1 Goals

Ruhusa v0.1 provides a small deterministic authorization core for experimenting with:

- default-deny authorization
- least-privilege delegation
- resource and argument constraints
- human approval decisions
- fail-closed policy evaluation
- hash-chained audit logging

The initial release intentionally keeps the authorization core independent of LangGraph, MCP, and A2A. Framework integrations can be added after the core security invariants are tested.

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

Ruhusa evaluates authorization at the action boundary:

```text
Agent proposes action
        |
        v
      Ruhusa
        |
        +-- Task valid?
        +-- Delegation valid and active?
        +-- Authority narrowed?
        +-- Resource allowed?
        +-- Arguments allowed?
        +-- Policy matched?
        |
        v
ALLOW | DENY | REQUIRE_APPROVAL
```

## Security Principles

Ruhusa v0.1 aims to preserve these invariants:

1. Fail closed when authorization cannot be evaluated safely.
2. Prevent delegated authority from expanding.
3. Keep authorization decisions deterministic and outside the LLM.
4. Mediate protected actions before execution.
5. Record authorization decisions in a hash-chained audit log.
6. Keep trusted authorization context outside agent-controlled prompt data.
7. Reject delegation grants that are expired, not yet active, or have invalid validity windows.
8. Cover security-relevant behavior with tests.

> Note: the v0.1 audit log is **hash-chained**, not cryptographically anchored or independently signed. It should not yet be treated as a production tamper-evident audit system.

## Research Direction

Ruhusa is intended to support research into authorization correctness across dynamic multi-agent workflows, including:

- multi-hop delegation
- mid-workflow revocation
- retry-induced privilege escalation
- replanning-induced privilege escalation
- tool substitution
- cross-user and cross-resource access
- approval bypass
- policy mutation
- expired authority replay
- audit reconstruction

Future versions are expected to explore integrations with:

- LangGraph
- Model Context Protocol (MCP)
- Agent2Agent (A2A)
- OAuth/OIDC
- enterprise policy decision points
- OPA/Rego or comparable policy engines
- OpenTelemetry-based tracing and observability

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and security principles.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## License

Ruhusa is licensed under the Apache License 2.0.
