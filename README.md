# Ruhusa

**Continuous authorization for multi-agent AI systems.**

Ruhusa means **permission** in Swahili.

LLMs decide what action to propose. Ruhusa determines whether they have permission to execute it.

> **Authority should narrow as agents delegate—not expand.**

## v0.1 goals

Ruhusa v0.1 provides a small deterministic authorization core for experimenting with:

- default-deny authorization
- least-privilege delegation
- resource and argument constraints
- human approval decisions
- fail-closed policy evaluation
- tamper-evident audit logging

The initial release intentionally keeps the authorization core independent of LangGraph, MCP, and A2A. Framework integrations can be added after the core security invariants are tested.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Setup

Clone the repository:

```bash
git clone https://github.com/Claire56/ruhusa.git
cd ruhusa
```

Create the environment and install the project with development dependencies:

```bash
uv sync
```

Run the test suite:

```bash
uv run pytest
```

Run the example:

```bash
uv run python examples/refund_demo.py
```

Build the Python package:

```bash
uv build
```

The wheel and source distribution will be written to `dist/`.

## Adding dependencies

Runtime dependency:

```bash
uv add pydantic
```

Development dependency:

```bash
uv add --dev pytest-cov
```

After dependency changes, commit both:

```text
pyproject.toml
uv.lock
```

## Core usage

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
        +-- Delegation valid?
        +-- Authority narrowed?
        +-- Resource allowed?
        +-- Arguments allowed?
        +-- Policy matched?
        |
        v
ALLOW | DENY | REQUIRE_APPROVAL
```

## Research direction

Ruhusa is an open-source research framework for studying authorization correctness across dynamic multi-agent workflows, including:

- multi-hop delegation
- mid-workflow revocation
- retry- and replanning-induced privilege escalation
- tool substitution
- cross-user/resource access
- approval bypass
- policy mutation
- audit reconstruction

## License

Apache License 2.0.
