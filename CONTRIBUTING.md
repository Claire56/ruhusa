# Contributing to Ruhusa

Thank you for contributing to Ruhusa.

## Development

Ruhusa uses `uv` for Python environment and dependency management.

Clone the repository and install dependencies:

```bash
git clone https://github.com/Claire56/ruhusa.git
cd ruhusa
uv sync
```

Run formatting:

```bash
uv run ruff format .
```

Run linting:

```bash
uv run ruff check .
```

Automatically fix safe lint issues:

```bash
uv run ruff check . --fix
```

Run the test suite:

```bash
uv run pytest -q
```

Run the example:

```bash
uv run python examples/refund_demo.py
```

Build the package:

```bash
uv build
```

When dependencies change, commit both:

```text
pyproject.toml
uv.lock
```

## Principles

Changes to the authorization core should preserve these invariants:

1. **Fail closed.** If authorization cannot be evaluated safely, deny the action.
2. **Prevent privilege amplification.** Delegated authority must remain equal to or narrower than the authority of the delegating principal.
3. **Keep authorization deterministic.** LLMs may propose actions, but policy decisions must be made outside the model by deterministic enforcement logic.
4. **Mediate every protected action.** Security-sensitive tool calls must pass through the authorization boundary before execution.
5. **Audit authorization decisions.** Record sufficient context to reconstruct who requested an action, what was requested, which authority applied, and why the decision was made.
6. **Protect authorization context.** Agents must not be able to modify trusted identity, delegation, approval, or policy state through prompt-generated data.
7. **Validate delegation time bounds.** Grants must be active at evaluation time and must have a valid issuance/expiration window.
8. **Test security behavior.** Every security-relevant change must include tests covering both allowed and denied cases.

## Pull Requests

Before submitting a pull request, run:

```bash
uv run ruff format .
uv run ruff check .
uv run pytest -q
uv build
```

Security-sensitive changes should include a brief explanation of:

- the authorization behavior being changed;
- the threat or use case being addressed;
- the security invariant affected; and
- the tests demonstrating the expected behavior.
