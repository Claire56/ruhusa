# Contributing to Ruhusa

Thank you for contributing to Ruhusa.

Ruhusa is a security research framework. Changes to authorization behavior should be treated as changes to a security model, not merely as feature additions.

## Development Setup

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

Run tests:

```bash
uv run pytest
```

Run the example:

```bash
uv run python examples/refund_demo.py
```

Build:

```bash
uv build
```

When dependencies change, commit both:

```text
pyproject.toml
uv.lock
```

## Core Principles

Changes should preserve the following design rules.

1. **Fail closed.** If required authorization state cannot be evaluated safely, deny the action.
2. **Prevent privilege amplification.** Delegated authority may remain equal or narrow; it may not expand.
3. **Keep authorization deterministic.** LLMs may propose actions, but final authorization decisions remain outside the model.
4. **Mediate protected actions.** Security-sensitive side effects must pass through the authorization boundary.
5. **Separate claims from provenance.** Agent-supplied identity fields must not be treated as authenticated merely because they contain expected values.
6. **Protect canonical authorization state.** Executing agents must not be able to mutate trusted grant, revocation, invocation, tool-registry, or policy state.
7. **Bind authority to context.** Task, delegation, operation, and time bounds must remain explicit.
8. **Audit decisions.** Record enough context to support reconstruction and research analysis.
9. **Do not overclaim.** A control's documented guarantee must match the exact configuration and attack variants that have been tested.

## Attack-First Method

Security-sensitive changes should normally begin with an adversarial test.

Preferred sequence:

```text
attack
  |
  v
baseline result
  |
  +-- already blocked -> document existing invariant
  |
  +-- succeeds -------> record GAP
                         |
                         v
                    identify root cause
                         |
                         v
                    implement smallest control
                         |
                         v
                    rerun same attack
```

After a mitigation succeeds, consider how an attacker would adapt.

A new security control should include, where practical:

- an attack-path test;
- a legitimate positive-path test;
- a fail-closed/error-path test if external state is involved; and
- documentation of any configuration in which the attack remains possible.

## Benchmark Labels

Tests in security benchmark modules may intentionally encode vulnerabilities.

`GAP` means the test passes when the attack succeeds.

`BLOCKS` means the test passes when Ruhusa rejects the attack.

`CONTROL` confirms existing behavior remains correct.

Do not "fix" a `GAP` assertion merely because it expects `ALLOW`; first determine whether the test is preserving an intentional baseline research result.

See:

```text
docs/attack-benchmarks.md
```

## Documentation Responsibilities

Security-relevant changes should keep these documents aligned:

```text
docs/architecture.md
docs/threat-model.md
docs/attack-benchmarks.md
```

Historical snapshots such as:

```text
docs/threat-model/v0.4.md
docs/architecture/v0.1.md
```

should not be rewritten to describe later behavior.

When a milestone is frozen, create a new versioned snapshot rather than editing old history.

## Pull Requests

Before opening or updating a pull request:

```bash
uv run ruff format .
uv run ruff check .
uv run pytest
uv build
```

A security-sensitive PR should describe:

- the threat or failure being studied;
- the baseline behavior;
- the affected invariant;
- the control being introduced;
- exact verification tests;
- the legitimate path that should remain allowed;
- known limitations or configurations where the threat remains open.

Where a PR intentionally preserves a vulnerable compatibility mode, say so explicitly.

## Scope Discipline

Ruhusa should not accumulate controls simply because they are common security features.

Prefer:

```text
demonstrated failure
        ->
small targeted control
        ->
executable evidence
```

over speculative feature accumulation.

## Code Style

Use the existing project tooling and patterns. Keep authorization code deterministic, small, inspectable, and testable.

Avoid moving authorization decisions into model prompts or LLM judgment.

## Security Reports

Do not place sensitive vulnerability details, real credentials, customer data, or proprietary policy material in public issues.

See `SECURITY.md` for reporting guidance.
