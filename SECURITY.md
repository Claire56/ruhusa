# Security Policy

## Project Status

Ruhusa is currently a **pre-1.0 research framework**.

It should not be treated as a production security boundary, IAM replacement, authorization server, or hardened policy decision point.

The project intentionally contains benchmark configurations labeled `GAP` that reproduce known authorization weaknesses for research purposes.

Before evaluating a security claim, review:

- `docs/threat-model.md`
- `docs/attack-benchmarks.md`
- `docs/architecture.md`

## Reporting a Vulnerability

Please do **not** publish sensitive exploit details, credentials, customer data, proprietary policies, or other confidential material in a public GitHub issue.

If GitHub Private Vulnerability Reporting is enabled for this repository, use the repository's **Security** tab and private reporting flow.

If a private reporting option is not available, open a minimal public issue stating that you have a security report and need a private disclosure channel. Do not include exploit steps, secrets, proof-of-concept payloads, or sensitive logs in that issue.

## What to Include Privately

A useful security report should include:

- affected component or configuration
- preconditions
- attacker capability
- expected behavior
- observed behavior
- minimal reproduction steps
- impact
- whether the issue also applies to strong provenance mode or only a weak compatibility mode

## Research Gaps vs Vulnerabilities

Some behaviors are intentionally preserved as research baselines.

Examples may include tests labeled:

```text
GAP
```

in `docs/attack-benchmarks.md`.

A known `GAP` is still useful to report if you have discovered:

- a new attack variant;
- a bypass of a control documented as `BLOCKS`;
- an unexpected impact beyond the benchmarked case; or
- a vulnerability in a configuration documented as hardened.

## Current Security Assumptions

The current strong-provenance model assumes:

- executing agents cannot write to canonical trusted stores;
- trusted orchestration records runtime identity faithfully;
- authorization checks run before protected side effects;
- callers honor the returned authorization decision.

Compromise of the Ruhusa host process or trusted orchestration boundary is outside the current guarantee.

## Supported Versions

Ruhusa has not yet reached a stable 1.0 security-support policy.

During pre-1.0 development, security fixes are applied to the active development line rather than maintained across multiple long-lived release branches.

## Disclosure Expectations

Please allow maintainers a reasonable opportunity to reproduce, understand, and address a reported issue before public disclosure.

The project may convert validated vulnerabilities into anonymized adversarial benchmark cases after remediation so that the security property remains regression-tested.
