# v0.8.0 release checklist

## Repository gate

- package version is `0.8.0`
- `uv lock` is current
- Ruff format check passes
- Ruff lint passes
- full pytest suite passes
- wheel and sdist build as `ruhusa-0.8.0`
- `tests/test_release_contract.py` passes
- release-candidate GitHub Actions workflow is green

## Clean wheel gate

- base wheel installs with `--no-deps`
- importing `ruhusa` does not require PostgreSQL or FastAPI
- installed `ruhusa version` prints `0.8.0`
- installed `ruhusa doctor --json` works
- `[postgres,fastapi]` extras install together
- namespaced PostgreSQL and FastAPI imports work

## Upgrade gate

The release-candidate workflow must create a database using the published
`ruhusa[postgres]==0.7.0`, verify schema version 1, install the local v0.8.0
wheel, migrate the same database, verify schema version 2, verify exactly one
1→2 migration-history row, and pass `ruhusa postgres health`.

## External consumer regression

Run the external `ruhusa-fastapi-smoke` application against the locally built
v0.8.0 wheel or RC tag.

Re-run the previously established scenarios:

- ALLOW
- REQUIRE_APPROVAL
- DENY
- PostgreSQL persistence
- audit-chain persistence
- replay block
- concurrent execution claim with exactly one winner
- audit failure fail-closed
- stale CLAIMED → UNKNOWN
- UNKNOWN replay blocked
- trusted reconciliation
- database outage blocks protected side effect
- recovery after database restoration

Do not publish v0.8.0 until the external consumer regression is green.

## Release metadata

- release notes reviewed
- known limitations retained
- PyPI description/classifiers reviewed
- tag is exactly `v0.8.0`
- package metadata version is exactly `0.8.0`
- publishing workflow checks tag/package version equality

## Publish

After merge to main and final validation:

1. create signed/annotated `v0.8.0` tag according to project practice;
2. push the tag;
3. create the GitHub release using `docs/releases/v0.8.0.md`;
4. run/observe the existing trusted-publishing workflow;
5. verify PyPI base install in a clean Python 3.12 environment;
6. verify `ruhusa[postgres]==0.8.0`;
7. verify `ruhusa[fastapi]==0.8.0`;
8. verify the CLI from PyPI.

Do not retag a published release. Any release defect becomes `v0.8.1`.
