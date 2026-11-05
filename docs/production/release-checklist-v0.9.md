# Ruhusa v0.9 release-candidate checklist

**Candidate:** `0.9.0rc1` · **Stable on PyPI:** `0.8.0` until GA publication.

## Version and packaging

- [ ] `pyproject.toml`, `uv.lock`, `importlib.metadata.version`, wheel, sdist and CLI report `0.9.0rc1`.
- [ ] Run `uv lock` and `uv sync --locked --extra postgres --extra fastapi`.
- [ ] Run `uv build`; install wheel and sdist in independent clean Python 3.12 virtual environments.
- [ ] Verify base wheel does not require PostgreSQL/FastAPI packages; extras work in clean installs.

## Mandatory CI

- [ ] Ruff format/lint, general tests, FastAPI integration, full PostgreSQL suite.
- [ ] D3b direct unsigned reconciliation rejected by default in both execution stores.
- [ ] D3c restart, cross-process concurrency, rollback and abrupt-exit tests **actually run and pass**.
- [ ] Real MCP SDK v2 round-trip **runs and passes**; a skip is not sufficient.
- [ ] PostgreSQL v0.7.0 → candidate v4 upgrade test passes.
- [ ] PostgreSQL published v0.8.0 schema v2 → candidate v4 upgrade test passes.
- [ ] Final CI logs archived in release evidence.

## Security release review

- [ ] No untrusted path can construct/use unsafe legacy recovery mode.
- [ ] Reconciler transport identity, roles, signing keys, logging/retention and rotation documented.
- [ ] No claim of exactly-once external effects, network partition tolerance or full formal proof.
- [ ] Document approvals, trust boundaries, fail-closed behavior and known limitations.

## Documentation

- [ ] README status and install examples match candidate; stable v0.8.0 guidance retained.
- [ ] CHANGELOG records D1–D3c, A/B/C milestones, upgrade/breaking changes.
- [ ] Schema migration guide and PostgreSQL deployment guide updated for v4.
- [ ] MCP and authenticated recovery guides verified against actual API signatures.
- [ ] Candidate release notes, production limitations and test methodology reviewed.
- [ ] Links and example code validated in CI or manually.

## Publication (not automatic)

- [ ] Candidate approved and tagged `v0.9.0rc1` only after checks pass.
- [ ] Verify TestPyPI/PyPI publishing configuration, credentials and provenance.
- [ ] For GA, change version to `0.9.0`, regenerate lock/artifacts, repeat all release checks.
- [ ] Publish GitHub release notes and PyPI distribution; verify download/install.
