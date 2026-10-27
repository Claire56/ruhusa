# Documentation audit — 2026-10-27

Basis: user-provided `ruhusa-main.zip` and public GitHub main/PR #28 pages.
The ZIP is a main-branch snapshot; unmerged PR files were **not** available
for direct file-by-file editing here. Recheck this audit against the live PR
before applying changes to that branch.

## Corrected in this patch

- README was announcing v0.7 as current despite package metadata v0.8.0.
- README table of contents was incomplete and had nonstandard anchors.
- CHANGELOG lacked v0.8.0 and a clear unreleased v0.9 section.
- Top of architecture.md was presenting v0.6 as the current package.
- Production readiness was titled v0.7 and had an obsolete self-referential release gate.
- PostgreSQL guide had an outdated v0.7-only introduction / schema version statement.
- Migration guide lacked a clearly separated schema-v3 development note.

## Retained as historical artifacts

- `docs/threat-model/v0.4.md`, `v0.5.md`, `v0.6.md`.
- `docs/research/v0.6-*.md`, `docs/framework/v0.7-A-stable-interfaces.md`.
- `docs/releases/v0.8.0.md` and `docs/production/release-checklist-v0.8.0.md`.

They describe historical milestones and should **not** be rewritten as if
v0.9 features existed at the time of release.

## Follow-up needed on the v0.9 development branch

- Reconcile `docs/architecture/approvals.md` and new public API docs against
  final implementation of `PostgresApprovalStore` and its trust limitations.
- Verify that v0.9 schema v3 migration tests distinguish stable v0.8 upgrades
  from development upgrade-to-v3 tests.
- Check all workflow job names and Python environment extras for PostgreSQL.
- Re-run full tests and link checks after applying this documentation patch.
- Do not claim benchmark or MCP integration is shipped before those tests/code exist.
