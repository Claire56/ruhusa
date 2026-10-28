# Documentation audit — 2026-10-28

## Source and coverage

Audited the user-supplied `ruhusa-main (4).zip` snapshot. Reviewed the 36 Markdown files in the repository, checked local Markdown file links (zero missing relative file targets), and cross-checked release, PostgreSQL schema, integration, and test statements against the source tree and the user-provided run reports. This is a documentation review, **not** an independent execution of the full test matrix or a verification of the latest remote GitHub branch.

## Corrections supplied in this patch

1. **README:** Correctly distinguishes stable published `0.8.0` (PostgreSQL schema v2) from unreleased source with schema v3; removes duplicate recovery roadmap item and outdated PR-centric phrasing.
2. **Changelog:** Separates implemented D1 signed-evidence prototype from pending *distributed* authenticated recovery and production MCP transport authentication.
3. **Development status:** Replaces duplicated and stale MCP/recovery rows with milestone-by-milestone status and release gates; records B3 controlled results and optional MCP protocol verification without calling them production guarantees.
4. **PostgreSQL/migrations:** Documents `SCHEMA_VERSION = 3` in development source and the v2→v3 migration while preserving the distinction from the published stable package.
5. **Approvals:** Removes unsupported suggestion that the B-series research benchmark provides verified external approver identity.
6. **B3 protocol:** Adds the reported 10-trial, nine-scenario GPT-4.1-mini controlled results with limitations.
7. **MCP documentation:** Updates the remaining production gates to recognize the existing in-process SDK round-trip test.
8. **Recovery security documentation:** Clarifies that signatures authenticate receipts but do not establish the truthfulness of an external side effect.

## Remaining documentation / verification gates

- **Stable-version package labeling:** `pyproject.toml` currently identifies as `0.8.0` while development source includes schema v3 and unreleased APIs. Before distributing any build, adopt a deliberate pre-release version / publishing policy so development artifacts cannot be mistaken for the stable `0.8.0` package.
- **Production recovery protection:** D1 does not enforce signed evidence on the legacy `reconcile_unknown` entry points; durable shared replay and atomic evidence/state transitions are D2 work. Keep this limitation prominently documented.
- **MCP transport security:** The SDK in-process round trip does not test authenticated HTTP deployments, external service identity, or durable fencing of real side effects.
- **Research reproducibility:** Record exact source commit, model identifier and parameters, prompts, test environment, and saved experiment output for B3. Its 90 evaluations were controlled and repeated proposals were largely identical.
- **Persistent approval trust:** `approved_by` and related strings are recorded, not cryptographically authenticated by Ruhusa. Production deployment instructions must require a trusted identity source.
- **Migration/upgrade tests:** Verify both v0.7 schema-v1→v0.8 schema-v2 and v0.7/v0.8→v0.9 schema-v3 paths in CI; include repeat initialization and mutation-of-checksum detection.
- **Historical docs:** Do not rewrite frozen v0.6/v0.7 milestone documents as current manuals. They are appropriately preserved as historical context.
- **Claims in long-form architecture and attack-benchmark narratives:** Manually cross-verify the historical experiment count and any statements about automatic descendant revocation against the exact current code and test names before using them in a paper or external security claim. This review did not substantiate every historical claim line-by-line.

## Scope of audit validation

- Markdown file inventory: 36.
- Missing relative Markdown file targets: 0.
- README, changelog, status, migration, PostgreSQL, approval, MCP, authenticated-recovery, and B3 materials revised.
- No Python source or migration SQL changed.
- No claims made about running the full test suite, deployed HTTP MCP, or the published PyPI wheel from this audit.
