# v0.9-D3c: distributed recovery validation (development)

This increment adds adversarial PostgreSQL tests for the **authenticated**
recovery adapter. It does not change the public recovery API.

## New tests

- **Reconciler process restart and replay**: an independent process accepts a
  signed receipt, exits normally; another independently constructed process
  cannot reuse that receipt. The committed state persists.
- **Cross-process concurrency**: two independently spawned processes compete
  to reconcile the same attempt. Exactly one succeeds; one receipt is stored.
- **Injected PostgreSQL update failure**: a temporary test-only trigger raises
  after the receipt is inserted but before the execution transition completes.
  The entire service transaction rolls back; the same still-valid evidence can
  succeed after the fault is removed.
- **Abrupt crash before commit**: a child process inserts an uncommitted receipt
  and exits with `os._exit(73)`; PostgreSQL rolls back the receipt, leaving the
  execution UNKNOWN. Authenticated reconciliation subsequently succeeds.

## Run in GitHub Actions

The CI PostgreSQL service should set `RUHUSA_TEST_POSTGRES_DSN` and execute the
**full PostgreSQL-enabled suite**, rather than an explicit filename list:

```bash
uv run --extra postgres pytest -v -rs --tb=short
```

Focused run:

```bash
uv run --extra postgres pytest tests/test_v09_postgres_recovery_d3c.py -v -rs
```

**Only run against a disposable test database**. The fixture truncates both
`ruhusa_executions` and `ruhusa_recovery_receipts`. The rollback test briefly
creates a test-only trigger on `ruhusa_executions` and removes it in `finally`.
Do not run these tests concurrently with other suites against the same DSN.

## Evidence boundaries and known gaps

- Process-isolated testing verifies multiple Python processes using separate
  connection pools, but it is **not** a network-partition, multi-region, or
  container-kill test.
- Abrupt termination occurs after a direct uncommitted receipt write; it
  verifies PostgreSQL rollback semantics but does not instrument termination
  at every internal point of `PostgresAuthenticatedRecoveryService`.
- Signed evidence authenticates claims from the configured reconciler; it does
  not prove the external provider's report is factually correct.
- Library-level default-deny checks cannot secure unrestricted database
  `UPDATE` privileges or leaked signing keys. Production reconciliation
  requires separate identities, database permissions, and secret controls.
- Final release should confirm CI results on the latest merged branch and
  test actual deployment credentials and failure boundaries separately.
