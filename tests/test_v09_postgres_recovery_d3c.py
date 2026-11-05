"""D3c: real-process restart, rollback, crash, and replay PostgreSQL evidence.

These tests require a disposable PostgreSQL test database. Never use a production DSN.
Workers create their OWN connections/pools rather than sharing a parent's pool.
"""

from __future__ import annotations

import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa import ExecutionRecoveryOutcome, ExecutionState
from ruhusa.postgres import (
    PostgresExecutionStore,
    create_postgres_pool,
    initialize_postgres_schema,
)
from ruhusa.postgres_recovery import PostgresAuthenticatedRecoveryService
from ruhusa.recovery_evidence import (
    RecoveryEvidence,
    RecoveryEvidenceVerifier,
    sign_recovery_evidence,
)

DSN = os.getenv("RUHUSA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(DSN is None, reason="RUHUSA_TEST_POSTGRES_DSN not set")
NOW = datetime(2026, 10, 28, tzinfo=UTC)
KEY = b"d3c-test-reconciler-secret-longer-than-32-bytes"


def _verifier():
    return RecoveryEvidenceVerifier({("d3c-reconciler", "key-1"): KEY})


def _independent_reconcile(dsn: str, evidence: RecoveryEvidence) -> bool:
    """Runs in a spawned process, with no inherited pool or service."""
    pool = create_postgres_pool(dsn, min_size=1, max_size=2)
    try:
        service = PostgresAuthenticatedRecoveryService(pool, _verifier())
        return service.reconcile(evidence, now=NOW + timedelta(seconds=3))
    finally:
        pool.close()


def _crash_during_uncommitted_receipt(dsn: str, evidence: RecoveryEvidence) -> None:
    """Simulate abrupt reconciler death after INSERT but before COMMIT.

    An independent Psycopg connection starts a transaction and writes a receipt.
    os._exit() terminates without COMMIT or connection cleanup. PostgreSQL must
    roll back the uncommitted record when the connection disappears.
    """
    import psycopg

    conn = psycopg.connect(dsn)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO ruhusa_recovery_receipts
           (evidence_id, invocation_id, claim_id, attempt, issuer, key_id,
            outcome, signature, reconciled_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            evidence.evidence_id,
            evidence.invocation_id,
            evidence.claim_id,
            evidence.attempt,
            evidence.issuer,
            evidence.key_id,
            evidence.outcome.value,
            evidence.signature,
            NOW + timedelta(seconds=3),
        ),
    )
    os._exit(73)


@pytest.fixture
def prepared():
    pool = create_postgres_pool(DSN, min_size=1, max_size=5)
    try:
        initialize_postgres_schema(pool)
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("TRUNCATE ruhusa_recovery_receipts, ruhusa_executions")
        yield pool, PostgresExecutionStore(pool)
    finally:
        pool.close()


def _make_unknown(store, invocation: str) -> RecoveryEvidence:
    claimed = store.claim(invocation, expires_at=NOW + timedelta(hours=1), now=NOW)
    assert claimed.permit is not None
    assert store.mark_unknown(claimed.permit, now=NOW + timedelta(seconds=1))
    return sign_recovery_evidence(
        RecoveryEvidence(
            evidence_id=f"d3c-receipt-{invocation}",
            issuer="d3c-reconciler",
            key_id="key-1",
            invocation_id=invocation,
            claim_id=claimed.permit.claim_id,
            attempt=claimed.permit.attempt,
            outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED,
            reason="trusted provider verification",
            issued_at=NOW + timedelta(seconds=2),
            expires_at=NOW + timedelta(minutes=2),
            signature="",
        ),
        key=KEY,
    )


def _receipt_count(pool) -> int:
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM ruhusa_recovery_receipts")
        return cur.fetchone()[0]


def test_recovery_persists_after_service_and_connection_restart(prepared):
    pool, store = prepared
    evidence = _make_unknown(store, "d3c-restart")
    # A spawned process has an independent pool and service lifecycle.
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=1, mp_context=ctx) as executor:
        assert executor.submit(_independent_reconcile, DSN, evidence).result(timeout=30)
    assert store.get(evidence.invocation_id).state is ExecutionState.AVAILABLE
    assert _receipt_count(pool) == 1
    with ProcessPoolExecutor(max_workers=1, mp_context=ctx) as executor:
        assert not executor.submit(_independent_reconcile, DSN, evidence).result(timeout=30)
    assert _receipt_count(pool) == 1


def test_two_independent_processes_only_one_can_reconcile(prepared):
    pool, store = prepared
    evidence = _make_unknown(store, "d3c-process-race")
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=2, mp_context=ctx) as executor:
        futures = [executor.submit(_independent_reconcile, DSN, evidence) for _ in range(2)]
        results = [f.result(timeout=30) for f in futures]
    assert sorted(results) == [False, True]
    assert _receipt_count(pool) == 1
    assert store.get(evidence.invocation_id).state is ExecutionState.AVAILABLE


def test_failed_transition_rolls_back_receipt_and_is_retryable(prepared):
    """Force an UPDATE error after receipt INSERT inside the service transaction."""
    pool, store = prepared
    evidence = _make_unknown(store, "d3c-rollback")
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """CREATE OR REPLACE FUNCTION ruhusa_d3c_fail_recovery()
                   RETURNS trigger LANGUAGE plpgsql AS $$
                   BEGIN
                       RAISE EXCEPTION 'd3c injected update failure';
                   END;
                   $$"""
        )
        cur.execute(
            """CREATE TRIGGER ruhusa_d3c_fail_recovery_update
                   BEFORE UPDATE ON ruhusa_executions
                   FOR EACH ROW
                   WHEN (NEW.recovery_count > OLD.recovery_count)
                   EXECUTE FUNCTION ruhusa_d3c_fail_recovery()"""
        )
    try:
        service = PostgresAuthenticatedRecoveryService(pool, _verifier())
        with pytest.raises(Exception, match="d3c injected update failure"):
            service.reconcile(evidence, now=NOW + timedelta(seconds=3))
        assert _receipt_count(pool) == 0
        assert store.get(evidence.invocation_id).state is ExecutionState.UNKNOWN
    finally:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "DROP TRIGGER IF EXISTS ruhusa_d3c_fail_recovery_update ON ruhusa_executions"
            )
            cur.execute("DROP FUNCTION IF EXISTS ruhusa_d3c_fail_recovery()")
    assert service.reconcile(evidence, now=NOW + timedelta(seconds=4))
    assert _receipt_count(pool) == 1


def test_abrupt_process_exit_rolls_back_uncommitted_receipt(prepared):
    pool, store = prepared
    evidence = _make_unknown(store, "d3c-crash")
    ctx = multiprocessing.get_context("spawn")
    child = ctx.Process(target=_crash_during_uncommitted_receipt, args=(DSN, evidence))
    child.start()
    child.join(timeout=30)
    if child.is_alive():
        child.terminate()
        child.join(timeout=5)
        pytest.fail("crash-injection worker hung")
    assert child.exitcode == 73, f"worker did not reach crash point: {child.exitcode}"
    assert _receipt_count(pool) == 0
    assert store.get(evidence.invocation_id).state is ExecutionState.UNKNOWN
    assert PostgresAuthenticatedRecoveryService(pool, _verifier()).reconcile(
        evidence, now=NOW + timedelta(seconds=3)
    )
    assert _receipt_count(pool) == 1
