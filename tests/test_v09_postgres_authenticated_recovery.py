"""D2 PostgreSQL evidence and recovery state must commit atomically."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa import ExecutionRecoveryOutcome, ExecutionState  # noqa: E402
from ruhusa.postgres import (  # noqa: E402
    PostgresExecutionStore,
    create_postgres_pool,
    initialize_postgres_schema,
)
from ruhusa.postgres_recovery import PostgresAuthenticatedRecoveryService  # noqa: E402
from ruhusa.recovery_evidence import (  # noqa: E402
    RecoveryEvidence,
    RecoveryEvidenceVerifier,
    sign_recovery_evidence,
)

DSN = os.getenv("RUHUSA_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(DSN is None, reason="RUHUSA_TEST_POSTGRES_DSN not set")
NOW = datetime(2026, 10, 28, tzinfo=UTC)
KEY = b"test-only-reconciler-secret-longer-than-32-bytes"


@pytest.fixture
def prepared():
    pool = create_postgres_pool(DSN, min_size=1, max_size=8)
    try:
        initialize_postgres_schema(pool)
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE ruhusa_recovery_receipts, ruhusa_executions")
        store = PostgresExecutionStore(pool)
        verifier = RecoveryEvidenceVerifier({("reconciler", "key-1"): KEY})
        service = PostgresAuthenticatedRecoveryService(pool, verifier)
        yield pool, store, service
    finally:
        pool.close()


def make_unknown(
    store, invocation="d2-inv", outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED
):
    claimed = store.claim(invocation, expires_at=NOW + timedelta(hours=1), now=NOW)
    assert claimed.permit is not None
    assert store.mark_unknown(claimed.permit, now=NOW + timedelta(seconds=1))
    return sign_recovery_evidence(
        RecoveryEvidence(
            evidence_id=f"receipt-{invocation}",
            issuer="reconciler",
            key_id="key-1",
            invocation_id=invocation,
            claim_id=claimed.permit.claim_id,
            attempt=claimed.permit.attempt,
            outcome=outcome,
            reason="verified external provider transaction",
            issued_at=NOW + timedelta(seconds=2),
            expires_at=NOW + timedelta(minutes=2),
            signature="",
        ),
        key=KEY,
    )


def test_committed_receipt_and_state(prepared):
    pool, store, service = prepared
    evidence = make_unknown(store)
    assert service.reconcile(evidence, now=NOW + timedelta(seconds=3))
    assert store.get(evidence.invocation_id).state is ExecutionState.AVAILABLE
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM ruhusa_recovery_receipts")
            assert cur.fetchone() == (1,)
    assert not service.reconcile(evidence, now=NOW + timedelta(seconds=4))


def test_invalid_evidence_does_not_consume_or_recover(prepared):
    pool, store, service = prepared
    evidence = make_unknown(store)
    forged = replace(evidence, reason="forged")
    assert not service.reconcile(forged, now=NOW + timedelta(seconds=3))
    assert store.get(evidence.invocation_id).state is ExecutionState.UNKNOWN
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM ruhusa_recovery_receipts")
            assert cur.fetchone() == (0,)


def test_two_service_instances_one_winner(prepared):
    pool, store, service = prepared
    evidence = make_unknown(store)
    other = PostgresAuthenticatedRecoveryService(pool, service._verifier)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(s.reconcile, evidence, now=NOW + timedelta(seconds=3))
            for s in (service, other)
        ]
        results = [future.result() for future in futures]
    assert sorted(results) == [False, True]
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM ruhusa_recovery_receipts")
            assert cur.fetchone() == (1,)


def test_confirmed_effect_not_retryable(prepared):
    _, store, service = prepared
    evidence = make_unknown(store, outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED)
    assert service.reconcile(evidence, now=NOW + timedelta(seconds=3))
    assert store.get(evidence.invocation_id).state is ExecutionState.COMPLETED
