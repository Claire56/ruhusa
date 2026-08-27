from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa.execution import (  # noqa: E402
    ExecutionRecoveryOutcome,
    ExecutionState,
)
from ruhusa.interfaces import ExecutionStore  # noqa: E402
from ruhusa.postgres import (  # noqa: E402
    PostgresExecutionStore,
    create_postgres_pool,
    initialize_postgres_schema,
)

TEST_DSN = os.getenv("RUHUSA_TEST_POSTGRES_DSN")

pytestmark = pytest.mark.skipif(
    TEST_DSN is None,
    reason="RUHUSA_TEST_POSTGRES_DSN is not configured",
)


@pytest.fixture
def pool():
    assert TEST_DSN is not None

    pool = create_postgres_pool(
        TEST_DSN,
        min_size=1,
        max_size=20,
    )
    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE ruhusa_executions")

    try:
        yield pool
    finally:
        pool.close()


def _now() -> datetime:
    return datetime(
        2026,
        8,
        26,
        12,
        0,
        tzinfo=UTC,
    )


def test_postgres_execution_store_satisfies_protocol(
    pool,
) -> None:
    assert isinstance(
        PostgresExecutionStore(pool),
        ExecutionStore,
    )


def test_claim_creates_durable_claimed_record(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)
    now = _now()

    result = store.claim(
        "inv-1",
        expires_at=now + timedelta(hours=1),
        now=now,
    )

    assert result.allowed
    assert result.permit is not None
    assert result.record is not None
    assert result.record.state is ExecutionState.CLAIMED
    assert result.record.attempt_count == 1

    stored = store.get("inv-1")

    assert stored == result.record
    assert store.is_active(result.permit)


def test_concurrent_claim_has_exactly_one_winner(
    pool,
) -> None:
    now = _now()
    expires_at = now + timedelta(hours=1)

    worker_count = 20
    barrier = Barrier(worker_count)

    def attempt_claim(_: int):
        # Separate store instances deliberately share no Python lock.
        store = PostgresExecutionStore(pool)
        barrier.wait()

        return store.claim(
            "inv-concurrent",
            expires_at=expires_at,
            now=now,
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = list(
            executor.map(
                attempt_claim,
                range(worker_count),
            )
        )

    winners = [result for result in results if result.allowed]

    assert len(winners) == 1
    assert winners[0].permit is not None

    store = PostgresExecutionStore(pool)
    record = store.get("inv-concurrent")

    assert record is not None
    assert record.state is ExecutionState.CLAIMED
    assert record.attempt_count == 1
    assert store.is_active(winners[0].permit)


def test_expired_authority_cannot_be_claimed(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)
    now = _now()

    result = store.claim(
        "inv-expired",
        expires_at=now,
        now=now,
    )

    assert not result.allowed
    assert result.reason == ("execution authority has expired")
    assert store.get("inv-expired") is None


def test_canonical_expiry_mismatch_denies(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)
    now = _now()

    first = store.claim(
        "inv-expiry",
        expires_at=now + timedelta(hours=1),
        now=now,
    )
    assert first.allowed
    assert first.permit is not None

    assert store.release_before_execution(
        first.permit,
        now=now + timedelta(seconds=1),
    )

    mismatch = store.claim(
        "inv-expiry",
        expires_at=now + timedelta(hours=2),
        now=now + timedelta(seconds=2),
    )

    assert not mismatch.allowed
    assert mismatch.reason == "execution lifecycle expiry does not match canonical invocation"


def test_stale_permit_cannot_complete_new_attempt(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)
    now = _now()
    expires_at = now + timedelta(hours=1)

    first = store.claim(
        "inv-fencing",
        expires_at=expires_at,
        now=now,
    )

    assert first.allowed
    assert first.permit is not None

    assert store.release_before_execution(
        first.permit,
        now=now + timedelta(seconds=1),
    )

    second = store.claim(
        "inv-fencing",
        expires_at=expires_at,
        now=now + timedelta(seconds=2),
    )

    assert second.allowed
    assert second.permit is not None

    assert second.permit.attempt == 2
    assert second.permit.claim_id != first.permit.claim_id

    # Old worker has lost its fencing token.
    assert not store.complete(
        first.permit,
        now=now + timedelta(seconds=3),
    )

    assert store.is_active(second.permit)

    assert store.complete(
        second.permit,
        now=now + timedelta(seconds=4),
    )

    record = store.get("inv-fencing")

    assert record is not None
    assert record.state is ExecutionState.COMPLETED


def test_unknown_blocks_retry_until_reconciliation(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)
    now = _now()
    expires_at = now + timedelta(hours=1)

    claimed = store.claim(
        "inv-unknown",
        expires_at=expires_at,
        now=now,
    )

    assert claimed.permit is not None

    assert store.mark_unknown(
        claimed.permit,
        now=now + timedelta(seconds=1),
    )

    retry = store.claim(
        "inv-unknown",
        expires_at=expires_at,
        now=now + timedelta(seconds=2),
    )

    assert not retry.allowed
    assert retry.record is not None
    assert retry.record.state is ExecutionState.UNKNOWN

    assert store.reconcile_unknown(
        "inv-unknown",
        outcome=(ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED),
        reason="provider confirms no side effect",
        now=now + timedelta(seconds=3),
    )

    retry_after_recovery = store.claim(
        "inv-unknown",
        expires_at=expires_at,
        now=now + timedelta(seconds=4),
    )

    assert retry_after_recovery.allowed
    assert retry_after_recovery.permit is not None
    assert retry_after_recovery.permit.attempt == 2


def test_confirmed_side_effect_becomes_terminal_completed(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)
    now = _now()
    expires_at = now + timedelta(hours=1)

    claimed = store.claim(
        "inv-confirmed",
        expires_at=expires_at,
        now=now,
    )
    assert claimed.permit is not None

    assert store.mark_unknown(
        claimed.permit,
        now=now + timedelta(seconds=1),
    )

    assert store.reconcile_unknown(
        "inv-confirmed",
        outcome=(ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED),
        reason="provider confirms transaction",
        now=now + timedelta(seconds=2),
    )

    record = store.get("inv-confirmed")

    assert record is not None
    assert record.state is ExecutionState.COMPLETED
    assert record.recovery_count == 1
    assert record.recovery_outcome is ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED

    replay = store.claim(
        "inv-confirmed",
        expires_at=expires_at,
        now=now + timedelta(seconds=3),
    )

    assert not replay.allowed


def test_stale_claim_is_quarantined_as_unknown(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)
    now = _now()

    claimed = store.claim(
        "inv-stale",
        expires_at=now + timedelta(hours=1),
        now=now,
    )

    assert claimed.allowed

    assert not store.mark_stale_claim_unknown(
        "inv-stale",
        stale_after=timedelta(minutes=5),
        now=now + timedelta(minutes=4),
    )

    assert store.mark_stale_claim_unknown(
        "inv-stale",
        stale_after=timedelta(minutes=5),
        now=now + timedelta(minutes=5),
    )

    record = store.get("inv-stale")

    assert record is not None
    assert record.state is ExecutionState.UNKNOWN


def test_concurrent_reconciliation_has_one_winner(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)
    now = _now()

    claimed = store.claim(
        "inv-recovery-race",
        expires_at=now + timedelta(hours=1),
        now=now,
    )

    assert claimed.permit is not None

    assert store.mark_unknown(
        claimed.permit,
        now=now + timedelta(seconds=1),
    )

    barrier = Barrier(2)

    def reconcile(
        outcome: ExecutionRecoveryOutcome,
    ) -> bool:
        worker_store = PostgresExecutionStore(pool)
        barrier.wait()

        return worker_store.reconcile_unknown(
            "inv-recovery-race",
            outcome=outcome,
            reason=f"trusted result: {outcome.value}",
            now=now + timedelta(seconds=2),
        )

    outcomes = [
        ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED,
        ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED,
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                reconcile,
                outcomes,
            )
        )

    assert sum(results) == 1

    record = store.get("inv-recovery-race")

    assert record is not None
    assert record.recovery_count == 1
    assert record.state in {
        ExecutionState.AVAILABLE,
        ExecutionState.COMPLETED,
    }


def test_cancel_requires_current_permit(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)
    now = _now()

    claim = store.claim(
        "inv-cancel",
        expires_at=now + timedelta(hours=1),
        now=now,
    )

    assert claim.permit is not None

    assert store.cancel(
        claim.permit,
        reason="authorization revoked",
        now=now + timedelta(seconds=1),
    )

    assert not store.complete(
        claim.permit,
        now=now + timedelta(seconds=2),
    )

    record = store.get("inv-cancel")

    assert record is not None
    assert record.state is ExecutionState.CANCELLED
    assert record.cancel_reason == "authorization revoked"


def test_database_failure_propagates(
    pool,
) -> None:
    store = PostgresExecutionStore(pool)

    pool.close()

    with pytest.raises(Exception):
        store.get("inv-db-down")
