"""v0.6-C idempotency and recovery attack tests.

These tests verify that crash recovery remains fail closed:

- stale CLAIMED work becomes UNKNOWN, never automatically retryable;
- a live claim cannot be stolen before the stale threshold;
- UNKNOWN can only become COMPLETED or AVAILABLE through trusted reconciliation;
- confirmed external side effects permanently consume execution authority;
- retry is allowed only after positive confirmation that no side effect occurred;
- terminal states cannot be resurrected;
- concurrent reconciliation has exactly one winner;
- stale permits cannot mutate a recovered/fresh attempt.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from ruhusa import (
    ExecutionPermit,
    ExecutionRecoveryOutcome,
    ExecutionState,
    InMemoryExecutionStore,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
EXPIRY = NOW + timedelta(hours=1)
INVOCATION_ID = "inv-recovery-001"


def claimed_store(
    invocation_id: str = INVOCATION_ID,
) -> tuple[InMemoryExecutionStore, ExecutionPermit]:
    store = InMemoryExecutionStore()
    claim = store.claim(
        invocation_id,
        expires_at=EXPIRY,
        now=NOW,
    )

    assert claim.allowed is True
    assert claim.permit is not None

    return store, claim.permit


def test_stale_claim_moves_to_unknown_not_available() -> None:
    store, _ = claimed_store()

    recovered = store.mark_stale_claim_unknown(
        INVOCATION_ID,
        stale_after=timedelta(seconds=30),
        now=NOW + timedelta(seconds=31),
    )

    assert recovered is True

    record = store.get(INVOCATION_ID)
    assert record is not None
    assert record.state == ExecutionState.UNKNOWN

    retry = store.claim(
        INVOCATION_ID,
        expires_at=EXPIRY,
        now=NOW + timedelta(seconds=32),
    )

    assert retry.allowed is False
    assert "already unknown" in retry.reason


def test_live_claim_is_not_recovered_early() -> None:
    store, _ = claimed_store()

    recovered = store.mark_stale_claim_unknown(
        INVOCATION_ID,
        stale_after=timedelta(minutes=5),
        now=NOW + timedelta(minutes=4),
    )

    assert recovered is False

    record = store.get(INVOCATION_ID)
    assert record is not None
    assert record.state == ExecutionState.CLAIMED


def test_unknown_confirmed_side_effect_becomes_completed() -> None:
    store, permit = claimed_store()

    assert store.mark_unknown(
        permit,
        now=NOW + timedelta(seconds=1),
    )

    reconciled = store.reconcile_unknown(
        INVOCATION_ID,
        outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED,
        reason="payment provider confirms refund transaction exists",
        now=NOW + timedelta(seconds=2),
    )

    assert reconciled is True

    record = store.get(INVOCATION_ID)
    assert record is not None
    assert record.state == ExecutionState.COMPLETED
    assert record.recovery_outcome == ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED
    assert record.recovery_count == 1

    replay = store.claim(
        INVOCATION_ID,
        expires_at=EXPIRY,
        now=NOW + timedelta(seconds=3),
    )

    assert replay.allowed is False
    assert "already completed" in replay.reason


def test_confirmed_not_applied_allows_fresh_claim() -> None:
    store, first_permit = claimed_store()

    assert store.mark_unknown(
        first_permit,
        now=NOW + timedelta(seconds=1),
    )

    reconciled = store.reconcile_unknown(
        INVOCATION_ID,
        outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED,
        reason="provider confirms no transaction exists for invocation",
        now=NOW + timedelta(seconds=2),
    )

    assert reconciled is True

    record = store.get(INVOCATION_ID)
    assert record is not None
    assert record.state == ExecutionState.AVAILABLE
    assert record.claim_id is None
    assert record.recovery_count == 1

    second = store.claim(
        INVOCATION_ID,
        expires_at=EXPIRY,
        now=NOW + timedelta(seconds=3),
    )

    assert second.allowed is True
    assert second.permit is not None
    assert second.permit.attempt == 2
    assert second.permit.claim_id != first_permit.claim_id


def test_reconciliation_only_accepts_unknown_state() -> None:
    store, permit = claimed_store()

    # A live CLAIMED invocation cannot be reconciled around its current owner.
    assert (
        store.reconcile_unknown(
            INVOCATION_ID,
            outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED,
            reason="attempt to reset active claim",
            now=NOW + timedelta(seconds=1),
        )
        is False
    )

    assert store.complete(
        permit,
        now=NOW + timedelta(seconds=2),
    )

    # COMPLETED is terminal and cannot be resurrected.
    assert (
        store.reconcile_unknown(
            INVOCATION_ID,
            outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED,
            reason="attempt to resurrect completed invocation",
            now=NOW + timedelta(seconds=3),
        )
        is False
    )

    record = store.get(INVOCATION_ID)
    assert record is not None
    assert record.state == ExecutionState.COMPLETED


def test_concurrent_reconciliation_has_one_winner() -> None:
    store, permit = claimed_store()

    assert store.mark_unknown(
        permit,
        now=NOW + timedelta(seconds=1),
    )

    def reconcile() -> bool:
        return store.reconcile_unknown(
            INVOCATION_ID,
            outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED,
            reason="trusted reconciliation result",
            now=NOW + timedelta(seconds=2),
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: reconcile(), range(32)))

    assert sum(results) == 1

    record = store.get(INVOCATION_ID)
    assert record is not None
    assert record.state == ExecutionState.COMPLETED
    assert record.recovery_count == 1


def test_old_permit_cannot_mutate_recovered_attempt() -> None:
    store, first_permit = claimed_store()

    assert store.mark_unknown(
        first_permit,
        now=NOW + timedelta(seconds=1),
    )

    assert store.reconcile_unknown(
        INVOCATION_ID,
        outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED,
        reason="external system confirms request never executed",
        now=NOW + timedelta(seconds=2),
    )

    second = store.claim(
        INVOCATION_ID,
        expires_at=EXPIRY,
        now=NOW + timedelta(seconds=3),
    )

    assert second.allowed is True
    assert second.permit is not None

    # Attempt 1 must never be able to complete or corrupt attempt 2.
    assert (
        store.complete(
            first_permit,
            now=NOW + timedelta(seconds=4),
        )
        is False
    )
    assert (
        store.mark_unknown(
            first_permit,
            now=NOW + timedelta(seconds=4),
        )
        is False
    )

    record = store.get(INVOCATION_ID)
    assert record is not None
    assert record.state == ExecutionState.CLAIMED
    assert record.claim_id == second.permit.claim_id
    assert record.attempt_count == 2


def test_stale_recovery_requires_positive_window() -> None:
    store, _ = claimed_store()

    with pytest.raises(ValueError, match="stale_after"):
        store.mark_stale_claim_unknown(
            INVOCATION_ID,
            stale_after=timedelta(0),
            now=NOW + timedelta(seconds=1),
        )


def test_reconciliation_requires_nonempty_reason() -> None:
    store, permit = claimed_store()

    assert store.mark_unknown(
        permit,
        now=NOW + timedelta(seconds=1),
    )

    with pytest.raises(ValueError, match="reason"):
        store.reconcile_unknown(
            INVOCATION_ID,
            outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED,
            reason="   ",
            now=NOW + timedelta(seconds=2),
        )

    record = store.get(INVOCATION_ID)
    assert record is not None
    assert record.state == ExecutionState.UNKNOWN
