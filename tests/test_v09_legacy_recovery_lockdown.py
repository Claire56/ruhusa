"""v0.9 default-deny enforcement for unsigned UNKNOWN reconciliation."""

from datetime import UTC, datetime, timedelta

import pytest

from ruhusa.execution import (
    ExecutionRecoveryOutcome,
    ExecutionState,
    InMemoryExecutionStore,
)

NOW = datetime(2026, 10, 28, tzinfo=UTC)


def test_in_memory_raw_reconciliation_is_disabled_by_default():
    store = InMemoryExecutionStore()
    claim = store.claim("default-deny", expires_at=NOW + timedelta(hours=1), now=NOW)
    assert claim.permit is not None
    assert store.mark_unknown(claim.permit, now=NOW + timedelta(seconds=1))

    with pytest.raises(PermissionError, match="Unsigned reconciliation is disabled"):
        store.reconcile_unknown(
            "default-deny",
            outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED,
            reason="agent claims no effect occurred",
            now=NOW + timedelta(seconds=2),
        )
    assert store.get("default-deny").state is ExecutionState.UNKNOWN
    assert not store.claim(
        "default-deny", expires_at=NOW + timedelta(hours=1), now=NOW + timedelta(seconds=3)
    ).allowed


def test_explicit_legacy_mode_is_not_the_default():
    store = InMemoryExecutionStore(allow_unsafe_legacy_reconciliation=True)
    claim = store.claim("legacy-test", expires_at=NOW + timedelta(hours=1), now=NOW)
    assert claim.permit is not None
    assert store.mark_unknown(claim.permit, now=NOW + timedelta(seconds=1))
    assert store.reconcile_unknown(
        "legacy-test",
        outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED,
        reason="trusted research fixture",
        now=NOW + timedelta(seconds=2),
    )
    assert store.get("legacy-test").state is ExecutionState.COMPLETED
