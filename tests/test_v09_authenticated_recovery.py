"""v0.9-D signed recovery evidence: no unverified release of UNKNOWN."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from ruhusa import ExecutionRecoveryOutcome, ExecutionState, InMemoryExecutionStore
from ruhusa.recovery_evidence import (
    AuthenticatedRecoveryService,
    InMemoryRecoveryEvidenceReplayStore,
    RecoveryEvidence,
    RecoveryEvidenceVerifier,
    sign_recovery_evidence,
)

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
KEY = b"trusted-reconciler-test-key-with-32-bytes-minimum"


def setup(outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED):
    store = InMemoryExecutionStore()
    result = store.claim("inv-1", expires_at=NOW + timedelta(hours=1), now=NOW)
    assert result.permit is not None
    assert store.mark_unknown(result.permit, now=NOW + timedelta(seconds=1))
    evidence = RecoveryEvidence(
        evidence_id="receipt-1",
        issuer="reconciler-payments",
        key_id="2026-rotation-a",
        invocation_id="inv-1",
        claim_id=result.permit.claim_id,
        attempt=result.permit.attempt,
        outcome=outcome,
        reason="provider confirms outcome for transaction 123",
        issued_at=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(minutes=2),
        signature="",
    )
    evidence = sign_recovery_evidence(evidence, key=KEY)
    replay = InMemoryRecoveryEvidenceReplayStore()
    service = AuthenticatedRecoveryService(
        store,
        RecoveryEvidenceVerifier({("reconciler-payments", "2026-rotation-a"): KEY}),
        replay,
    )
    return store, evidence, service


def test_signed_not_applied_makes_available_for_fresh_authorization():
    store, evidence, service = setup()
    assert service.reconcile(evidence, now=NOW + timedelta(seconds=3))
    assert store.get("inv-1").state is ExecutionState.AVAILABLE
    assert store.claim(
        "inv-1", expires_at=NOW + timedelta(hours=1), now=NOW + timedelta(seconds=4)
    ).allowed


def test_signed_confirmed_permanently_completes():
    store, evidence, service = setup(ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED)
    assert service.reconcile(evidence, now=NOW + timedelta(seconds=3))
    assert store.get("inv-1").state is ExecutionState.COMPLETED
    assert not store.claim(
        "inv-1", expires_at=NOW + timedelta(hours=1), now=NOW + timedelta(seconds=4)
    ).allowed


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "agent"},
        {"key_id": "fake"},
        {"invocation_id": "inv-other"},
        {"claim_id": "forged-claim"},
        {"attempt": 99},
        {"outcome": ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED},
        {"reason": "agent says it failed"},
        {"signature": "0" * 64},
    ],
)
def test_forged_or_tampered_evidence_fails_closed(change):
    store, evidence, service = setup()
    assert not service.reconcile(replace(evidence, **change), now=NOW + timedelta(seconds=3))
    assert store.get("inv-1").state is ExecutionState.UNKNOWN


def test_expired_and_future_evidence_fail_closed():
    store, evidence, service = setup()
    assert not service.reconcile(evidence, now=NOW + timedelta(minutes=3))
    assert not service.reconcile(evidence, now=NOW)
    assert store.get("inv-1").state is ExecutionState.UNKNOWN


def test_invalid_attempt_signed_by_trusted_key_is_rejected():
    store, evidence, service = setup()
    forged = sign_recovery_evidence(replace(evidence, claim_id="other", signature=""), key=KEY)
    assert not service.reconcile(forged, now=NOW + timedelta(seconds=3))
    assert store.get("inv-1").state is ExecutionState.UNKNOWN


def test_replay_and_concurrent_reconciliation_only_one_winner():
    store, evidence, service = setup()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: service.reconcile(evidence, now=NOW + timedelta(seconds=3)), range(8)
            )
        )
    assert sum(results) == 1
    assert not service.reconcile(evidence, now=NOW + timedelta(seconds=4))
    assert store.get("inv-1").state is ExecutionState.AVAILABLE


def test_wrong_key_rejected():
    store, evidence, service = setup()
    alternate = sign_recovery_evidence(
        replace(evidence, signature=""), key=b"another-signing-key-long-enough-to-work"
    )
    assert not service.reconcile(alternate, now=NOW + timedelta(seconds=3))
    assert store.get("inv-1").state is ExecutionState.UNKNOWN


def test_reconciliation_backend_failure_never_releases_unknown():
    store, evidence, _ = setup()

    class BrokenStore:
        def get(self, invocation_id):
            return store.get(invocation_id)

        def reconcile_unknown(self, *args, **kwargs):
            raise RuntimeError("database unavailable")

    service = AuthenticatedRecoveryService(
        BrokenStore(),
        RecoveryEvidenceVerifier({("reconciler-payments", "2026-rotation-a"): KEY}),
        InMemoryRecoveryEvidenceReplayStore(),
    )
    with pytest.raises(RuntimeError, match="database unavailable"):
        service.reconcile(evidence, now=NOW + timedelta(seconds=3))
    assert store.get("inv-1").state is ExecutionState.UNKNOWN
