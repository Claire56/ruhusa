from __future__ import annotations

import concurrent.futures
from datetime import UTC, datetime, timedelta

from ruhusa.approvals import ApprovalRecord, ApprovalState, InMemoryApprovalStore
from ruhusa.execution import ExecutionPermit


def test_concurrent_consumers_have_exactly_one_winner() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    store = InMemoryApprovalStore()
    store.create(ApprovalRecord("approval-1", "inv-1", "task-1", now, now + timedelta(minutes=5)))
    assert store.approve(
        "approval-1", approved_by="human:1", now=now + timedelta(seconds=1)
    ).allowed
    permits = [ExecutionPermit("inv-1", f"claim-{i}", i + 1) for i in range(20)]

    def consume(permit: ExecutionPermit) -> bool:
        return store.consume("approval-1", permit=permit, now=now + timedelta(seconds=2)).allowed

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(consume, permits))
    assert sum(results) == 1
    record = store.get("approval-1")
    assert record is not None and record.state is ApprovalState.CONSUMED
    assert record.consumed_claim_id is not None and record.consumed_attempt is not None


def test_concurrent_approve_and_reject_have_one_terminal_winner() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    store = InMemoryApprovalStore()
    store.create(ApprovalRecord("approval-1", "inv-1", "task-1", now, now + timedelta(minutes=5)))

    def approve() -> bool:
        return store.approve(
            "approval-1", approved_by="human:approver", now=now + timedelta(seconds=1)
        ).allowed

    def reject() -> bool:
        return store.reject(
            "approval-1", rejected_by="human:rejector", now=now + timedelta(seconds=1)
        ).allowed

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = [executor.submit(approve).result(), executor.submit(reject).result()]
    assert sum(results) == 1
    record = store.get("approval-1")
    assert record is not None and record.state in {ApprovalState.APPROVED, ApprovalState.REJECTED}
