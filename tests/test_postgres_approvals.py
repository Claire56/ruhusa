from __future__ import annotations

import concurrent.futures
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

pytestmark = pytest.mark.postgres

psycopg_pool = pytest.importorskip("psycopg_pool")

from ruhusa.approvals import ApprovalRecord, ApprovalState  # noqa: E402
from ruhusa.execution import ExecutionPermit  # noqa: E402
from ruhusa.invocations import InvocationRecord, compute_arguments_digest  # noqa: E402
from ruhusa.postgres import (  # noqa: E402
    PostgresApprovalStore,
    PostgresInvocationStore,
    create_postgres_pool,
    initialize_postgres_schema,
)


def _dsn() -> str:
    value = os.environ.get("RUHUSA_TEST_POSTGRES_DSN")
    if not value:
        pytest.skip("RUHUSA_TEST_POSTGRES_DSN is not set")
    return value


def _stores():
    pool = create_postgres_pool(_dsn(), min_size=1, max_size=24)
    initialize_postgres_schema(pool)
    return pool, PostgresInvocationStore(pool), PostgresApprovalStore(pool)


def _register_invocation(store: PostgresInvocationStore, now: datetime) -> str:
    invocation_id = f"inv-{uuid4().hex}"
    store.register(
        InvocationRecord(
            invocation_id=invocation_id,
            invoking_principal_id="gateway",
            executing_principal_id="agent-1",
            task_id=f"task-{uuid4().hex}",
            action="refund",
            resource="account/123",
            arguments_digest=compute_arguments_digest({"amount": 50}),
            tool_id="refund-tool",
            implementation_id="refund-tool@sha256:test",
            recorded_at=now,
            expires_at=now + timedelta(minutes=10),
        )
    )
    return invocation_id


def _approval(
    invocation_id: str,
    now: datetime,
    *,
    approval_id: str | None = None,
) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=approval_id or f"approval-{uuid4().hex}",
        invocation_id=invocation_id,
        task_id=f"task-{uuid4().hex}",
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def test_postgres_approval_round_trip_and_single_use() -> None:
    now = datetime.now(UTC)
    pool, invocations, approvals = _stores()
    try:
        invocation_id = _register_invocation(invocations, now)
        created = approvals.create(_approval(invocation_id, now))

        approved = approvals.approve(
            created.approval_id,
            approved_by="human:reviewer",
            now=now + timedelta(seconds=1),
        )
        assert approved.allowed is True
        assert approved.record is not None
        assert approved.record.state is ApprovalState.APPROVED

        permit = ExecutionPermit(
            invocation_id=invocation_id,
            claim_id=f"claim-{uuid4().hex}",
            attempt=1,
        )
        consumed = approvals.consume(
            created.approval_id,
            permit=permit,
            now=now + timedelta(seconds=2),
        )
        assert consumed.allowed is True
        assert consumed.record is not None
        assert consumed.record.state is ApprovalState.CONSUMED

        replay = approvals.consume(
            created.approval_id,
            permit=permit,
            now=now + timedelta(seconds=3),
        )
        assert replay.allowed is False
        assert replay.record is not None
        assert replay.record.state is ApprovalState.CONSUMED
    finally:
        pool.close()


def test_postgres_enforces_one_active_approval_per_invocation() -> None:
    now = datetime.now(UTC)
    pool, invocations, approvals = _stores()
    try:
        invocation_id = _register_invocation(invocations, now)
        first = approvals.create(_approval(invocation_id, now))

        with pytest.raises(ValueError, match="active approval"):
            approvals.create(_approval(invocation_id, now))

        rejected = approvals.reject(
            first.approval_id,
            rejected_by="human:reviewer",
            now=now + timedelta(seconds=1),
        )
        assert rejected.allowed is True

        second = approvals.create(_approval(invocation_id, now))
        assert second.state is ApprovalState.PENDING
    finally:
        pool.close()


def test_postgres_concurrent_consumers_have_exactly_one_winner() -> None:
    now = datetime.now(UTC)
    pool, invocations, approvals = _stores()
    try:
        invocation_id = _register_invocation(invocations, now)
        created = approvals.create(_approval(invocation_id, now))
        assert approvals.approve(
            created.approval_id,
            approved_by="human:reviewer",
            now=now + timedelta(seconds=1),
        ).allowed

        permits = [
            ExecutionPermit(
                invocation_id=invocation_id,
                claim_id=f"claim-{index}-{uuid4().hex}",
                attempt=index + 1,
            )
            for index in range(20)
        ]

        def consume(permit: ExecutionPermit) -> bool:
            return approvals.consume(
                created.approval_id,
                permit=permit,
                now=now + timedelta(seconds=2),
            ).allowed

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(consume, permits))

        assert sum(results) == 1
        final = approvals.get(created.approval_id)
        assert final is not None
        assert final.state is ApprovalState.CONSUMED
        assert final.consumed_claim_id is not None
        assert final.consumed_attempt is not None
    finally:
        pool.close()


def test_postgres_cross_invocation_replay_is_blocked() -> None:
    now = datetime.now(UTC)
    pool, invocations, approvals = _stores()
    try:
        invocation_id = _register_invocation(invocations, now)
        attacker_invocation_id = _register_invocation(invocations, now)
        created = approvals.create(_approval(invocation_id, now))
        assert approvals.approve(
            created.approval_id,
            approved_by="human:reviewer",
            now=now + timedelta(seconds=1),
        ).allowed

        result = approvals.consume(
            created.approval_id,
            permit=ExecutionPermit(
                invocation_id=attacker_invocation_id,
                claim_id=f"claim-{uuid4().hex}",
                attempt=1,
            ),
            now=now + timedelta(seconds=2),
        )

        assert result.allowed is False
        assert result.reason == "approval is bound to a different invocation"
        assert result.record is not None
        assert result.record.state is ApprovalState.APPROVED
    finally:
        pool.close()
