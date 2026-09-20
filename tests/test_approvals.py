from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ruhusa.approvals import ApprovalController, ApprovalState, InMemoryApprovalStore
from ruhusa.execution import ExecutionPermit
from ruhusa.invocations import InMemoryInvocationStore, InvocationRecord, compute_arguments_digest
from ruhusa.models import (
    AuthorizationDecision,
    AuthorizationRequest,
    DecisionEffect,
    Principal,
    TaskContext,
)


def _fixture(now: datetime):
    invocations = InMemoryInvocationStore()
    approvals = InMemoryApprovalStore()
    controller = ApprovalController(approval_store=approvals, invocation_store=invocations)
    invocation = InvocationRecord(
        invocation_id="inv-1",
        invoking_principal_id="gateway",
        executing_principal_id="billing-agent",
        task_id="task-1",
        action="refund",
        resource="account/123",
        arguments_digest=compute_arguments_digest({"amount": 500}),
        tool_id="refund-tool",
        implementation_id="refund-tool@sha256:abc",
        recorded_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    invocations.register(invocation)
    request = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="refund",
        resource="account/123",
        arguments={"amount": 500},
        task=TaskContext(
            task_id="task-1",
            initiated_by="user-1",
            purpose="refund",
            expires_at=now + timedelta(minutes=20),
        ),
        invocation_id="inv-1",
    )
    decision = AuthorizationDecision(
        DecisionEffect.REQUIRE_APPROVAL, "human approval required", policy_id="refund-policy"
    )
    return controller, approvals, request, decision


def test_require_approval_creates_pending_record() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, store, request, decision = _fixture(now)
    approval = controller.request(
        request=request, decision=decision, approval_id="approval-1", now=now
    )
    assert approval.state is ApprovalState.PENDING
    assert approval.invocation_id == "inv-1"
    assert approval.task_id == "task-1"
    assert approval.expires_at == now + timedelta(minutes=10)
    assert store.get("approval-1") == approval


def test_only_require_approval_decision_can_create_approval() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, _, request, _ = _fixture(now)
    for effect in (DecisionEffect.ALLOW, DecisionEffect.DENY):
        with pytest.raises(ValueError, match="REQUIRE_APPROVAL"):
            controller.request(
                request=request, decision=AuthorizationDecision(effect, "test"), now=now
            )


def test_approval_cannot_outlive_invocation_or_task() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, _, request, decision = _fixture(now)
    with pytest.raises(ValueError, match="must not exceed"):
        controller.request(
            request=request, decision=decision, expires_at=now + timedelta(minutes=11), now=now
        )


def test_pending_can_be_approved_then_consumed_once() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, store, request, decision = _fixture(now)
    approval = controller.request(
        request=request, decision=decision, approval_id="approval-1", now=now
    )
    approved = store.approve(
        approval.approval_id, approved_by="human:claire", now=now + timedelta(seconds=1)
    )
    assert (
        approved.allowed is True
        and approved.record is not None
        and approved.record.state is ApprovalState.APPROVED
    )
    controller.require_approved(
        approval.approval_id, invocation_id="inv-1", now=now + timedelta(seconds=2)
    )
    permit = ExecutionPermit(invocation_id="inv-1", claim_id="claim-1", attempt=1)
    consumed = controller.consume_for_execution(
        approval.approval_id, permit=permit, now=now + timedelta(seconds=3)
    )
    assert consumed.state is ApprovalState.CONSUMED
    assert consumed.consumed_claim_id == "claim-1"
    assert consumed.consumed_attempt == 1
    with pytest.raises(PermissionError, match="consumed"):
        controller.consume_for_execution(
            approval.approval_id, permit=permit, now=now + timedelta(seconds=4)
        )


def test_rejected_approval_cannot_be_approved() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, store, request, decision = _fixture(now)
    approval = controller.request(
        request=request, decision=decision, approval_id="approval-1", now=now
    )
    rejected = store.reject(
        approval.approval_id, rejected_by="human:reviewer", now=now + timedelta(seconds=1)
    )
    assert (
        rejected.allowed is True
        and rejected.record is not None
        and rejected.record.state is ApprovalState.REJECTED
    )
    approve = store.approve(
        approval.approval_id, approved_by="human:reviewer", now=now + timedelta(seconds=2)
    )
    assert (
        approve.allowed is False
        and approve.record is not None
        and approve.record.state is ApprovalState.REJECTED
    )


def test_approved_approval_can_be_revoked_before_consumption() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, store, request, decision = _fixture(now)
    approval = controller.request(
        request=request, decision=decision, approval_id="approval-1", now=now
    )
    assert store.approve(
        approval.approval_id, approved_by="human:reviewer", now=now + timedelta(seconds=1)
    ).allowed
    revoked = store.revoke(
        approval.approval_id, revoked_by="human:reviewer", now=now + timedelta(seconds=2)
    )
    assert (
        revoked.allowed is True
        and revoked.record is not None
        and revoked.record.state is ApprovalState.REVOKED
    )
    with pytest.raises(PermissionError, match="revoked"):
        controller.require_approved(
            approval.approval_id, invocation_id="inv-1", now=now + timedelta(seconds=3)
        )


def test_expired_approval_fails_closed() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, store, request, decision = _fixture(now)
    approval = controller.request(
        request=request,
        decision=decision,
        approval_id="approval-1",
        expires_at=now + timedelta(seconds=5),
        now=now,
    )
    assert store.approve(
        approval.approval_id, approved_by="human:reviewer", now=now + timedelta(seconds=1)
    ).allowed
    with pytest.raises(PermissionError, match="expired"):
        controller.require_approved(
            approval.approval_id, invocation_id="inv-1", now=now + timedelta(seconds=5)
        )
    consume = store.consume(
        approval.approval_id,
        permit=ExecutionPermit("inv-1", "claim-1", 1),
        now=now + timedelta(seconds=6),
    )
    assert (
        consume.allowed is False
        and consume.record is not None
        and consume.record.state is ApprovalState.EXPIRED
    )
