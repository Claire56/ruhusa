from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ruhusa.approvals import ApprovalController, InMemoryApprovalStore
from ruhusa.execution import ExecutionPermit
from ruhusa.invocations import InMemoryInvocationStore, InvocationRecord, compute_arguments_digest
from ruhusa.models import (
    AuthorizationDecision,
    AuthorizationRequest,
    DecisionEffect,
    Principal,
    TaskContext,
)


def _controller_and_request(now: datetime):
    invocations = InMemoryInvocationStore()
    approvals = InMemoryApprovalStore()
    controller = ApprovalController(approval_store=approvals, invocation_store=invocations)
    invocations.register(
        InvocationRecord(
            invocation_id="inv-original",
            invoking_principal_id="gateway",
            executing_principal_id="agent-1",
            task_id="task-1",
            action="refund",
            resource="account/1",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id="refund-tool",
            implementation_id="refund-tool@sha256:1",
            recorded_at=now,
            expires_at=now + timedelta(minutes=10),
        )
    )
    request = AuthorizationRequest(
        principal=Principal("agent-1"),
        action="refund",
        resource="account/1",
        arguments={"amount": 250},
        task=TaskContext(
            task_id="task-1",
            initiated_by="user-1",
            purpose="refund",
            expires_at=now + timedelta(minutes=10),
        ),
        invocation_id="inv-original",
    )
    decision = AuthorizationDecision(DecisionEffect.REQUIRE_APPROVAL, "approval required")
    return controller, approvals, request, decision


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("principal", Principal("attacker"), "principal"),
        ("action", "delete", "action"),
        ("resource", "account/other", "resource"),
        ("arguments", {"amount": 999}, "arguments"),
    ],
)
def test_approval_request_rejects_substitution(field: str, value, match: str) -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, _, request, decision = _controller_and_request(now)
    values = {
        "principal": request.principal,
        "action": request.action,
        "resource": request.resource,
        "arguments": request.arguments,
        "task": request.task,
        "invocation_id": request.invocation_id,
    }
    values[field] = value
    mutated = AuthorizationRequest(**values)
    with pytest.raises(ValueError, match=match):
        controller.request(request=mutated, decision=decision, now=now)


def test_cross_invocation_approval_replay_is_blocked() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, store, request, decision = _controller_and_request(now)
    approval = controller.request(
        request=request, decision=decision, approval_id="approval-1", now=now
    )
    assert store.approve(
        approval.approval_id, approved_by="human:1", now=now + timedelta(seconds=1)
    ).allowed
    with pytest.raises(PermissionError, match="different invocation"):
        controller.require_approved(
            approval.approval_id, invocation_id="inv-attacker", now=now + timedelta(seconds=2)
        )
    result = store.consume(
        approval.approval_id,
        permit=ExecutionPermit("inv-attacker", "claim-attacker", 1),
        now=now + timedelta(seconds=2),
    )
    assert result.allowed is False
    assert result.reason == "approval is bound to a different invocation"


def test_consumed_approval_cannot_be_revoked_or_reapproved() -> None:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
    controller, store, request, decision = _controller_and_request(now)
    approval = controller.request(
        request=request, decision=decision, approval_id="approval-1", now=now
    )
    assert store.approve(
        approval.approval_id, approved_by="human:1", now=now + timedelta(seconds=1)
    ).allowed
    assert store.consume(
        approval.approval_id,
        permit=ExecutionPermit("inv-original", "claim-1", 1),
        now=now + timedelta(seconds=2),
    ).allowed
    assert not store.revoke(
        approval.approval_id, revoked_by="human:1", now=now + timedelta(seconds=3)
    ).allowed
    assert not store.approve(
        approval.approval_id, approved_by="human:1", now=now + timedelta(seconds=3)
    ).allowed
