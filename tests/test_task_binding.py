"""
tests/test_task_binding.py

Proves that DelegationGrant.task_id is enforced as a security control:
a grant bound to task-A cannot be replayed to authorize action under task-B,
even if every other field (grantor, grantee, scope, timestamps) is identical.
"""

from datetime import UTC, datetime, timedelta

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    DelegationGrant,
    PolicyRule,
    Principal,
    Ruhusa,
    Scope,
    StaticPolicyStore,
    TaskContext,
)

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)

SCOPE = Scope(
    actions=frozenset({"issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 500},
)


def make_task(task_id: str, initiated_by: str = "user-1") -> TaskContext:
    return TaskContext(
        task_id=task_id,
        initiated_by=initiated_by,
        purpose="billing support",
        expires_at=NOW + timedelta(hours=1),
    )


def make_grant(
    grant_id: str,
    grantor_id: str,
    grantee_id: str,
    task_id: str,
    scope: Scope = SCOPE,
) -> DelegationGrant:
    return DelegationGrant(
        grant_id=grant_id,
        grantor_id=grantor_id,
        grantee_id=grantee_id,
        task_id=task_id,
        scope=scope,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=30),
    )


def policy_store() -> StaticPolicyStore:
    return StaticPolicyStore(
        [
            PolicyRule(
                policy_id="allow-refund",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"issue_refund"}),
                principal_ids=frozenset({"billing-agent"}),
                resource_prefixes=("customer:123",),
                condition=lambda req: req.arguments["amount"] <= 500,
                reason="refund allowed",
            )
        ]
    )


# ---------------------------------------------------------------------------
# Case 1: grant task_id matches request task_id → ALLOW
# ---------------------------------------------------------------------------


def test_grant_bound_to_correct_task_is_allowed() -> None:
    """A grant whose task_id equals the request's task.task_id must succeed."""
    grant = make_grant("g1", "user-1", "billing-agent", task_id="task-A")
    task = make_task("task-A")

    req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invoking_principal_id="user-1",
    )

    decision = Ruhusa(policy_store=policy_store()).authorize(req, now=NOW)
    assert decision.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Case 2: same grant replayed under a different task → DENY
# ---------------------------------------------------------------------------


def test_grant_replayed_under_different_task_is_denied() -> None:
    """
    Replay-prevention core test:
    The grant was issued for task-A. Presenting it in a request for task-B
    must be denied even though all other fields are valid.
    """
    grant = make_grant("g1", "user-1", "billing-agent", task_id="task-A")
    task_b = make_task("task-B")

    req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task_b,
        delegation_chain=(grant,),
    )

    decision = Ruhusa(policy_store=policy_store()).authorize(req, now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "bound to a different task" in decision.reason


# ---------------------------------------------------------------------------
# Case 3: multi-hop chain, every grant carries the same task_id → ALLOW
# ---------------------------------------------------------------------------


def test_multi_hop_chain_same_task_is_allowed() -> None:
    """
    A two-hop chain where both grants carry task_id="task-A" and the
    request is also for task-A must be approved.
    """
    supervisor_scope = Scope(
        actions=frozenset({"issue_refund"}),
        resource_prefixes=("customer:123",),
        max_numeric_arguments={"amount": 500},
    )
    billing_scope = Scope(
        actions=frozenset({"issue_refund"}),
        resource_prefixes=("customer:123",),
        max_numeric_arguments={"amount": 300},
    )

    g1 = make_grant("g1", "user-1", "supervisor-agent", task_id="task-A", scope=supervisor_scope)
    g2 = make_grant(
        "g2", "supervisor-agent", "billing-agent", task_id="task-A", scope=billing_scope
    )
    task = make_task("task-A")

    req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(g1, g2),
        invoking_principal_id="supervisor-agent",
    )

    decision = Ruhusa(policy_store=policy_store()).authorize(req, now=NOW)
    assert decision.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Case 4: multi-hop chain, second grant carries wrong task_id → DENY
# ---------------------------------------------------------------------------


def test_multi_hop_chain_one_wrong_task_is_denied() -> None:
    """
    A two-hop chain where the first grant is correctly bound to task-A
    but the second grant was issued for task-B (a cross-task splice).
    The chain must be rejected.
    """
    supervisor_scope = Scope(
        actions=frozenset({"issue_refund"}),
        resource_prefixes=("customer:123",),
        max_numeric_arguments={"amount": 500},
    )
    billing_scope = Scope(
        actions=frozenset({"issue_refund"}),
        resource_prefixes=("customer:123",),
        max_numeric_arguments={"amount": 300},
    )

    g1 = make_grant("g1", "user-1", "supervisor-agent", task_id="task-A", scope=supervisor_scope)
    # g2 was issued for a different task — this is the splice
    g2 = make_grant(
        "g2", "supervisor-agent", "billing-agent", task_id="task-B", scope=billing_scope
    )
    task = make_task("task-A")

    req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(g1, g2),
    )

    decision = Ruhusa(policy_store=policy_store()).authorize(req, now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "bound to a different task" in decision.reason
