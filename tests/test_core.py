from datetime import datetime, timedelta, timezone

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


NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


def task() -> TaskContext:
    return TaskContext(
        task_id="t1",
        initiated_by="user-1",
        purpose="billing support",
        expires_at=NOW + timedelta(minutes=30),
    )


def policy_store() -> StaticPolicyStore:
    return StaticPolicyStore(
        [
            PolicyRule(
                policy_id="allow-small-refund",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"issue_refund"}),
                principal_ids=frozenset({"billing-agent"}),
                resource_prefixes=("customer:123",),
                condition=lambda req: req.arguments["amount"] <= 500,
                reason="small refund allowed",
            ),
            PolicyRule(
                policy_id="approve-medium-refund",
                effect=DecisionEffect.REQUIRE_APPROVAL,
                actions=frozenset({"issue_refund"}),
                principal_ids=frozenset({"billing-agent"}),
                resource_prefixes=("customer:123",),
                condition=lambda req: 500 < req.arguments["amount"] <= 1000,
                reason="manager approval required",
                obligations=("manager_approval",),
            ),
        ]
    )


def grant(grantor: str, grantee: str, amount: float = 1000) -> DelegationGrant:
    return DelegationGrant(
        grant_id=f"{grantor}-{grantee}",
        grantor_id=grantor,
        grantee_id=grantee,
        scope=Scope(
            actions=frozenset({"issue_refund"}),
            resource_prefixes=("customer:123",),
            max_numeric_arguments={"amount": amount},
        ),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=20),
    )


def request(amount: float, chain: tuple[DelegationGrant, ...]) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": amount},
        task=task(),
        delegation_chain=chain,
    )


def test_default_deny() -> None:
    gate = Ruhusa()
    decision = gate.authorize(
        AuthorizationRequest(
            principal=Principal("agent-1"),
            action="read_record",
            resource="record:1",
            arguments={},
            task=task(),
        ),
        now=NOW,
    )
    assert decision.effect == DecisionEffect.DENY
    assert "default deny" in decision.reason


def test_allowed_action() -> None:
    chain = (grant("user-1", "billing-agent"),)
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(request(250, chain), now=NOW)
    assert decision.effect == DecisionEffect.ALLOW


def test_human_approval() -> None:
    chain = (grant("user-1", "billing-agent"),)
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(request(750, chain), now=NOW)
    assert decision.effect == DecisionEffect.REQUIRE_APPROVAL
    assert "manager_approval" in decision.obligations


def test_privilege_amplification_is_denied() -> None:
    chain = (
        grant("user-1", "supervisor-agent", amount=500),
        grant("supervisor-agent", "billing-agent", amount=1000),
    )
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(request(250, chain), now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "exceeds parent scope" in decision.reason


def test_argument_scope_is_enforced() -> None:
    chain = (grant("user-1", "billing-agent", amount=500),)
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(request(750, chain), now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "arguments exceed delegated scope" in decision.reason


def test_audit_chain_verifies() -> None:
    chain = (grant("user-1", "billing-agent"),)
    gate = Ruhusa(policy_store=policy_store())
    gate.authorize(request(250, chain), now=NOW)
    gate.authorize(request(750, chain), now=NOW)
    assert gate.audit_log.verify_chain() is True


def test_resource_scope_cannot_widen() -> None:
    parent = grant("user-1", "supervisor-agent")
    child = DelegationGrant(
        grant_id="bad-resource-grant",
        grantor_id="supervisor-agent",
        grantee_id="billing-agent",
        scope=Scope(
            actions=frozenset({"issue_refund"}),
            resource_prefixes=(),
            max_numeric_arguments={"amount": 1000},
        ),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=20),
    )
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(request(250, (parent, child)), now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "exceeds parent scope" in decision.reason


def test_wrong_principal_does_not_match_policy() -> None:
    gate = Ruhusa(policy_store=policy_store())
    req = AuthorizationRequest(
        principal=Principal("claims-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task(),
    )
    decision = gate.authorize(req, now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "default deny" in decision.reason
