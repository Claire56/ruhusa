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


now = datetime.now(timezone.utc)

policies = StaticPolicyStore(
    [
        PolicyRule(
            policy_id="refund-auto-small",
            effect=DecisionEffect.ALLOW,
            actions=frozenset({"issue_refund"}),
            principal_ids=frozenset({"billing-agent"}),
            resource_prefixes=("customer:123",),
            condition=lambda req: float(req.arguments.get("amount", 0)) <= 500,
            reason="refund is within autonomous threshold",
        ),
        PolicyRule(
            policy_id="refund-manager-approval",
            effect=DecisionEffect.REQUIRE_APPROVAL,
            actions=frozenset({"issue_refund"}),
            principal_ids=frozenset({"billing-agent"}),
            resource_prefixes=("customer:123",),
            condition=lambda req: 500 < float(req.arguments.get("amount", 0)) <= 1000,
            reason="refund requires human approval",
            obligations=("manager_approval",),
        ),
    ]
)

gate = Ruhusa(policy_store=policies)

root_scope = Scope(
    actions=frozenset({"read_invoice", "issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 1000},
)

billing_scope = Scope(
    actions=frozenset({"read_invoice", "issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 1000},
)

request = AuthorizationRequest(
    principal=Principal("billing-agent"),
    action="issue_refund",
    resource="customer:123:billing",
    arguments={"amount": 750},
    task=TaskContext(
        task_id="task-001",
        initiated_by="user-42",
        purpose="resolve disputed invoice",
        expires_at=now + timedelta(minutes=15),
    ),
    delegation_chain=(
        DelegationGrant(
            grant_id="grant-user-supervisor",
            grantor_id="user-42",
            grantee_id="supervisor-agent",
            scope=root_scope,
            issued_at=now,
            expires_at=now + timedelta(minutes=15),
        ),
        DelegationGrant(
            grant_id="grant-supervisor-billing",
            grantor_id="supervisor-agent",
            grantee_id="billing-agent",
            scope=billing_scope,
            issued_at=now,
            expires_at=now + timedelta(minutes=10),
        ),
    ),
)

decision = gate.authorize(request)
print(f"{decision.effect.value} - {decision.reason}")
print(f"audit_id={decision.audit_id}")
