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
from ruhusa.revocation import InMemoryRevocationStore

NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)


def task() -> TaskContext:
    return TaskContext(
        task_id="revocation-task",
        initiated_by="user-1",
        purpose="billing support",
        expires_at=NOW + timedelta(hours=1),
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
            )
        ]
    )


def grant(
    grant_id: str = "grant-billing-1",
    *,
    grantor: str = "user-1",
    grantee: str = "billing-agent",
) -> DelegationGrant:
    return DelegationGrant(
        grant_id=grant_id,
        grantor_id=grantor,
        grantee_id=grantee,
        task_id="revocation-task",
        scope=Scope(
            actions=frozenset({"issue_refund"}),
            resource_prefixes=("customer:123",),
            max_numeric_arguments={"amount": 500},
        ),
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=30),
    )


def request(
    delegation_grant: DelegationGrant,
    *,
    amount: float = 250,
) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": amount},
        task=task(),
        delegation_chain=(delegation_grant,),
        invoking_principal_id=delegation_grant.grantor_id,
    )


def test_active_grant_allows_action() -> None:
    active_grant = grant()
    gate = Ruhusa(policy_store=policy_store())

    decision = gate.authorize(request(active_grant), now=NOW)

    assert decision.effect == DecisionEffect.ALLOW


def test_revoked_grant_is_denied() -> None:
    revoked_grant = grant()
    gate = Ruhusa(policy_store=policy_store())

    gate.revoke_grant(
        revoked_grant.grant_id,
        reason="user withdrew authority",
        revoked_at=NOW,
    )

    decision = gate.authorize(
        request(revoked_grant),
        now=NOW + timedelta(seconds=1),
    )

    assert decision.effect == DecisionEffect.DENY
    assert "revoked" in decision.reason
    assert decision.audit_id is not None


def test_mid_workflow_revocation_changes_allow_to_deny() -> None:
    workflow_grant = grant()
    gate = Ruhusa(policy_store=policy_store())

    before = gate.authorize(request(workflow_grant), now=NOW)
    assert before.effect == DecisionEffect.ALLOW

    gate.revoke_grant(
        workflow_grant.grant_id,
        reason="authority withdrawn during workflow",
        revoked_at=NOW + timedelta(minutes=1),
    )

    after = gate.authorize(
        request(workflow_grant),
        now=NOW + timedelta(minutes=2),
    )

    assert after.effect == DecisionEffect.DENY
    assert "revoked" in after.reason


def test_revoking_unrelated_grant_does_not_affect_active_grant() -> None:
    active_grant = grant("grant-billing-active")
    gate = Ruhusa(policy_store=policy_store())

    gate.revoke_grant(
        "some-other-grant",
        reason="unrelated authority withdrawn",
        revoked_at=NOW,
    )

    decision = gate.authorize(
        request(active_grant),
        now=NOW + timedelta(seconds=1),
    )

    assert decision.effect == DecisionEffect.ALLOW


def test_future_effective_revocation_allows_before_and_denies_after() -> None:
    workflow_grant = grant()
    gate = Ruhusa(policy_store=policy_store())

    gate.revoke_grant(
        workflow_grant.grant_id,
        reason="scheduled revocation",
        revoked_at=NOW + timedelta(minutes=10),
    )

    before_revocation = gate.authorize(
        request(workflow_grant),
        now=NOW + timedelta(minutes=5),
    )
    after_revocation = gate.authorize(
        request(workflow_grant),
        now=NOW + timedelta(minutes=11),
    )

    assert before_revocation.effect == DecisionEffect.ALLOW
    assert after_revocation.effect == DecisionEffect.DENY
    assert "revoked" in after_revocation.reason


def test_revocation_store_failure_fails_closed() -> None:
    class FailingRevocationStore(InMemoryRevocationStore):
        def is_revoked(
            self,
            grant_id: str,
            *,
            at: datetime | None = None,
        ) -> bool:
            raise RuntimeError("revocation backend unavailable")

    active_grant = grant()
    gate = Ruhusa(
        policy_store=policy_store(),
        revocation_store=FailingRevocationStore(),
    )

    decision = gate.authorize(request(active_grant), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert decision.reason == "revocation status unavailable; default deny"
    assert decision.audit_id is not None


def test_earlier_revocation_supersedes_later_scheduled_revocation() -> None:
    workflow_grant = grant()
    gate = Ruhusa(policy_store=policy_store())

    scheduled = gate.revoke_grant(
        workflow_grant.grant_id,
        reason="scheduled revocation",
        revoked_at=NOW + timedelta(minutes=10),
    )

    before_emergency = gate.authorize(
        request(workflow_grant),
        now=NOW + timedelta(minutes=1),
    )

    emergency = gate.revoke_grant(
        workflow_grant.grant_id,
        reason="emergency revocation",
        revoked_at=NOW + timedelta(minutes=2),
    )

    after_emergency = gate.authorize(
        request(workflow_grant),
        now=NOW + timedelta(minutes=3),
    )

    assert scheduled.revoked_at == NOW + timedelta(minutes=10)
    assert before_emergency.effect == DecisionEffect.ALLOW
    assert emergency.revoked_at == NOW + timedelta(minutes=2)
    assert emergency.reason == "emergency revocation"
    assert after_emergency.effect == DecisionEffect.DENY
    assert "revoked" in after_emergency.reason
