"""
tests/test_replanning_attacks.py

v0.4 attack scenarios: replanning and delegation-bypass experiments.

Each test documents the attack and the expected outcome.

Tests marked BLOCKS confirm Ruhusa prevents the attack.
All five scenarios are currently blocked.
"""

from datetime import UTC, datetime, timedelta

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    DelegationGrant,
    InMemoryGrantStore,
    PolicyRule,
    Principal,
    Ruhusa,
    Scope,
    StaticPolicyStore,
    TaskContext,
)

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

REFUND_SCOPE = Scope(
    actions=frozenset({"issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 500},
)

WIDE_SCOPE = Scope(
    actions=frozenset({"issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 2000},
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
    scope: Scope = REFUND_SCOPE,
) -> DelegationGrant:
    return DelegationGrant(
        grant_id=grant_id,
        grantor_id=grantor_id,
        grantee_id=grantee_id,
        task_id=task_id,
        scope=scope,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
    )


def make_request(
    principal_id: str,
    action: str,
    resource: str,
    arguments: dict,
    task: TaskContext,
    chain: tuple[DelegationGrant, ...] = (),
) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=Principal(principal_id),
        action=action,
        resource=resource,
        arguments=arguments,
        task=task,
        delegation_chain=chain,
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
        ]
    )


# ---------------------------------------------------------------------------
# Attack 1: Denied agent delegates to another agent and retries
#
# Scenario: billing-agent is denied (no delegation chain). It then delegates
# to sub-agent, which presents a chain originating from billing-agent rather
# than from the task initiator (user-1). The chain origin check should catch
# this because chain[0].grantor_id must equal task.initiated_by.
#
# Expected: BLOCKS — chain does not originate from task initiator.
# ---------------------------------------------------------------------------


def test_denied_agent_cannot_delegate_to_bypass_denial() -> None:
    """
    BLOCKS: An agent that was denied cannot create a valid delegation chain
    rooted at itself. The first grant in any chain must originate from the
    task initiator, not from a previously-denied agent.
    """
    task = make_task("task-refund-001")

    # billing-agent tries to delegate to sub-agent, rooting the chain in itself
    forged_grant = make_grant(
        grant_id="forged-grant",
        grantor_id="billing-agent",  # not the task initiator
        grantee_id="sub-agent",
        task_id="task-refund-001",
    )

    req = make_request(
        principal_id="sub-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        chain=(forged_grant,),
    )

    decision = Ruhusa(policy_store=policy_store()).authorize(req, now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "does not originate from task initiator" in decision.reason


# ---------------------------------------------------------------------------
# Attack 2: Scope escalation through a child grant
#
# Scenario: user-1 grants billing-agent a scope capped at $500.
# billing-agent re-delegates to sub-agent with a scope capped at $2000,
# attempting to widen authority through a child grant.
#
# Expected: BLOCKS — scope attenuation check prevents widening.
# ---------------------------------------------------------------------------


def test_child_grant_cannot_widen_scope() -> None:
    """
    BLOCKS: A child delegation grant cannot exceed the scope of its parent.
    Attempting to raise the numeric cap ($500 → $2000) must be denied.
    """
    task = make_task("task-escalation-001")

    parent_grant = make_grant(
        grant_id="parent-grant",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id="task-escalation-001",
        scope=REFUND_SCOPE,  # capped at $500
    )

    escalated_grant = make_grant(
        grant_id="escalated-grant",
        grantor_id="billing-agent",
        grantee_id="sub-agent",
        task_id="task-escalation-001",
        scope=WIDE_SCOPE,  # attempts to widen to $2000
    )

    req = make_request(
        principal_id="sub-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 1500},
        task=task,
        chain=(parent_grant, escalated_grant),
    )

    decision = Ruhusa(policy_store=policy_store()).authorize(req, now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "exceeds parent scope" in decision.reason


# ---------------------------------------------------------------------------
# Attack 3: Revoked authority reused through a fabricated fresh grant
#
# Scenario: user-1 grants billing-agent authority via grant-001, registered
# in the grant store. grant-001 is then revoked. The attacker fabricates
# grant-002 with identical fields (same grantor, grantee, scope, task) but
# a new grant_id, hoping Ruhusa will accept it because the revocation is
# keyed to grant-001.
#
# Fix (v0.4): Ruhusa is configured with an InMemoryGrantStore. Only grants
# registered through the store are accepted. grant-002 was never registered,
# so it is denied regardless of its contents.
#
# Expected: BLOCKS — unregistered grant is denied with "trusted boundary"
# reason.
# ---------------------------------------------------------------------------


def test_revoked_grant_reuse_via_fresh_chain_is_blocked_by_grant_store() -> None:
    """
    BLOCKS: When Ruhusa is configured with a grant store, a fabricated
    replacement grant is denied because it was not registered through the
    trusted issuance boundary.

    This closes the gap identified in the initial v0.4 experiments:
    revocation was grant-scoped, allowing an attacker to bypass it by
    constructing a new grant_id with identical authority.
    """
    task = make_task("task-revoke-001")
    grant_store = InMemoryGrantStore()

    original_grant = grant_store.register(
        make_grant(
            grant_id="grant-001",
            grantor_id="user-1",
            grantee_id="billing-agent",
            task_id="task-revoke-001",
        )
    )

    # Fabricated replacement — never registered in the grant store
    fabricated_grant = make_grant(
        grant_id="grant-002",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id="task-revoke-001",
    )

    gate = Ruhusa(policy_store=policy_store(), grant_store=grant_store)

    # Revoke the original grant
    gate.revoke_grant(
        original_grant.grant_id,
        reason="authority withdrawn",
        revoked_at=NOW,
    )

    # Original grant is denied: revoked
    original_req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        chain=(original_grant,),
    )
    original_decision = gate.authorize(original_req, now=NOW + timedelta(seconds=1))
    assert original_decision.effect == DecisionEffect.DENY
    assert "revoked" in original_decision.reason

    # Fabricated grant is denied: not in the trusted issuance store
    fabricated_req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        chain=(fabricated_grant,),
    )
    fabricated_decision = gate.authorize(fabricated_req, now=NOW + timedelta(seconds=1))
    assert fabricated_decision.effect == DecisionEffect.DENY
    assert "trusted boundary" in fabricated_decision.reason

    # A legitimately re-issued grant (registered through the store) is still ALLOW.
    # This confirms the fix is targeted: it blocks fabrication, not re-authorization.
    reissued_grant = grant_store.register(
        make_grant(
            grant_id="grant-003",
            grantor_id="user-1",
            grantee_id="billing-agent",
            task_id="task-revoke-001",
        )
    )
    reissued_req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        chain=(reissued_grant,),
    )
    reissued_decision = gate.authorize(reissued_req, now=NOW + timedelta(seconds=1))
    assert reissued_decision.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Attack 4: Cross-task replay after denial
#
# Scenario: An agent is denied on task-A (expired grant). It replays the
# same grant against task-B. The task-binding check should catch this
# because the grant's task_id does not match task-B's task_id.
#
# Expected: BLOCKS — grant is bound to task-A; task-B is rejected.
# ---------------------------------------------------------------------------


def test_cross_task_replay_after_denial() -> None:
    """
    BLOCKS: A grant denied under task-A (here: due to task-id mismatch when
    replayed) cannot be reused to authorize an action under task-B.
    """
    task_a = make_task("task-A")
    task_b = make_task("task-B")

    grant_for_a = make_grant(
        grant_id="grant-task-a",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id="task-A",
    )

    # Denied under task-A (imagine scope exceeded, then agent retries under task-B)
    req_a = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 9999},  # exceeds scope — denied
        task=task_a,
        chain=(grant_for_a,),
    )
    gate = Ruhusa(policy_store=policy_store())
    decision_a = gate.authorize(req_a, now=NOW)
    assert decision_a.effect == DecisionEffect.DENY

    # Agent replays the same grant under task-B
    req_b = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task_b,
        chain=(grant_for_a,),  # grant is bound to task-A
    )
    decision_b = gate.authorize(req_b, now=NOW)

    assert decision_b.effect == DecisionEffect.DENY
    assert "bound to a different task" in decision_b.reason


# ---------------------------------------------------------------------------
# Attack 5: Equivalent action retried through a different delegation path
#
# Scenario: billing-agent is denied because its grant exceeds the allowed
# amount. It constructs an alternate two-hop chain: user-1 → supervisor →
# billing-agent, hoping that routing through an intermediate grants wider
# effective authority. The scope must still be capped at the parent's limit
# at every hop; the policy condition also applies to the final request amount.
#
# Expected: BLOCKS — scope at each hop is attenuated; policy condition
# independently enforces the amount cap on the final request.
# ---------------------------------------------------------------------------


def test_alternate_delegation_path_does_not_widen_effective_authority() -> None:
    """
    BLOCKS: Routing a delegation through an additional intermediate
    (user-1 → supervisor → billing-agent) does not grant wider effective
    authority than a direct delegation. Scope attenuation and the policy
    condition both apply independently.
    """
    task = make_task("task-alternate-001")

    supervisor_scope = Scope(
        actions=frozenset({"issue_refund"}),
        resource_prefixes=("customer:123",),
        max_numeric_arguments={"amount": 500},
    )
    billing_scope = Scope(
        actions=frozenset({"issue_refund"}),
        resource_prefixes=("customer:123",),
        max_numeric_arguments={"amount": 500},
    )

    grant_to_supervisor = make_grant(
        grant_id="grant-supervisor",
        grantor_id="user-1",
        grantee_id="supervisor-agent",
        task_id="task-alternate-001",
        scope=supervisor_scope,
    )
    grant_to_billing = make_grant(
        grant_id="grant-billing",
        grantor_id="supervisor-agent",
        grantee_id="billing-agent",
        task_id="task-alternate-001",
        scope=billing_scope,
    )

    # Request an amount that is within delegated scope but exceeds what the
    # policy allows (policy allows ≤ $500; both grants cap at $500;
    # this request is exactly $500 — should be ALLOW)
    req_within = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 500},
        task=task,
        chain=(grant_to_supervisor, grant_to_billing),
    )
    gate = Ruhusa(policy_store=policy_store())
    decision_within = gate.authorize(req_within, now=NOW)
    assert decision_within.effect == DecisionEffect.ALLOW

    # Request an amount that exceeds the delegated scope — must be denied
    # regardless of how many hops the chain has.
    req_over = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 750},
        task=task,
        chain=(grant_to_supervisor, grant_to_billing),
    )
    decision_over = gate.authorize(req_over, now=NOW)
    assert decision_over.effect == DecisionEffect.DENY


# ---------------------------------------------------------------------------
# Attack 6: Registered grant ID presented with modified scope
#
# Scenario: The attacker knows a legitimate grant_id that was registered
# through the grant store. Rather than using the original grant, they
# construct a new DelegationGrant object with the same grant_id but a wider
# scope (e.g. $500 → $5000). Since only the ID is recognized, an ID-only
# check (contains) would pass; the content-integrity check (is_registered)
# must catch the mismatch.
#
# Expected: BLOCKS — presented grant contents do not match the issued grant.
# ---------------------------------------------------------------------------


def test_registered_id_with_tampered_scope_is_denied() -> None:
    """
    BLOCKS: Presenting a known grant_id with modified contents (wider scope)
    is denied because the full-equality check fails. The denial reason
    distinguishes 'contents do not match' from 'ID unknown'.
    """
    task = make_task("task-tamper-001")
    grant_store = InMemoryGrantStore()

    # Register the legitimate grant (scope capped at $500)
    legitimate_grant = grant_store.register(
        make_grant(
            grant_id="grant-legit",
            grantor_id="user-1",
            grantee_id="billing-agent",
            task_id="task-tamper-001",
            scope=REFUND_SCOPE,  # capped at $500
        )
    )

    # Attacker constructs a grant with the same grant_id but a wider scope
    tampered_grant = DelegationGrant(
        grant_id=legitimate_grant.grant_id,  # known, registered ID
        grantor_id=legitimate_grant.grantor_id,
        grantee_id=legitimate_grant.grantee_id,
        task_id=legitimate_grant.task_id,
        scope=WIDE_SCOPE,  # widened to $2000
        issued_at=legitimate_grant.issued_at,
        expires_at=legitimate_grant.expires_at,
    )

    req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 1500},
        task=task,
        chain=(tampered_grant,),
    )

    gate = Ruhusa(policy_store=policy_store(), grant_store=grant_store)
    decision = gate.authorize(req, now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "contents do not match" in decision.reason

    # Confirm the legitimate grant still works at an allowed amount
    legit_req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        chain=(legitimate_grant,),
    )
    legit_decision = gate.authorize(legit_req, now=NOW)
    assert legit_decision.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Attack 7: Grant-store backend becomes unavailable
#
# Scenario: Ruhusa is configured with a grant store whose backend throws an
# exception during the issuance check (e.g. network timeout, database error).
# Authorization must fail closed rather than letting the exception propagate
# or defaulting to ALLOW.
#
# Expected: BLOCKS — any exception from the grant store causes DENY with
# "grant issuance status unavailable" reason.
# ---------------------------------------------------------------------------


class _BrokenGrantStore(InMemoryGrantStore):
    """Grant store that simulates a backend failure on every lookup."""

    def is_registered(self, grant: DelegationGrant) -> bool:  # type: ignore[override]
        raise RuntimeError("grant store backend unavailable")


def test_grant_store_failure_is_fail_closed() -> None:
    """
    BLOCKS: If the grant store raises an exception during the issuance check,
    authorize() must deny the request rather than propagating the exception
    or defaulting to ALLOW.

    This mirrors the same fail-closed guarantee already provided for policy
    evaluation failures and revocation-store failures.
    """
    task = make_task("task-failclosed-001")

    grant = make_grant(
        grant_id="grant-failclosed",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id="task-failclosed-001",
    )

    req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        chain=(grant,),
    )

    gate = Ruhusa(policy_store=policy_store(), grant_store=_BrokenGrantStore())
    decision = gate.authorize(req, now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "grant issuance status unavailable" in decision.reason
