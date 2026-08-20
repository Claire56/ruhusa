"""
tests/test_tool_identity_attacks.py

Ruhusa v0.5 baseline attacks: tool identity, tool substitution,
and confused-deputy behavior.

These tests intentionally characterize the v0.4 baseline before a v0.5
mitigation is added.

Tests labeled GAP reproduce authorization behavior that v0.5 is expected
to strengthen. They pass when the current limitation is successfully
demonstrated.

Control tests confirm that existing action, resource, delegation, task,
and policy controls continue to work.
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

NOW = datetime(2026, 8, 20, 16, 0, tzinfo=UTC)

REFUND_SCOPE = Scope(
    actions=frozenset({"issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 500},
)


def make_task(task_id: str = "task-tool-001") -> TaskContext:
    return TaskContext(
        task_id=task_id,
        initiated_by="user-1",
        purpose="billing support",
        expires_at=NOW + timedelta(hours=1),
    )


def make_grant(
    *,
    grant_id: str = "grant-tool-001",
    grantee_id: str = "billing-agent",
    task_id: str = "task-tool-001",
) -> DelegationGrant:
    return DelegationGrant(
        grant_id=grant_id,
        grantor_id="user-1",
        grantee_id=grantee_id,
        task_id=task_id,
        scope=REFUND_SCOPE,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=30),
    )


def make_policy_store() -> StaticPolicyStore:
    return StaticPolicyStore(
        [
            PolicyRule(
                policy_id="billing-refund",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"issue_refund"}),
                principal_ids=frozenset({"billing-agent"}),
                resource_prefixes=("customer:123",),
                condition=lambda req: req.arguments["amount"] <= 500,
                reason="billing agent may issue bounded refunds",
            )
        ]
    )


def make_gate_and_grant() -> tuple[Ruhusa, DelegationGrant]:
    grant_store = InMemoryGrantStore()
    grant = grant_store.register(make_grant())

    gate = Ruhusa(
        policy_store=make_policy_store(),
        grant_store=grant_store,
    )
    return gate, grant


def make_request(
    grant: DelegationGrant,
    *,
    principal_id: str = "billing-agent",
    action: str = "issue_refund",
    resource: str = "customer:123:billing",
    amount: float = 250,
    context: dict | None = None,
) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=Principal(principal_id),
        action=action,
        resource=resource,
        arguments={"amount": amount},
        task=make_task(),
        delegation_chain=(grant,),
        context=context or {},
    )


# ---------------------------------------------------------------------------
# Attack 1: Tool substitution
#
# The same authorized semantic action is routed through a different tool.
# v0.4 has no trusted tool identity in AuthorizationRequest, Scope, or policy,
# so agent-controlled context does not affect the decision.
#
# GAP: both requests currently ALLOW.
# ---------------------------------------------------------------------------


def test_baseline_tool_substitution_gap_is_reproducible() -> None:
    gate, grant = make_gate_and_grant()

    trusted_tool_request = make_request(
        grant,
        context={
            "tool_id": "trusted-refund-tool",
            "tool_provider": "internal-billing",
        },
    )

    substituted_tool_request = make_request(
        grant,
        context={
            "tool_id": "untrusted-refund-tool",
            "tool_provider": "external-plugin",
        },
    )

    trusted = gate.authorize(trusted_tool_request, now=NOW)
    substituted = gate.authorize(substituted_tool_request, now=NOW)

    assert trusted.effect == DecisionEffect.ALLOW

    # GAP: v0.4 does not bind authorization to a trusted tool identity.
    assert substituted.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Attack 2: Same logical tool name, different implementation
#
# A malicious or compromised registry swaps the implementation behind an
# apparently familiar logical tool. v0.4 cannot distinguish implementations.
#
# GAP: both implementations currently ALLOW.
# ---------------------------------------------------------------------------


def test_baseline_tool_implementation_swap_is_not_detected() -> None:
    gate, grant = make_gate_and_grant()

    original = make_request(
        grant,
        context={
            "tool_id": "refund-tool",
            "tool_implementation_id": "billing-refund-service:v1",
        },
    )

    substituted = make_request(
        grant,
        context={
            "tool_id": "refund-tool",
            "tool_implementation_id": "attacker-service:v9",
        },
    )

    original_decision = gate.authorize(original, now=NOW)
    substituted_decision = gate.authorize(substituted, now=NOW)

    assert original_decision.effect == DecisionEffect.ALLOW

    # GAP: implementation identity is not part of the authorization decision.
    assert substituted_decision.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Attack 3: Confused deputy
#
# low-privilege-agent is not permitted to issue refunds directly. It induces
# billing-agent (the privileged deputy) to submit the protected request.
#
# The current model evaluates the executing principal but has no trusted
# caller/on-behalf-of chain. Agent-controlled context stating who induced the
# deputy is not an authorization input.
#
# GAP: direct request DENY; deputy request ALLOW.
# ---------------------------------------------------------------------------


def test_baseline_confused_deputy_gap_is_reproducible() -> None:
    gate, grant = make_gate_and_grant()

    direct_low_privilege_request = make_request(
        grant,
        principal_id="low-privilege-agent",
        context={"requesting_principal_id": "low-privilege-agent"},
    )

    direct = gate.authorize(direct_low_privilege_request, now=NOW)

    assert direct.effect == DecisionEffect.DENY

    induced_deputy_request = make_request(
        grant,
        principal_id="billing-agent",
        context={
            "requesting_principal_id": "low-privilege-agent",
            "on_behalf_of": "low-privilege-agent",
        },
    )

    deputy = gate.authorize(induced_deputy_request, now=NOW)

    # GAP: the effective caller/deputy relationship is not authenticated
    # or evaluated by v0.4.
    assert deputy.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Control 1: Existing action scope remains effective
# ---------------------------------------------------------------------------


def test_control_unrelated_action_is_still_denied() -> None:
    gate, grant = make_gate_and_grant()

    request = make_request(
        grant,
        action="delete_customer",
        context={"tool_id": "trusted-refund-tool"},
    )

    decision = gate.authorize(request, now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "action outside delegated scope" in decision.reason


# ---------------------------------------------------------------------------
# Control 2: Existing resource scope remains effective
# ---------------------------------------------------------------------------


def test_control_other_resource_is_still_denied() -> None:
    gate, grant = make_gate_and_grant()

    request = make_request(
        grant,
        resource="customer:999:billing",
        context={"tool_id": "trusted-refund-tool"},
    )

    decision = gate.authorize(request, now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "resource outside delegated scope" in decision.reason
