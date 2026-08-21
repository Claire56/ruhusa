"""
tests/test_tool_registry.py

v0.5-B: Tool identity controls (INV-18).

Tests confirm that when Ruhusa is configured with an InMemoryToolRegistry:

  1. A registered (tool_id, implementation_id) pair with the correct action is
     ALLOW.
  2. An unregistered implementation_id is DENY, even when the tool_id is known.
  3. A registered pair that does not cover the requested action is DENY.
  4. Omitting tool_id or implementation_id is a hard DENY (fail-closed).
  5. A tool registry backend failure fails closed.
  6. Without a registry configured, tool_id / implementation_id fields are
     ignored — existing behaviour is unchanged (backward-compatible).
"""

from datetime import UTC, datetime, timedelta

import pytest

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    DelegationGrant,
    InMemoryToolRegistry,
    PolicyRule,
    Principal,
    Ruhusa,
    Scope,
    StaticPolicyStore,
    TaskContext,
    ToolRegistration,
)

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)

REFUND_SCOPE = Scope(
    actions=frozenset({"issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 500},
)

TRUSTED_TOOL = ToolRegistration(
    tool_id="billing_refund_tool",
    implementation_id="billing_refund_tool@v1.2.0-sha256:abc123",
    allowed_actions=frozenset({"issue_refund"}),
)

SUBSTITUTE_IMPL = "billing_refund_tool@attacker-sha256:evil"


def make_task(task_id: str = "task-001") -> TaskContext:
    return TaskContext(
        task_id=task_id,
        initiated_by="user-1",
        purpose="billing support",
        expires_at=NOW + timedelta(hours=1),
    )


def make_grant(task_id: str = "task-001") -> DelegationGrant:
    return DelegationGrant(
        grant_id="grant-001",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task_id,
        scope=REFUND_SCOPE,
        issued_at=NOW - timedelta(minutes=5),
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


def make_request(
    *,
    tool_id: str | None = TRUSTED_TOOL.tool_id,
    implementation_id: str | None = TRUSTED_TOOL.implementation_id,
    task_id: str = "task-001",
    with_chain: bool = True,
) -> AuthorizationRequest:
    grant = make_grant(task_id) if with_chain else None
    chain = (grant,) if grant is not None else ()
    return AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=make_task(task_id),
        delegation_chain=chain,
        invoking_principal_id="user-1" if chain else None,
        tool_id=tool_id,
        implementation_id=implementation_id,
    )


# ---------------------------------------------------------------------------
# InMemoryToolRegistry unit tests
# ---------------------------------------------------------------------------


def test_registry_register_and_is_trusted() -> None:
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)
    assert registry.is_trusted(TRUSTED_TOOL.tool_id, TRUSTED_TOOL.implementation_id)


def test_registry_unknown_pair_is_not_trusted() -> None:
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)
    assert not registry.is_trusted(TRUSTED_TOOL.tool_id, SUBSTITUTE_IMPL)


def test_registry_duplicate_registration_raises() -> None:
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(TRUSTED_TOOL)


def test_registry_allows_action_for_registered_tool() -> None:
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)
    assert registry.allows_action(
        TRUSTED_TOOL.tool_id, TRUSTED_TOOL.implementation_id, "issue_refund"
    )


def test_registry_disallows_unlisted_action() -> None:
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)
    assert not registry.allows_action(
        TRUSTED_TOOL.tool_id, TRUSTED_TOOL.implementation_id, "delete_account"
    )


def test_registry_get_returns_registration() -> None:
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)
    assert registry.get(TRUSTED_TOOL.tool_id, TRUSTED_TOOL.implementation_id) == TRUSTED_TOOL


def test_registry_get_returns_none_for_unknown() -> None:
    registry = InMemoryToolRegistry()
    assert registry.get(TRUSTED_TOOL.tool_id, SUBSTITUTE_IMPL) is None


# ---------------------------------------------------------------------------
# INV-18 authorization checks
# ---------------------------------------------------------------------------


def test_registered_tool_is_allowed() -> None:
    """A request whose (tool_id, implementation_id) is registered is ALLOW."""
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)

    gate = Ruhusa(policy_store=policy_store(), tool_registry=registry)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.ALLOW


def test_unregistered_implementation_is_denied() -> None:
    """A request with a known tool_id but an unregistered implementation_id is DENY."""
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)

    gate = Ruhusa(policy_store=policy_store(), tool_registry=registry)
    decision = gate.authorize(
        make_request(implementation_id=SUBSTITUTE_IMPL),
        now=NOW,
    )

    assert decision.effect == DecisionEffect.DENY
    assert "not in the trusted registry" in decision.reason


def test_missing_tool_id_is_denied() -> None:
    """Omitting tool_id when a registry is configured is a hard DENY."""
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)

    gate = Ruhusa(policy_store=policy_store(), tool_registry=registry)
    decision = gate.authorize(make_request(tool_id=None), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "tool identity is required" in decision.reason


def test_missing_implementation_id_is_denied() -> None:
    """Omitting implementation_id when a registry is configured is a hard DENY."""
    registry = InMemoryToolRegistry()
    registry.register(TRUSTED_TOOL)

    gate = Ruhusa(policy_store=policy_store(), tool_registry=registry)
    decision = gate.authorize(make_request(implementation_id=None), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "tool identity is required" in decision.reason


def test_tool_not_authorized_for_action_is_denied() -> None:
    """A registered tool whose allowed_actions does not include the requested action is DENY."""
    registry = InMemoryToolRegistry()
    restricted_tool = ToolRegistration(
        tool_id="billing_refund_tool",
        implementation_id="billing_refund_tool@v1.2.0-sha256:abc123",
        allowed_actions=frozenset({"read_balance"}),  # issue_refund NOT included
    )
    registry.register(restricted_tool)

    gate = Ruhusa(policy_store=policy_store(), tool_registry=registry)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "not authorized to perform action" in decision.reason


def test_tool_registry_failure_fails_closed() -> None:
    """A tool registry backend exception results in DENY, not an unhandled error."""

    class _BrokenToolRegistry(InMemoryToolRegistry):
        def is_trusted(self, tool_id: str, implementation_id: str) -> bool:
            raise RuntimeError("tool registry backend unavailable")

    registry = _BrokenToolRegistry()
    gate = Ruhusa(policy_store=policy_store(), tool_registry=registry)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "tool registry unavailable" in decision.reason


def test_no_registry_ignores_tool_fields() -> None:
    """Without a registry, tool_id and implementation_id fields are ignored (backward compat)."""
    gate = Ruhusa(policy_store=policy_store())

    # Should ALLOW regardless of what tool fields are set or absent.
    decision_with_fields = gate.authorize(make_request(), now=NOW)
    decision_no_fields = gate.authorize(
        make_request(tool_id=None, implementation_id=None),
        now=NOW,
    )

    assert decision_with_fields.effect == DecisionEffect.ALLOW
    assert decision_no_fields.effect == DecisionEffect.ALLOW
