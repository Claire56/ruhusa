"""
tests/test_invocation_provenance.py

v0.5-A+: Trusted invocation provenance via InMemoryInvocationStore (INV-17 strong mode).

Tests confirm that when Ruhusa is configured with an InMemoryInvocationStore:

  1. A registered InvocationRecord with a matching invoker/executor/task → ALLOW.
  2. Omitting invocation_id when a store is configured → DENY (fail-closed).
  3. An unknown invocation_id → DENY.
  4. Wrong executing_principal_id in the record → DENY.
  5. Wrong task_id in the record → DENY.
  6. Wrong invoking_principal_id in the record (doesn't match leaf grantor) → DENY.
  7. Invocation store backend failure → DENY (fail-closed).
  8. Forged invoking_principal_id on the request is ignored in strong mode → DENY.
  9. Without a store, invoking_principal_id field is used (weak / backward-compat mode).
 10. InMemoryInvocationStore unit-level tests (register, get, is_registered, duplicate).
"""

from datetime import UTC, datetime, timedelta

import pytest

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    DelegationGrant,
    InMemoryInvocationStore,
    InvocationRecord,
    PolicyRule,
    Principal,
    Ruhusa,
    Scope,
    StaticPolicyStore,
    TaskContext,
)

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)

REFUND_SCOPE = Scope(
    actions=frozenset({"issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 500},
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def make_task(task_id: str = "task-inv-001") -> TaskContext:
    return TaskContext(
        task_id=task_id,
        initiated_by="user-1",
        purpose="billing support",
        expires_at=NOW + timedelta(hours=1),
    )


def make_grant(task_id: str = "task-inv-001") -> DelegationGrant:
    return DelegationGrant(
        grant_id="grant-inv-001",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task_id,
        scope=REFUND_SCOPE,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
    )


def make_record(
    invocation_id: str = "inv-001",
    invoking_principal_id: str = "user-1",
    executing_principal_id: str = "billing-agent",
    task_id: str = "task-inv-001",
) -> InvocationRecord:
    return InvocationRecord(
        invocation_id=invocation_id,
        invoking_principal_id=invoking_principal_id,
        executing_principal_id=executing_principal_id,
        task_id=task_id,
        recorded_at=NOW,
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
    invocation_id: str | None = "inv-001",
    invoking_principal_id: str | None = None,
    task_id: str = "task-inv-001",
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
        invocation_id=invocation_id,
        invoking_principal_id=invoking_principal_id,
    )


# ---------------------------------------------------------------------------
# InMemoryInvocationStore unit tests
# ---------------------------------------------------------------------------


def test_store_register_and_is_registered() -> None:
    store = InMemoryInvocationStore()
    record = make_record()
    store.register(record)
    assert store.is_registered(record.invocation_id)


def test_store_get_returns_record() -> None:
    store = InMemoryInvocationStore()
    record = make_record()
    store.register(record)
    assert store.get(record.invocation_id) == record


def test_store_get_returns_none_for_unknown() -> None:
    store = InMemoryInvocationStore()
    assert store.get("inv-unknown") is None


def test_store_is_registered_returns_false_for_unknown() -> None:
    store = InMemoryInvocationStore()
    assert not store.is_registered("inv-unknown")


def test_store_duplicate_registration_raises() -> None:
    store = InMemoryInvocationStore()
    record = make_record()
    store.register(record)
    with pytest.raises(ValueError, match="already registered"):
        store.register(record)


def test_store_register_returns_record() -> None:
    store = InMemoryInvocationStore()
    record = make_record()
    returned = store.register(record)
    assert returned == record


# ---------------------------------------------------------------------------
# INV-17 strong mode: authorization checks
# ---------------------------------------------------------------------------


def test_registered_invocation_is_allowed() -> None:
    """A request with a valid, registered InvocationRecord is ALLOW."""
    store = InMemoryInvocationStore()
    store.register(make_record())

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.ALLOW


def test_missing_invocation_id_is_denied() -> None:
    """Omitting invocation_id when a store is configured is a hard DENY."""
    store = InMemoryInvocationStore()
    store.register(make_record())

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(invocation_id=None), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "invocation id is required" in decision.reason


def test_unknown_invocation_id_is_denied() -> None:
    """An invocation_id that has no registered record is DENY."""
    store = InMemoryInvocationStore()
    # No records registered.

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(invocation_id="inv-ghost"), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "not found in trusted store" in decision.reason


def test_wrong_executing_principal_is_denied() -> None:
    """A record whose executing_principal_id differs from request.principal is DENY."""
    store = InMemoryInvocationStore()
    store.register(
        make_record(executing_principal_id="other-agent")  # does not match billing-agent
    )

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "does not match request principal" in decision.reason


def test_wrong_task_id_in_record_is_denied() -> None:
    """A record bound to a different task_id is DENY."""
    store = InMemoryInvocationStore()
    store.register(
        make_record(task_id="task-other-999")  # does not match task-inv-001
    )

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "bound to a different task" in decision.reason


def test_wrong_invoking_principal_in_record_is_denied() -> None:
    """A record whose invoking_principal_id does not match the leaf grant grantor is DENY."""
    store = InMemoryInvocationStore()
    store.register(
        make_record(invoking_principal_id="low-privilege-agent")  # grantor is user-1
    )

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "does not match leaf grant grantor" in decision.reason


def test_invocation_store_backend_failure_fails_closed() -> None:
    """A store backend exception results in DENY, not an unhandled error."""

    class _BrokenStore(InMemoryInvocationStore):
        def get(self, invocation_id: str) -> InvocationRecord | None:
            raise RuntimeError("invocation store backend unavailable")

    store = _BrokenStore()
    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "invocation store unavailable" in decision.reason


def test_forged_invoking_principal_id_ignored_in_strong_mode() -> None:
    """In strong mode, the request's invoking_principal_id is ignored.

    The attacker forges invoking_principal_id="user-1" on the request object.
    The store record shows the real invoker is "low-privilege-agent".
    Ruhusa uses the store record → DENY.
    """
    store = InMemoryInvocationStore()
    store.register(
        make_record(invoking_principal_id="low-privilege-agent")  # actual caller
    )

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(
        make_request(invoking_principal_id="user-1"),  # forged on the request — ignored
        now=NOW,
    )

    assert decision.effect == DecisionEffect.DENY
    assert "does not match leaf grant grantor" in decision.reason


# ---------------------------------------------------------------------------
# Backward compatibility: weak mode (no store configured)
# ---------------------------------------------------------------------------


def test_no_store_weak_mode_matching_invoker_is_allowed() -> None:
    """Without a store, invoking_principal_id matching the leaf grantor is ALLOW."""
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(
        make_request(invocation_id=None, invoking_principal_id="user-1"),
        now=NOW,
    )
    assert decision.effect == DecisionEffect.ALLOW


def test_no_store_weak_mode_mismatched_invoker_is_denied() -> None:
    """Without a store, an invoking_principal_id that doesn't match the leaf grantor is DENY."""
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(
        make_request(invocation_id=None, invoking_principal_id="low-privilege-agent"),
        now=NOW,
    )
    assert decision.effect == DecisionEffect.DENY
    assert "invoking principal" in decision.reason


def test_no_store_weak_mode_missing_invoker_is_denied() -> None:
    """Without a store, omitting invoking_principal_id on a delegated request is DENY."""
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(
        make_request(invocation_id=None, invoking_principal_id=None),
        now=NOW,
    )
    assert decision.effect == DecisionEffect.DENY
    assert "invoking principal is required" in decision.reason


def test_no_store_no_chain_ignores_invocation_fields() -> None:
    """Without a chain, INV-17 does not apply — no store or invoker fields needed."""
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(
        make_request(with_chain=False, invocation_id=None, invoking_principal_id=None),
        now=NOW,
    )
    assert decision.effect == DecisionEffect.ALLOW


def test_store_no_chain_ignores_invocation_id() -> None:
    """With a store but no delegation chain, INV-17 does not apply — no invocation_id needed."""
    store = InMemoryInvocationStore()
    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(
        make_request(with_chain=False, invocation_id=None),
        now=NOW,
    )
    assert decision.effect == DecisionEffect.ALLOW
