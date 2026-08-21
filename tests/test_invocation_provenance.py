"""
tests/test_invocation_provenance.py

v0.5-A+: Trusted invocation provenance via InMemoryInvocationStore (INV-17 strong mode).

The InvocationRecord is the authoritative source for:
  - Invocation identity  (invoker, executor, task)
  - Operation binding    (action, resource, arguments digest)
  - Tool identity        (orchestrator-resolved tool pair, not request fields)
  - Temporal validity    (record-level expiry independent of the task)

Tests confirm that when Ruhusa is configured with an InMemoryInvocationStore:

   1. A fully valid record → ALLOW.
   2. Missing invocation_id → DENY (fail-closed).
   3. Unknown invocation_id → DENY.
   4. Wrong executing_principal_id → DENY.
   5. Wrong task_id → DENY.
   6. Wrong invoking_principal_id (doesn't match leaf grantor) → DENY.
   7. Action mismatch → DENY (operation binding).
   8. Resource mismatch → DENY (operation binding).
   9. Arguments digest mismatch → DENY (operation binding).
  10. Expired invocation record → DENY.
  11. Record's tool_id not in registry → DENY (strong-mode tool identity).
  12. Record's tool_id not authorized for action → DENY.
  13. Request tool fields are ignored in strong mode → DENY from record, not request.
  14. Invocation store backend failure → DENY (fail-closed).
  15. Forged invoking_principal_id on the request is ignored → DENY from record.
  16. Without a store, invoking_principal_id field is used (weak / backward-compat mode).
  17. InMemoryInvocationStore unit tests (register, get, is_registered, duplicate).
"""

from datetime import UTC, datetime, timedelta

import pytest

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    DelegationGrant,
    InMemoryInvocationStore,
    InMemoryToolRegistry,
    InvocationRecord,
    PolicyRule,
    Principal,
    Ruhusa,
    Scope,
    StaticPolicyStore,
    TaskContext,
    ToolRegistration,
    compute_arguments_digest,
)

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)

REFUND_SCOPE = Scope(
    actions=frozenset({"issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 500},
)

_DEFAULT_ARGS: dict = {"amount": 250}


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
    action: str = "issue_refund",
    resource: str = "customer:123:billing",
    arguments: dict | None = None,
    tool_id: str | None = None,
    implementation_id: str | None = None,
    recorded_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> InvocationRecord:
    args = arguments if arguments is not None else _DEFAULT_ARGS
    return InvocationRecord(
        invocation_id=invocation_id,
        invoking_principal_id=invoking_principal_id,
        executing_principal_id=executing_principal_id,
        task_id=task_id,
        action=action,
        resource=resource,
        arguments_digest=compute_arguments_digest(args),
        tool_id=tool_id,
        implementation_id=implementation_id,
        recorded_at=recorded_at or NOW,
        expires_at=expires_at or (NOW + timedelta(minutes=5)),
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
    action: str = "issue_refund",
    resource: str = "customer:123:billing",
    arguments: dict | None = None,
    with_chain: bool = True,
) -> AuthorizationRequest:
    args = arguments if arguments is not None else _DEFAULT_ARGS
    grant = make_grant(task_id) if with_chain else None
    chain = (grant,) if grant is not None else ()
    return AuthorizationRequest(
        principal=Principal("billing-agent"),
        action=action,
        resource=resource,
        arguments=args,
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
# INV-17 strong mode: identity cross-checks
# ---------------------------------------------------------------------------


def test_registered_invocation_is_allowed() -> None:
    """A request with a fully valid InvocationRecord is ALLOW."""
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
    """An invocation_id not in the store is DENY."""
    store = InMemoryInvocationStore()
    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(invocation_id="inv-ghost"), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "not found in trusted store" in decision.reason


def test_wrong_executing_principal_is_denied() -> None:
    """A record whose executing_principal_id differs from request.principal is DENY."""
    store = InMemoryInvocationStore()
    store.register(make_record(executing_principal_id="other-agent"))

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "does not match request principal" in decision.reason


def test_wrong_task_id_in_record_is_denied() -> None:
    """A record bound to a different task_id is DENY."""
    store = InMemoryInvocationStore()
    store.register(make_record(task_id="task-other-999"))

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "bound to a different task" in decision.reason


def test_wrong_invoking_principal_in_record_is_denied() -> None:
    """A record whose invoking_principal_id does not match the leaf grant grantor is DENY."""
    store = InMemoryInvocationStore()
    store.register(make_record(invoking_principal_id="low-privilege-agent"))

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "does not match leaf grant grantor" in decision.reason


# ---------------------------------------------------------------------------
# INV-17 strong mode: operation binding
# ---------------------------------------------------------------------------


def test_action_mismatch_is_denied() -> None:
    """A record whose action differs from the request action is DENY."""
    store = InMemoryInvocationStore()
    store.register(make_record(action="read_balance"))  # record says different action

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(action="issue_refund"), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "does not match request action" in decision.reason


def test_resource_mismatch_is_denied() -> None:
    """A record whose resource differs from the request resource is DENY."""
    store = InMemoryInvocationStore()
    store.register(make_record(resource="customer:456:billing"))  # different customer

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "does not match request resource" in decision.reason


def test_arguments_mismatch_is_denied() -> None:
    """A record whose arguments digest doesn't match the request arguments is DENY.

    The attacker registers a record for a $250 refund and then attempts to
    submit a $500 refund using the same invocation_id.
    """
    store = InMemoryInvocationStore()
    store.register(make_record(arguments={"amount": 250}))  # record: $250

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(
        make_request(arguments={"amount": 500}),  # request: $500 — digest mismatch
        now=NOW,
    )

    assert decision.effect == DecisionEffect.DENY
    assert "arguments digest does not match" in decision.reason


# ---------------------------------------------------------------------------
# INV-17 strong mode: temporal validity
# ---------------------------------------------------------------------------


def test_expired_invocation_record_is_denied() -> None:
    """An invocation record with expires_at in the past is DENY."""
    store = InMemoryInvocationStore()
    store.register(
        make_record(expires_at=NOW - timedelta(seconds=1))  # already expired
    )

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "invocation record has expired" in decision.reason


def test_not_yet_expired_record_is_allowed() -> None:
    """An invocation record with expires_at in the future is ALLOW."""
    store = InMemoryInvocationStore()
    store.register(
        make_record(expires_at=NOW + timedelta(seconds=1))  # valid for 1 more second
    )

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    assert gate.authorize(make_request(), now=NOW).effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# INV-18 strong mode: tool identity from the record
# ---------------------------------------------------------------------------

TRUSTED_IMPL_ID = "billing_refund_tool@v1.2.0-sha256:abc123"
ATTACKER_IMPL_ID = "billing_refund_tool@attacker-sha256:evil"


def _refund_registry() -> InMemoryToolRegistry:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolRegistration(
            tool_id="billing_refund_tool",
            implementation_id=TRUSTED_IMPL_ID,
            allowed_actions=frozenset({"issue_refund"}),
        )
    )
    return registry


def test_record_tool_id_verified_against_registry() -> None:
    """In strong mode the record's tool_id is used for the registry check, not the request's.

    The orchestrator recorded the attacker's actual implementation in the
    InvocationRecord.  The registry does not contain it → DENY.
    """
    store = InMemoryInvocationStore()
    store.register(
        make_record(
            tool_id="billing_refund_tool",
            implementation_id=ATTACKER_IMPL_ID,  # actual implementation observed
        )
    )

    gate = Ruhusa(
        policy_store=policy_store(),
        invocation_store=store,
        tool_registry=_refund_registry(),
    )
    # Request self-asserts the trusted implementation — but it's ignored in strong mode.
    decision = gate.authorize(
        AuthorizationRequest(
            principal=Principal("billing-agent"),
            action="issue_refund",
            resource="customer:123:billing",
            arguments=_DEFAULT_ARGS,
            task=make_task(),
            delegation_chain=(make_grant(),),
            invocation_id="inv-001",
            tool_id="billing_refund_tool",
            implementation_id=TRUSTED_IMPL_ID,  # forged — ignored
        ),
        now=NOW,
    )

    assert decision.effect == DecisionEffect.DENY
    assert "from invocation record is not in the trusted registry" in decision.reason


def test_record_tool_not_authorized_for_action_is_denied() -> None:
    """In strong mode, record.tool_id must be authorized for the requested action."""
    restricted_registry = InMemoryToolRegistry()
    restricted_registry.register(
        ToolRegistration(
            tool_id="billing_refund_tool",
            implementation_id=TRUSTED_IMPL_ID,
            allowed_actions=frozenset({"read_balance"}),  # NOT issue_refund
        )
    )

    store = InMemoryInvocationStore()
    store.register(
        make_record(
            tool_id="billing_refund_tool",
            implementation_id=TRUSTED_IMPL_ID,
        )
    )

    gate = Ruhusa(
        policy_store=policy_store(),
        invocation_store=store,
        tool_registry=restricted_registry,
    )
    decision = gate.authorize(make_request(), now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "from invocation record is not authorized to perform action" in decision.reason


def test_request_tool_fields_ignored_when_invocation_store_configured() -> None:
    """Forged request.tool_id / implementation_id are ignored in strong mode.

    The record has the orchestrator's observed (trusted) implementation.
    The request self-asserts a different (attacker) pair.
    The registry check uses the record's pair → ALLOW.
    """
    store = InMemoryInvocationStore()
    store.register(
        make_record(
            tool_id="billing_refund_tool",
            implementation_id=TRUSTED_IMPL_ID,  # what the orchestrator resolved
        )
    )

    gate = Ruhusa(
        policy_store=policy_store(),
        invocation_store=store,
        tool_registry=_refund_registry(),
    )
    # Request claims the attacker's implementation — but that field is ignored.
    decision = gate.authorize(
        AuthorizationRequest(
            principal=Principal("billing-agent"),
            action="issue_refund",
            resource="customer:123:billing",
            arguments=_DEFAULT_ARGS,
            task=make_task(),
            delegation_chain=(make_grant(),),
            invocation_id="inv-001",
            tool_id="billing_refund_tool",
            implementation_id=ATTACKER_IMPL_ID,  # self-asserted, ignored
        ),
        now=NOW,
    )

    assert decision.effect == DecisionEffect.ALLOW


def test_record_with_no_tool_id_skips_registry_check() -> None:
    """v0.5-C: When record.tool_id is None and a registry is configured, DENY fail-closed.

    Before v0.5-C, tool_id=None in the invocation record caused the registry check to
    be silently skipped (the guard was ``if record.tool_id is not None``), and policy
    decided alone → ALLOW.  After v0.5-C, a missing tool_id is fail-closed when a
    registry is configured; the record must carry tool identity for the check to pass.
    """
    store = InMemoryInvocationStore()
    store.register(make_record(tool_id=None, implementation_id=None))

    gate = Ruhusa(
        policy_store=policy_store(),
        invocation_store=store,
        tool_registry=_refund_registry(),
    )
    decision = gate.authorize(make_request(), now=NOW)

    # v0.5-C: fail-closed — registry configured but record carries no tool_id → DENY.
    assert decision.effect == DecisionEffect.DENY
    assert "record carries no tool_id" in decision.reason


# ---------------------------------------------------------------------------
# Fail-closed: store backend failure
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Forged request field is ignored in strong mode
# ---------------------------------------------------------------------------


def test_forged_invoking_principal_id_ignored_in_strong_mode() -> None:
    """In strong mode, the request's invoking_principal_id is ignored.

    The attacker forges invoking_principal_id="user-1" on the request object.
    The store record shows the real invoker is "low-privilege-agent".
    Ruhusa uses the store record → DENY.
    """
    store = InMemoryInvocationStore()
    store.register(make_record(invoking_principal_id="low-privilege-agent"))

    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(
        make_request(invoking_principal_id="user-1"),  # forged — ignored
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
    """Without a chain, INV-17 does not apply — no invoker fields needed."""
    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(
        make_request(with_chain=False, invocation_id=None, invoking_principal_id=None),
        now=NOW,
    )
    assert decision.effect == DecisionEffect.ALLOW


def test_store_no_chain_ignores_invocation_id() -> None:
    """v0.5-C: With a store configured, ALL requests require a canonical InvocationRecord.

    Before v0.5-C, the invocation check was gated on ``if request.delegation_chain:``,
    so non-delegated requests with an InvocationStore would skip the check entirely
    and receive ALLOW from policy alone.  After v0.5-C, the check applies to all
    requests regardless of whether a delegation chain is present.  A non-delegated
    request with no invocation_id is DENY.
    """
    store = InMemoryInvocationStore()
    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)
    decision = gate.authorize(
        make_request(with_chain=False, invocation_id=None),
        now=NOW,
    )
    # v0.5-C: invocation_id required for all requests when a store is configured.
    assert decision.effect == DecisionEffect.DENY
    assert "invocation id is required" in decision.reason
