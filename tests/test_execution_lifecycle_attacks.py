"""
v0.6-A experiments: execution claiming, exact replay, concurrency, and failure state.

The v0.5 release intentionally retained one known limitation:
``Ruhusa.authorize`` is non-consuming, so the exact same valid canonical
invocation can receive ALLOW repeatedly.

v0.6-A does not erase that baseline.  Instead, it introduces a separate trusted
execution lifecycle boundary and measures whether execution authority can be
claimed or reused safely.

Experiments:
  18 — Exact replay through authorize() remains reproducible        GAP
  19 — Second execution claim for same invocation                   BLOCKS
  20 — Concurrent claim race has exactly one winner                 BLOCKS
  21 — Completed invocation cannot execute again                    BLOCKS
  22 — Known pre-side-effect failure can release and retry          CONTROL
  23 — Unknown external outcome blocks automatic retry              BLOCKS
  24 — Stale/forged permit cannot mutate another attempt            BLOCKS
  25 — Expired execution authority cannot be claimed                BLOCKS
  26 — Authorization DENY does not consume execution authority      CONTROL
  27 — Execution-store failure fails closed                         BLOCKS
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    ExecutionController,
    ExecutionPermit,
    ExecutionState,
    InMemoryExecutionStore,
    InMemoryInvocationStore,
    InMemoryToolRegistry,
    InvocationRecord,
    PolicyRule,
    Principal,
    Ruhusa,
    StaticPolicyStore,
    TaskContext,
    ToolRegistration,
    compute_arguments_digest,
)

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
TOOL_ID = "billing_refund_tool"
IMPLEMENTATION_ID = "billing_refund_tool@v1.2.0-sha256:abc123"


def make_task() -> TaskContext:
    return TaskContext(
        task_id="task-execution-001",
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


def make_system(
    *,
    amount: int = 250,
    invocation_id: str = "inv-execution-001",
) -> tuple[Ruhusa, AuthorizationRequest, InMemoryInvocationStore]:
    task = make_task()
    arguments = {"amount": amount}

    invocation_store = InMemoryInvocationStore()
    invocation_store.register(
        InvocationRecord(
            invocation_id=invocation_id,
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest(arguments),
            tool_id=TOOL_ID,
            implementation_id=IMPLEMENTATION_ID,
            recorded_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=10),
        )
    )

    tool_registry = InMemoryToolRegistry()
    tool_registry.register(
        ToolRegistration(
            tool_id=TOOL_ID,
            implementation_id=IMPLEMENTATION_ID,
            allowed_actions=frozenset({"issue_refund"}),
        )
    )

    gate = Ruhusa(
        policy_store=policy_store(),
        invocation_store=invocation_store,
        tool_registry=tool_registry,
    )

    request = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments=arguments,
        task=task,
        invocation_id=invocation_id,
    )

    return gate, request, invocation_store


# ---------------------------------------------------------------------------
# Experiment 18 — preserve the v0.5 exact-replay baseline.
# GAP: authorize() itself remains non-consuming.
# ---------------------------------------------------------------------------


def test_exp18_exact_replay_through_authorize_remains_gap() -> None:
    gate, request, _ = make_system()

    first = gate.authorize(request, now=NOW)
    second = gate.authorize(request, now=NOW)

    assert first.effect == DecisionEffect.ALLOW
    assert second.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 19 — second execution claim is denied.
# ---------------------------------------------------------------------------


def test_exp19_second_execution_claim_is_blocked() -> None:
    gate, request, _ = make_system()
    controller = ExecutionController(gate)

    first = controller.begin(request, now=NOW)
    second = controller.begin(request, now=NOW)

    assert first.allowed is True
    assert first.permit is not None
    assert second.allowed is False
    assert "already claimed" in second.reason


# ---------------------------------------------------------------------------
# Experiment 20 — concurrent claim race has exactly one winner.
# ---------------------------------------------------------------------------


def test_exp20_concurrent_claim_has_exactly_one_winner() -> None:
    store = InMemoryExecutionStore()

    def attempt() -> bool:
        return store.claim(
            "inv-concurrent-001",
            expires_at=NOW + timedelta(minutes=5),
            now=NOW,
        ).allowed

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: attempt(), range(32)))

    assert sum(results) == 1

    record = store.get("inv-concurrent-001")
    assert record is not None
    assert record.state == ExecutionState.CLAIMED
    assert record.attempt_count == 1


# ---------------------------------------------------------------------------
# Experiment 21 — completed invocation cannot be replayed.
# ---------------------------------------------------------------------------


def test_exp21_completed_invocation_cannot_execute_again() -> None:
    gate, request, _ = make_system()
    controller = ExecutionController(gate)

    first = controller.begin(request, now=NOW)
    assert first.allowed is True
    assert first.permit is not None

    assert controller.complete(first.permit, now=NOW + timedelta(seconds=1)) is True

    replay = controller.begin(request, now=NOW + timedelta(seconds=2))

    assert replay.allowed is False
    assert "already completed" in replay.reason

    record = controller.execution_store.get(request.invocation_id or "")
    assert record is not None
    assert record.state == ExecutionState.COMPLETED


# ---------------------------------------------------------------------------
# Experiment 22 — known pre-execution failure may safely release and retry.
# ---------------------------------------------------------------------------


def test_exp22_release_before_execution_allows_safe_retry() -> None:
    gate, request, _ = make_system()
    controller = ExecutionController(gate)

    first = controller.begin(request, now=NOW)
    assert first.allowed is True
    assert first.permit is not None

    assert (
        controller.release_before_execution(
            first.permit,
            now=NOW + timedelta(seconds=1),
        )
        is True
    )

    second = controller.begin(request, now=NOW + timedelta(seconds=2))

    assert second.allowed is True
    assert second.permit is not None
    assert second.permit.claim_id != first.permit.claim_id
    assert second.permit.attempt == 2


# ---------------------------------------------------------------------------
# Experiment 23 — uncertain side-effect outcome blocks automatic retry.
# ---------------------------------------------------------------------------


def test_exp23_unknown_outcome_blocks_automatic_retry() -> None:
    gate, request, _ = make_system()
    controller = ExecutionController(gate)

    first = controller.begin(request, now=NOW)
    assert first.allowed is True
    assert first.permit is not None

    assert controller.mark_unknown(first.permit, now=NOW + timedelta(seconds=1)) is True

    retry = controller.begin(request, now=NOW + timedelta(seconds=2))

    assert retry.allowed is False
    assert "already unknown" in retry.reason

    record = controller.execution_store.get(request.invocation_id or "")
    assert record is not None
    assert record.state == ExecutionState.UNKNOWN


# ---------------------------------------------------------------------------
# Experiment 24 — stale and forged permits cannot mutate another attempt.
# ---------------------------------------------------------------------------


def test_exp24_stale_or_forged_permit_cannot_mutate_new_attempt() -> None:
    gate, request, _ = make_system()
    controller = ExecutionController(gate)

    first = controller.begin(request, now=NOW)
    assert first.allowed is True
    assert first.permit is not None

    # A definitely pre-side-effect failure releases attempt 1.
    assert (
        controller.release_before_execution(
            first.permit,
            now=NOW + timedelta(seconds=1),
        )
        is True
    )

    # Attempt 2 now owns the invocation.
    second = controller.begin(request, now=NOW + timedelta(seconds=2))
    assert second.allowed is True
    assert second.permit is not None

    # The stale attempt-1 permit must not be able to mutate attempt 2.
    assert controller.complete(first.permit, now=NOW + timedelta(seconds=3)) is False
    assert (
        controller.release_before_execution(
            first.permit,
            now=NOW + timedelta(seconds=3),
        )
        is False
    )
    assert controller.mark_unknown(first.permit, now=NOW + timedelta(seconds=3)) is False

    forged = ExecutionPermit(
        invocation_id=second.permit.invocation_id,
        claim_id="attacker-forged-claim",
        attempt=second.permit.attempt,
    )
    assert controller.complete(forged, now=NOW + timedelta(seconds=3)) is False

    record = controller.execution_store.get(second.permit.invocation_id)
    assert record is not None
    assert record.state == ExecutionState.CLAIMED
    assert record.claim_id == second.permit.claim_id
    assert record.attempt_count == 2


# ---------------------------------------------------------------------------
# Experiment 25 — expired execution authority cannot be claimed.
# ---------------------------------------------------------------------------


def test_exp25_expired_execution_authority_is_denied() -> None:
    store = InMemoryExecutionStore()

    result = store.claim(
        "inv-expired-001",
        expires_at=NOW - timedelta(seconds=1),
        now=NOW,
    )

    assert result.allowed is False
    assert "expired" in result.reason
    assert store.get("inv-expired-001") is None


# ---------------------------------------------------------------------------
# Experiment 26 — authorization DENY must not consume execution authority.
# ---------------------------------------------------------------------------


def test_exp26_authorization_deny_does_not_claim_execution_state() -> None:
    gate, request, _ = make_system(amount=600)
    controller = ExecutionController(gate)

    decision = controller.begin(request, now=NOW)

    assert decision.allowed is False
    assert decision.authorization.effect == DecisionEffect.DENY
    assert controller.execution_store.get(request.invocation_id or "") is None


# ---------------------------------------------------------------------------
# Experiment 27 — lifecycle backend failure fails closed.
# ---------------------------------------------------------------------------


class FailingExecutionStore(InMemoryExecutionStore):
    def claim(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("execution store unavailable")


def test_exp27_execution_store_failure_fails_closed() -> None:
    gate, request, _ = make_system()
    controller = ExecutionController(
        gate,
        execution_store=FailingExecutionStore(),
    )

    decision = controller.begin(request, now=NOW)

    assert decision.allowed is False
    assert "default deny" in decision.reason
