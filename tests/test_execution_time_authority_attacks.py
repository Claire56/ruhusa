"""
v0.6-B experiments: execution-time authority validity and TOCTOU.

Research question:
    Is authorization at claim time sufficient when authority can change before
    the protected side effect occurs?

v0.6-B introduces ``ExecutionController.revalidate_before_execution``. The
method re-runs the complete deterministic authorization path immediately before
tool/API execution and cancels a claimed invocation when live authority is no
longer valid.

The benchmark intentionally preserves both the pre-control gap and the
remaining post-revalidation TOCTOU boundary.

Experiments:
  28 — Revocation before execution claim                          BLOCKS
  29 — Revocation after claim without revalidation                GAP
  30 — Revocation after claim with execution-time revalidation    BLOCKS
  31 — Task expiry after claim                                    BLOCKS
  32 — Policy removal/change after claim                          BLOCKS
  33 — Stale/forged permit at execution-time revalidation         BLOCKS
  34 — Execution-store failure during revalidation                BLOCKS
  35 — Revocation after successful revalidation                   GAP / boundary
"""

from datetime import UTC, datetime, timedelta

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    DelegationGrant,
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
    Scope,
    StaticPolicyStore,
    TaskContext,
    ToolRegistration,
    compute_arguments_digest,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
TOOL_ID = "billing_refund_tool"
IMPLEMENTATION_ID = "billing_refund_tool@v1.2.0-sha256:abc123"


def allow_policy_store() -> StaticPolicyStore:
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


def make_delegated_system(
    *,
    task_expires_at: datetime | None = None,
    invocation_expires_at: datetime | None = None,
) -> tuple[Ruhusa, AuthorizationRequest, DelegationGrant]:
    task = TaskContext(
        task_id="task-execution-time-001",
        initiated_by="user-1",
        purpose="billing support",
        expires_at=task_expires_at or NOW + timedelta(hours=1),
    )

    grant = DelegationGrant(
        grant_id="grant-execution-time-001",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
        scope=Scope(
            actions=frozenset({"issue_refund"}),
            resource_prefixes=("customer:123",),
            max_numeric_arguments={"amount": 500},
        ),
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=2),
    )

    arguments = {"amount": 250}

    invocation_store = InMemoryInvocationStore()
    invocation_store.register(
        InvocationRecord(
            invocation_id="inv-execution-time-001",
            invoking_principal_id=grant.grantor_id,
            executing_principal_id=grant.grantee_id,
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest(arguments),
            tool_id=TOOL_ID,
            implementation_id=IMPLEMENTATION_ID,
            recorded_at=NOW - timedelta(seconds=1),
            expires_at=invocation_expires_at or NOW + timedelta(hours=2),
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
        policy_store=allow_policy_store(),
        invocation_store=invocation_store,
        tool_registry=tool_registry,
    )

    request = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments=arguments,
        task=task,
        delegation_chain=(grant,),
        invocation_id="inv-execution-time-001",
    )

    return gate, request, grant


# ---------------------------------------------------------------------------
# Experiment 28 — revocation before claim is already blocked.
# CONTROL: begin() re-runs Ruhusa.authorize before creating execution state.
# ---------------------------------------------------------------------------


def test_exp28_revocation_before_claim_is_blocked() -> None:
    gate, request, grant = make_delegated_system()
    controller = ExecutionController(gate)

    gate.revoke_grant(
        grant.grant_id,
        reason="user withdrew authority before execution claim",
        revoked_at=NOW + timedelta(minutes=1),
    )

    decision = controller.begin(request, now=NOW + timedelta(minutes=2))

    assert decision.allowed is False
    assert decision.authorization.effect == DecisionEffect.DENY
    assert "revoked" in decision.reason
    assert controller.execution_store.get(request.invocation_id or "") is None


# ---------------------------------------------------------------------------
# Experiment 29 — v0.6-A gap: revocation after claim is not observed by
# complete() when no execution-time revalidation occurs.
# ---------------------------------------------------------------------------


def test_exp29_revocation_after_claim_without_revalidation_remains_gap() -> None:
    gate, request, grant = make_delegated_system()
    controller = ExecutionController(gate)

    claimed = controller.begin(request, now=NOW)
    assert claimed.allowed is True
    assert claimed.permit is not None

    gate.revoke_grant(
        grant.grant_id,
        reason="user withdrew authority after claim",
        revoked_at=NOW + timedelta(minutes=1),
    )

    # This intentionally reproduces the v0.6-A gap. complete() proves ownership
    # of the claimed attempt; it does not re-check authorization state.
    completed = controller.complete(
        claimed.permit,
        now=NOW + timedelta(minutes=2),
    )

    assert completed is True
    record = controller.execution_store.get(claimed.permit.invocation_id)
    assert record is not None
    assert record.state == ExecutionState.COMPLETED


# ---------------------------------------------------------------------------
# Experiment 30 — execution-time revalidation observes post-claim revocation.
# ---------------------------------------------------------------------------


def test_exp30_revalidation_blocks_revocation_after_claim() -> None:
    gate, request, grant = make_delegated_system()
    controller = ExecutionController(gate)

    claimed = controller.begin(request, now=NOW)
    assert claimed.allowed is True
    assert claimed.permit is not None

    gate.revoke_grant(
        grant.grant_id,
        reason="user withdrew authority after claim",
        revoked_at=NOW + timedelta(minutes=1),
    )

    validation = controller.revalidate_before_execution(
        request,
        claimed.permit,
        now=NOW + timedelta(minutes=2),
    )

    assert validation.allowed is False
    assert validation.authorization.effect == DecisionEffect.DENY
    assert "revoked" in validation.reason

    record = controller.execution_store.get(claimed.permit.invocation_id)
    assert record is not None
    assert record.state == ExecutionState.CANCELLED
    assert record.cancel_reason is not None
    assert "revoked" in record.cancel_reason

    # A cancelled invocation is terminal; the stale permit cannot be completed.
    assert (
        controller.complete(
            claimed.permit,
            now=NOW + timedelta(minutes=3),
        )
        is False
    )


# ---------------------------------------------------------------------------
# Experiment 31 — task expiry after claim is caught at execution time.
# ---------------------------------------------------------------------------


def test_exp31_revalidation_blocks_task_expiry_after_claim() -> None:
    gate, request, _ = make_delegated_system(
        task_expires_at=NOW + timedelta(minutes=1),
        invocation_expires_at=NOW + timedelta(hours=1),
    )
    controller = ExecutionController(gate)

    claimed = controller.begin(request, now=NOW)
    assert claimed.allowed is True
    assert claimed.permit is not None

    validation = controller.revalidate_before_execution(
        request,
        claimed.permit,
        now=NOW + timedelta(minutes=2),
    )

    assert validation.allowed is False
    assert validation.authorization.effect == DecisionEffect.DENY
    assert "task expired" in validation.reason

    record = controller.execution_store.get(claimed.permit.invocation_id)
    assert record is not None
    assert record.state == ExecutionState.CANCELLED


# ---------------------------------------------------------------------------
# Experiment 32 — current policy is evaluated again immediately before use.
# ---------------------------------------------------------------------------


def test_exp32_revalidation_blocks_policy_change_after_claim() -> None:
    gate, request, _ = make_delegated_system()
    controller = ExecutionController(gate)

    claimed = controller.begin(request, now=NOW)
    assert claimed.allowed is True
    assert claimed.permit is not None

    # Model a policy change/removal after the execution claim.
    gate.policy_store = StaticPolicyStore()

    validation = controller.revalidate_before_execution(
        request,
        claimed.permit,
        now=NOW + timedelta(minutes=1),
    )

    assert validation.allowed is False
    assert validation.authorization.effect == DecisionEffect.DENY
    assert "no policy matched" in validation.reason

    record = controller.execution_store.get(claimed.permit.invocation_id)
    assert record is not None
    assert record.state == ExecutionState.CANCELLED


# ---------------------------------------------------------------------------
# Experiment 33 — revalidation must also authenticate the active execution
# attempt, not merely re-authorize the underlying operation.
# ---------------------------------------------------------------------------


def test_exp33_revalidation_blocks_stale_or_forged_permit() -> None:
    gate, request, _ = make_delegated_system()
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

    stale = controller.revalidate_before_execution(
        request,
        first.permit,
        now=NOW + timedelta(seconds=3),
    )
    assert stale.allowed is False
    assert "not the active claimed attempt" in stale.reason

    forged = ExecutionPermit(
        invocation_id=second.permit.invocation_id,
        claim_id="forged-claim-id",
        attempt=second.permit.attempt,
    )
    forged_result = controller.revalidate_before_execution(
        request,
        forged,
        now=NOW + timedelta(seconds=3),
    )
    assert forged_result.allowed is False
    assert "not the active claimed attempt" in forged_result.reason

    record = controller.execution_store.get(second.permit.invocation_id)
    assert record is not None
    assert record.state == ExecutionState.CLAIMED
    assert record.claim_id == second.permit.claim_id


# ---------------------------------------------------------------------------
# Experiment 34 — lifecycle-state failure during revalidation fails closed.
# ---------------------------------------------------------------------------


class FailingRevalidationExecutionStore(InMemoryExecutionStore):
    def is_active(self, permit: ExecutionPermit) -> bool:
        raise RuntimeError("execution lifecycle backend unavailable")


def test_exp34_execution_store_failure_during_revalidation_fails_closed() -> None:
    gate, request, _ = make_delegated_system()
    store = FailingRevalidationExecutionStore()
    controller = ExecutionController(gate, execution_store=store)

    claimed = controller.begin(request, now=NOW)
    assert claimed.allowed is True
    assert claimed.permit is not None

    validation = controller.revalidate_before_execution(
        request,
        claimed.permit,
        now=NOW + timedelta(seconds=1),
    )

    assert validation.allowed is False
    assert "default deny" in validation.reason


# ---------------------------------------------------------------------------
# Experiment 35 — residual boundary: authority may change after a successful
# revalidation but before the external side effect.
#
# GAP: v0.6-B narrows the TOCTOU window; it does not make authorization state
# and a remote side effect one atomic transaction.
# ---------------------------------------------------------------------------


def test_exp35_revocation_after_successful_revalidation_remains_toctou_gap() -> None:
    gate, request, grant = make_delegated_system()
    controller = ExecutionController(gate)

    claimed = controller.begin(request, now=NOW)
    assert claimed.allowed is True
    assert claimed.permit is not None

    validation = controller.revalidate_before_execution(
        request,
        claimed.permit,
        now=NOW + timedelta(minutes=1),
    )
    assert validation.allowed is True

    # Authority changes *after* the successful final check.
    gate.revoke_grant(
        grant.grant_id,
        reason="authority withdrawn after execution-time check",
        revoked_at=NOW + timedelta(minutes=1, seconds=1),
    )

    # There is no atomic transaction coupling revocation state to an external
    # side effect. complete() still sees a valid lifecycle owner.
    completed = controller.complete(
        claimed.permit,
        now=NOW + timedelta(minutes=1, seconds=2),
    )

    assert completed is True

    # A fresh authorization at the same time correctly sees the revocation,
    # proving the gap is specifically between the final check and use.
    after = gate.authorize(
        request,
        now=NOW + timedelta(minutes=1, seconds=2),
    )
    assert after.effect == DecisionEffect.DENY
    assert "revoked" in after.reason
