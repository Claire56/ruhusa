from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    DelegationGrant,
    ExecutionClaimResult,
    ExecutionController,
    ExecutionPermit,
    InMemoryInvocationStore,
    InvocationRecord,
    PolicyRule,
    Principal,
    Ruhusa,
    Scope,
    StaticPolicyStore,
    StoreUnavailableError,
    TaskContext,
    compute_arguments_digest,
)

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
ACTION = "issue_refund"
RESOURCE = "customer:123:billing"
ARGUMENTS = {"amount": 250}


def allow_policy() -> StaticPolicyStore:
    return StaticPolicyStore(
        [
            PolicyRule(
                policy_id="allow-refund",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({ACTION}),
                principal_ids=frozenset({"billing-agent"}),
                resource_prefixes=("customer:123",),
                reason="allowed for failure-contract test",
            )
        ]
    )


def direct_request(
    *,
    invocation_id: str | None = None,
    tool_id: str | None = None,
    implementation_id: str | None = None,
) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=Principal("billing-agent"),
        action=ACTION,
        resource=RESOURCE,
        arguments=ARGUMENTS,
        task=TaskContext(
            task_id="task-store-failure",
            initiated_by="user-1",
            purpose="failure contract",
            expires_at=NOW + timedelta(hours=1),
        ),
        invocation_id=invocation_id,
        tool_id=tool_id,
        implementation_id=implementation_id,
    )


def delegated_request() -> AuthorizationRequest:
    task = TaskContext(
        task_id="task-store-failure-delegated",
        initiated_by="user-1",
        purpose="failure contract",
        expires_at=NOW + timedelta(hours=1),
    )
    grant = DelegationGrant(
        grant_id="grant-store-failure",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
        scope=Scope(
            actions=frozenset({ACTION}),
            resource_prefixes=("customer:123",),
            max_numeric_arguments={"amount": 500},
        ),
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
    )
    return AuthorizationRequest(
        principal=Principal("billing-agent"),
        action=ACTION,
        resource=RESOURCE,
        arguments=ARGUMENTS,
        task=task,
        delegation_chain=(grant,),
        invoking_principal_id="user-1",
    )


class FailingPolicyStore:
    def evaluate(self, request):
        raise StoreUnavailableError("policy backend unavailable")


class FailingAuditLog:
    def append(self, request, decision):
        raise StoreUnavailableError("audit backend unavailable")


class FailingGrantStore:
    def register(self, grant):
        raise StoreUnavailableError("grant backend unavailable")

    def get(self, grant_id):
        raise StoreUnavailableError("grant backend unavailable")

    def contains(self, grant_id):
        raise StoreUnavailableError("grant backend unavailable")

    def is_registered(self, grant):
        raise StoreUnavailableError("grant backend unavailable")


class FailingRevocationStore:
    def revoke(self, grant_id, *, reason, revoked_at=None):
        raise StoreUnavailableError("revocation backend unavailable")

    def is_revoked(self, grant_id, *, at=None):
        raise StoreUnavailableError("revocation backend unavailable")

    def get(self, grant_id):
        raise StoreUnavailableError("revocation backend unavailable")

    def snapshot(self):
        raise StoreUnavailableError("revocation backend unavailable")


class FailingInvocationStore:
    def register(self, record):
        raise StoreUnavailableError("invocation backend unavailable")

    def get(self, invocation_id):
        raise StoreUnavailableError("invocation backend unavailable")

    def is_registered(self, invocation_id):
        raise StoreUnavailableError("invocation backend unavailable")


class FailingToolRegistry:
    def register(self, tool):
        raise StoreUnavailableError("tool registry unavailable")

    def get(self, tool_id, implementation_id):
        raise StoreUnavailableError("tool registry unavailable")

    def is_trusted(self, tool_id, implementation_id):
        raise StoreUnavailableError("tool registry unavailable")

    def allows_action(self, tool_id, implementation_id, action):
        raise StoreUnavailableError("tool registry unavailable")


class FailingExecutionStore:
    def claim(self, invocation_id, *, expires_at, now=None):
        raise StoreUnavailableError("execution backend unavailable")


class FailingRevalidationStore:
    """Succeeds on claim but fails on is_active (revalidation path)."""

    def __init__(self):
        self._claimed = False
        self._permit = None

    def claim(self, invocation_id, *, expires_at, now=None):
        permit = ExecutionPermit(
            invocation_id=invocation_id,
            claim_id=str(uuid4()),
            attempt=1,
        )
        self._permit = permit
        return ExecutionClaimResult(allowed=True, reason="claimed", permit=permit)

    def is_active(self, permit):
        raise StoreUnavailableError("execution backend unavailable during revalidation")


def test_policy_store_failure_is_deny_not_bypass() -> None:
    gate = Ruhusa(policy_store=FailingPolicyStore())
    decision = gate.authorize(direct_request(), now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "policy evaluation failed" in decision.reason


def test_audit_log_failure_turns_would_be_allow_into_deny() -> None:
    gate = Ruhusa(policy_store=allow_policy(), audit_log=FailingAuditLog())
    decision = gate.authorize(direct_request(), now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "audit log unavailable" in decision.reason
    assert decision.audit_id is None


def test_grant_store_failure_is_deny_not_bypass() -> None:
    gate = Ruhusa(policy_store=allow_policy(), grant_store=FailingGrantStore())
    decision = gate.authorize(delegated_request(), now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "grant issuance status unavailable" in decision.reason


def test_revocation_store_failure_is_deny_not_bypass() -> None:
    gate = Ruhusa(
        policy_store=allow_policy(),
        revocation_store=FailingRevocationStore(),
    )
    decision = gate.authorize(delegated_request(), now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "revocation status unavailable" in decision.reason


def test_invocation_store_failure_is_deny_not_bypass() -> None:
    gate = Ruhusa(
        policy_store=allow_policy(),
        invocation_store=FailingInvocationStore(),
    )
    decision = gate.authorize(
        direct_request(invocation_id="inv-store-failure"),
        now=NOW,
    )
    assert decision.effect == DecisionEffect.DENY
    assert "invocation store unavailable" in decision.reason


def test_tool_registry_failure_is_deny_not_bypass() -> None:
    gate = Ruhusa(
        policy_store=allow_policy(),
        tool_registry=FailingToolRegistry(),
    )
    decision = gate.authorize(
        direct_request(
            tool_id="billing_refund_tool",
            implementation_id="billing_refund_tool@v1",
        ),
        now=NOW,
    )
    assert decision.effect == DecisionEffect.DENY
    assert "tool registry unavailable" in decision.reason


def test_execution_store_failure_denies_execution_admission() -> None:
    invocation_store = InMemoryInvocationStore()
    record = InvocationRecord(
        invocation_id="inv-execution-store-failure",
        invoking_principal_id="user-1",
        executing_principal_id="billing-agent",
        task_id="task-store-failure",
        action=ACTION,
        resource=RESOURCE,
        arguments_digest=compute_arguments_digest(ARGUMENTS),
        tool_id=None,
        implementation_id=None,
        recorded_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(hours=1),
    )
    invocation_store.register(record)

    gate = Ruhusa(
        policy_store=allow_policy(),
        invocation_store=invocation_store,
    )
    controller = ExecutionController(
        gate,
        execution_store=FailingExecutionStore(),
    )
    decision = controller.begin(
        direct_request(invocation_id=record.invocation_id),
        now=NOW,
    )
    assert decision.allowed is False
    assert "execution lifecycle state unavailable" in decision.reason


def test_execution_store_failure_during_revalidation_denies() -> None:
    invocation_store = InMemoryInvocationStore()
    record = InvocationRecord(
        invocation_id="inv-revalidation-failure",
        invoking_principal_id="user-1",
        executing_principal_id="billing-agent",
        task_id="task-store-failure",
        action=ACTION,
        resource=RESOURCE,
        arguments_digest=compute_arguments_digest(ARGUMENTS),
        tool_id=None,
        implementation_id=None,
        recorded_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(hours=1),
    )
    invocation_store.register(record)

    revalidation_store = FailingRevalidationStore()
    gate = Ruhusa(
        policy_store=allow_policy(),
        invocation_store=invocation_store,
    )
    controller = ExecutionController(
        gate,
        execution_store=revalidation_store,
    )
    req = direct_request(invocation_id=record.invocation_id)
    claim_result = controller.begin(req, now=NOW)
    assert claim_result.permit is not None

    revalidation = controller.revalidate_before_execution(
        req,
        claim_result.permit,
        now=NOW,
    )
    assert revalidation.allowed is False
    assert "execution lifecycle state unavailable" in revalidation.reason
