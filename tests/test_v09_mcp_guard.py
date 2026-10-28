from datetime import UTC, datetime, timedelta

import pytest

from ruhusa import (
    DecisionEffect,
    InMemoryInvocationStore,
    InMemoryToolRegistry,
    PolicyRule,
    Principal,
    Ruhusa,
    StaticPolicyStore,
    TaskContext,
    ToolRegistration,
)
from ruhusa.integrations.mcp import (
    MCPAuthorizationDenied,
    MCPToolBinding,
    RuhusaMCPGuard,
    TrustedMCPContext,
)
from ruhusa.integrations.trusted import TrustedInvocationFactory


@pytest.fixture
def setup_guard():
    invocations = InMemoryInvocationStore()
    tools = InMemoryToolRegistry()
    tools.register(ToolRegistration("credit-tool", "credit-tool@v1", frozenset({"issue_credit"})))
    gate = Ruhusa(
        policy_store=StaticPolicyStore(
            [
                PolicyRule(
                    "credit-limit",
                    DecisionEffect.ALLOW,
                    frozenset({"issue_credit"}),
                    principal_ids=frozenset({"billing-agent"}),
                    resource_prefixes=("customer:123",),
                    condition=lambda req: (
                        req.resource == "customer:123"
                        and type(req.arguments.get("amount")) is int
                        and 0 <= req.arguments["amount"] <= 20
                    ),
                )
            ]
        ),
        invocation_store=invocations,
        tool_registry=tools,
    )
    guard = RuhusaMCPGuard(gate, invocation_factory=TrustedInvocationFactory(invocations))
    trusted = TrustedMCPContext(
        invoking_principal_id="billing-agent",
        executing_principal=Principal("billing-agent"),
        task=TaskContext(
            "task-1", "billing-agent", "credit", datetime.now(UTC) + timedelta(hours=1)
        ),
    )
    binding = MCPToolBinding(
        "issue_credit", "issue_credit", "credit-tool", "credit-tool@v1", "customer:123"
    )
    return guard, trusted, binding, invocations


@pytest.mark.asyncio
async def test_authorized_call_runs_once(setup_guard):
    guard, trusted, binding, _ = setup_guard
    calls = []

    async def handler(args):
        calls.append(dict(args))
        return "ok"

    assert (
        await guard.call(
            binding=binding, trusted=trusted, arguments={"amount": 20}, handler=handler
        )
        == "ok"
    )
    assert calls == [{"amount": 20}]


@pytest.mark.asyncio
async def test_over_limit_cannot_execute(setup_guard):
    guard, trusted, binding, _ = setup_guard
    called = False

    async def handler(args):
        nonlocal called
        called = True

    with pytest.raises(MCPAuthorizationDenied):
        await guard.call(
            binding=binding, trusted=trusted, arguments={"amount": 200}, handler=handler
        )
    assert not called


@pytest.mark.asyncio
async def test_unregistered_tool_identity_blocks_execution(setup_guard):
    guard, trusted, binding, _ = setup_guard
    called = False

    async def handler(args):
        nonlocal called
        called = True

    wrong = MCPToolBinding(
        binding.name, binding.action, binding.tool_id, "fake-implementation", binding.resource
    )
    with pytest.raises(MCPAuthorizationDenied):
        await guard.call(binding=wrong, trusted=trusted, arguments={"amount": 20}, handler=handler)
    assert not called


@pytest.mark.asyncio
async def test_expired_task_blocks_execution(setup_guard):
    guard, trusted, binding, _ = setup_guard
    expired = TrustedMCPContext(
        trusted.invoking_principal_id,
        trusted.executing_principal,
        TaskContext("task-1", "billing-agent", "credit", datetime.now(UTC) - timedelta(seconds=5)),
    )

    async def handler(args):
        pytest.fail("handler should never execute")

    with pytest.raises(MCPAuthorizationDenied):
        await guard.call(
            binding=binding, trusted=expired, arguments={"amount": 20}, handler=handler
        )


def test_weak_mode_is_rejected():
    with pytest.raises(ValueError, match="invocation_store and tool_registry"):
        RuhusaMCPGuard(
            Ruhusa(), invocation_factory=TrustedInvocationFactory(InMemoryInvocationStore())
        )


@pytest.mark.asyncio
async def test_store_failure_fails_closed(setup_guard):
    guard, trusted, binding, invocations = setup_guard

    def fail(_record):
        raise RuntimeError("database unavailable")

    invocations.register = fail

    async def handler(args):
        pytest.fail("handler should never execute")

    with pytest.raises(MCPAuthorizationDenied, match="infrastructure unavailable"):
        await guard.call(
            binding=binding, trusted=trusted, arguments={"amount": 20}, handler=handler
        )
