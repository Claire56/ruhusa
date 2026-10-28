"""Tests exercise the actual tools/call routing boundary without a network."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

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
from ruhusa.integrations.mcp_sdk import ProtectedMCPTool, RuhusaMCPToolRouter
from ruhusa.integrations.trusted import TrustedInvocationFactory


@pytest.fixture
def setup_router():
    invocations = InMemoryInvocationStore()
    tools = InMemoryToolRegistry()
    tools.register(ToolRegistration("credit-tool", "credit-tool@v1", frozenset({"issue_credit"})))
    gate = Ruhusa(
        policy_store=StaticPolicyStore(
            [
                PolicyRule(
                    "limit",
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
    calls = []

    async def issue_credit(args):
        calls.append(dict(args))
        return {"simulated_credit": args["amount"]}

    trusted = TrustedMCPContext(
        invoking_principal_id="billing-agent",
        executing_principal=Principal("billing-agent"),
        task=TaskContext(
            "task-1", "billing-agent", "credit", datetime.now(UTC) + timedelta(hours=1)
        ),
    )

    async def resolve(ctx):
        if not ctx.authenticated:
            raise PermissionError("not authenticated")
        return trusted

    router = RuhusaMCPToolRouter(
        guard,
        (
            ProtectedMCPTool(
                MCPToolBinding(
                    "issue_credit", "issue_credit", "credit-tool", "credit-tool@v1", "customer:123"
                ),
                "Simulate a customer credit",
                {
                    "type": "object",
                    "properties": {"amount": {"type": "integer"}},
                    "required": ["amount"],
                },
                issue_credit,
            ),
        ),
        trusted_context=resolve,
    )
    return router, calls


@pytest.mark.asyncio
async def test_allowed_tool_call_executes_once(setup_router):
    router, calls = setup_router
    result = await router.call(
        SimpleNamespace(authenticated=True), name="issue_credit", arguments={"amount": 20}
    )
    assert result == {"simulated_credit": 20}
    assert calls == [{"amount": 20}]


@pytest.mark.asyncio
@pytest.mark.parametrize("amount", [21, 200, True, -1])
async def test_denied_amount_never_runs_handler(setup_router, amount):
    router, calls = setup_router
    with pytest.raises(MCPAuthorizationDenied):
        await router.call(
            SimpleNamespace(authenticated=True), name="issue_credit", arguments={"amount": amount}
        )
    assert calls == []


@pytest.mark.asyncio
async def test_unknown_tool_cannot_select_another_binding(setup_router):
    router, calls = setup_router
    with pytest.raises(MCPAuthorizationDenied):
        await router.call(
            SimpleNamespace(authenticated=True), name="admin_credit", arguments={"amount": 20}
        )
    assert calls == []


@pytest.mark.asyncio
async def test_client_supplied_identity_does_not_override_trusted_context(setup_router):
    router, calls = setup_router
    with pytest.raises(MCPAuthorizationDenied):
        await router.call(
            SimpleNamespace(authenticated=False),
            name="issue_credit",
            arguments={"amount": 20, "principal": "billing-agent", "task_id": "task-1"},
        )
    assert calls == []


@pytest.mark.asyncio
async def test_authenticated_extra_fields_do_not_expand_permission(setup_router):
    router, calls = setup_router
    with pytest.raises(MCPAuthorizationDenied):
        await router.call(
            SimpleNamespace(authenticated=True),
            name="issue_credit",
            arguments={"amount": 200, "principal": "admin"},
        )
    assert calls == []


@pytest.mark.asyncio
async def test_mutable_argument_mapping_must_be_dict(setup_router):
    router, calls = setup_router
    with pytest.raises(MCPAuthorizationDenied):
        await router.call(SimpleNamespace(authenticated=True), name="issue_credit", arguments=[20])
    assert calls == []


def test_duplicate_tool_registration_rejected(setup_router):
    router, _ = setup_router
    with pytest.raises(ValueError, match="unique"):
        RuhusaMCPToolRouter(
            router._guard, router.tools * 2, trusted_context=router._trusted_context
        )


@pytest.mark.asyncio
async def test_sdk_handler_dispatch_with_stubbed_sdk(setup_router, monkeypatch):
    """Verify SDK handler wiring without requiring the optional SDK in core CI."""
    import sys
    from types import ModuleType

    from ruhusa.integrations.mcp_sdk import create_mcp_sdk_server

    class FakeServer:
        def __init__(self, name, *, on_list_tools, on_call_tool):
            self.name = name
            self.on_list_tools = on_list_tools
            self.on_call_tool = on_call_tool

    class FakeTool:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class FakeResult:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class FakeText:
        def __init__(self, *, type, text):
            self.type = type
            self.text = text

    server_module = ModuleType("mcp.server")
    server_module.Server = FakeServer
    types_module = ModuleType("mcp.types")
    types_module.Tool = FakeTool
    types_module.CallToolResult = FakeResult
    types_module.ListToolsResult = FakeResult
    types_module.TextContent = FakeText
    root_module = ModuleType("mcp")
    root_module.server = server_module
    root_module.types = types_module
    monkeypatch.setitem(sys.modules, "mcp", root_module)
    monkeypatch.setitem(sys.modules, "mcp.server", server_module)
    monkeypatch.setitem(sys.modules, "mcp.types", types_module)

    router, calls = setup_router
    sdk_server = create_mcp_sdk_server(router)
    tools = await sdk_server.on_list_tools(None, None)
    assert [tool.name for tool in tools.tools] == ["issue_credit"]

    allowed = await sdk_server.on_call_tool(
        SimpleNamespace(authenticated=True),
        SimpleNamespace(name="issue_credit", arguments={"amount": 20}),
    )
    assert not getattr(allowed, "is_error", False)
    assert calls == [{"amount": 20}]

    denied = await sdk_server.on_call_tool(
        SimpleNamespace(authenticated=True),
        SimpleNamespace(name="issue_credit", arguments={"amount": 200}),
    )
    assert denied.is_error is True
    assert denied.content[0].text == "Tool call not authorized"
    assert calls == [{"amount": 20}]
