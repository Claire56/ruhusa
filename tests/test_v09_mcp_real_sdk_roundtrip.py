"""Actual MCP SDK protocol round-trip, optional until SDK v2 is installed.

This uses the SDK's in-process transport (real Client and low-level Server),
not mocks. No TCP listener or customer ledger is involved.
"""

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
from ruhusa.integrations.mcp import MCPToolBinding, RuhusaMCPGuard, TrustedMCPContext
from ruhusa.integrations.mcp_sdk import (
    ProtectedMCPTool,
    RuhusaMCPToolRouter,
    create_mcp_sdk_server,
)
from ruhusa.integrations.trusted import TrustedInvocationFactory


@pytest.mark.asyncio
async def test_real_mcp_client_server_enforces_before_tool_execution():
    """A real tools/call passes ALLOW but DENY and missing identity never execute."""
    mcp = pytest.importorskip("mcp", reason="install MCP Python SDK v2 for protocol round-trip")
    if not hasattr(mcp, "Client"):
        pytest.skip("requires MCP Python SDK v2 Client API")

    invocations = InMemoryInvocationStore()
    registry = InMemoryToolRegistry()
    registry.register(
        ToolRegistration("credit-tool", "credit-tool@v1", frozenset({"issue_credit"}))
    )
    authorization = Ruhusa(
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
        tool_registry=registry,
    )
    guard = RuhusaMCPGuard(authorization, invocation_factory=TrustedInvocationFactory(invocations))
    executed: list[int] = []
    authenticated = True  # Test-only server-owned session state, never an MCP argument.

    async def handler(args):
        executed.append(args["amount"])
        return {"simulated_credit": args["amount"]}

    async def resolve_context(_request_context):
        if not authenticated:
            raise PermissionError("not authenticated")
        return TrustedMCPContext(
            invoking_principal_id="billing-agent",
            executing_principal=Principal("billing-agent"),
            task=TaskContext(
                "task-mcp-roundtrip",
                "billing-agent",
                "credit",
                datetime.now(UTC) + timedelta(hours=1),
            ),
        )

    router = RuhusaMCPToolRouter(
        guard,
        tools=(
            ProtectedMCPTool(
                binding=MCPToolBinding(
                    "issue_credit", "issue_credit", "credit-tool", "credit-tool@v1", "customer:123"
                ),
                description="Simulate customer credit; no external side effects",
                input_schema={
                    "type": "object",
                    "properties": {"amount": {"type": "integer"}},
                    "required": ["amount"],
                    "additionalProperties": False,
                },
                handler=handler,
            ),
        ),
        trusted_context=resolve_context,
    )
    server = create_mcp_sdk_server(router, name="Ruhusa round-trip test")

    async with mcp.Client(server) as client:
        advertised = await client.list_tools()
        assert [tool.name for tool in advertised.tools] == ["issue_credit"]

        allowed = await client.call_tool("issue_credit", {"amount": 20})
        assert not allowed.is_error
        assert executed == [20]

        denied = await client.call_tool("issue_credit", {"amount": 200})
        assert denied.is_error
        assert executed == [20], "denied tool must not run side-effect handler"

        authenticated = False
        unauthenticated = await client.call_tool("issue_credit", {"amount": 20})
        assert unauthenticated.is_error
        assert executed == [20], "untrusted session must not run side-effect handler"
