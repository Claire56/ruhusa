"""Optional MCP Python SDK v2 tool-handler integration (v0.9-C2 experimental).

Use the SDK's low-level ``on_call_tool`` entry point, rather than provisional
middleware hooks. All names, bindings, and trusted context are server-owned.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .mcp import MCPAuthorizationDenied, MCPToolBinding, RuhusaMCPGuard, TrustedMCPContext


@dataclass(frozen=True)
class ProtectedMCPTool:
    """Trusted registration, advertised schema, and side-effect-free handler."""

    binding: MCPToolBinding
    description: str
    input_schema: Mapping[str, Any]
    handler: Callable[[Mapping[str, Any]], Awaitable[Any]]


class RuhusaMCPToolRouter:
    """The only tools/call dispatch path for registered protected tools.

    ``trusted_context`` must authenticate the real MCP transport/session and
    retrieve trusted task context; never inspect model-supplied arguments or
    unverified MCP metadata to create a principal or authority.
    """

    def __init__(
        self,
        guard: RuhusaMCPGuard,
        tools: tuple[ProtectedMCPTool, ...],
        *,
        trusted_context: Callable[[Any], Awaitable[TrustedMCPContext]],
    ) -> None:
        if not tools:
            raise ValueError("at least one protected tool is required")
        names = [tool.binding.name for tool in tools]
        if len(names) != len(set(names)) or any(not name for name in names):
            raise ValueError("MCP tool names must be unique and non-empty")
        self._guard = guard
        self._tools = {tool.binding.name: tool for tool in tools}
        self._trusted_context = trusted_context

    @property
    def tools(self) -> tuple[ProtectedMCPTool, ...]:
        return tuple(self._tools.values())

    async def call(self, ctx: Any, *, name: str, arguments: Mapping[str, Any]) -> Any:
        """Fail closed for unknown tools, bad args, auth failures, and missing identity."""
        tool = self._tools.get(name)
        if tool is None:
            raise MCPAuthorizationDenied("tool call not authorized")
        if not isinstance(arguments, dict):
            raise MCPAuthorizationDenied("tool call not authorized")
        try:
            trusted = await self._trusted_context(ctx)
            if not isinstance(trusted, TrustedMCPContext):
                raise TypeError("trusted context resolver returned invalid context")
        except Exception as exc:
            raise MCPAuthorizationDenied("trusted identity unavailable") from exc
        return await self._guard.call(
            binding=tool.binding,
            trusted=trusted,
            arguments=arguments,
            handler=tool.handler,
        )


def create_mcp_sdk_server(router: RuhusaMCPToolRouter, *, name: str = "Ruhusa MCP") -> Any:
    """Create an MCP Python SDK v2 low-level Server with protected call handlers.

    Requires the optional ``mcp`` SDK v2; import is deferred so Ruhusa's core
    can still be installed without MCP. Transport authentication must be
    configured by the host before exposing the server over HTTP.
    """
    try:
        from mcp.server import Server
        from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool
    except ImportError as exc:
        raise RuntimeError("MCP Python SDK v2 is required; install 'mcp>=2,<3'") from exc

    async def list_tools(ctx: Any, params: Any) -> Any:
        return ListToolsResult(
            tools=[
                Tool(
                    name=tool.binding.name,
                    description=tool.description,
                    input_schema=dict(tool.input_schema),
                )
                for tool in router.tools
            ]
        )

    async def call_tool(ctx: Any, params: Any) -> Any:
        try:
            result = await router.call(ctx, name=params.name, arguments=params.arguments or {})
        except MCPAuthorizationDenied:
            # Do not leak policy internals, identity, or audit backend details.
            return CallToolResult(
                content=[TextContent(type="text", text="Tool call not authorized")],
                is_error=True,
            )
        # Non-auth execution errors intentionally propagate as handler failures.
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, default=str))],
        )

    return Server(name, on_list_tools=list_tools, on_call_tool=call_tool)
