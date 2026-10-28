"""Fail-closed MCP tool-call enforcement boundary (v0.9-C, experimental).

This is a transport-neutral adapter, not an MCP SDK server or middleware.
Only the arguments mapping comes from the untrusted MCP client. A trusted
server-side resolver supplies all authorization identity and resource bindings.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

from ..core import Ruhusa
from ..models import DecisionEffect, DelegationGrant, Principal, TaskContext
from .trusted import TrustedInvocationFactory

T = TypeVar("T")


class MCPAuthorizationDenied(PermissionError):
    """Tool execution was not authorized (including approval-required cases)."""


@dataclass(frozen=True)
class TrustedMCPContext:
    """Server-authenticated context, never parsed from MCP model arguments."""

    invoking_principal_id: str
    executing_principal: Principal
    task: TaskContext
    delegation_chain: tuple[DelegationGrant, ...] = ()


@dataclass(frozen=True)
class MCPToolBinding:
    """Server-defined mapping between an MCP tool and its protected resource."""

    name: str
    action: str
    tool_id: str
    implementation_id: str
    resource: str


class RuhusaMCPGuard:
    """Authorize a tool call before invoking its async handler.

    Requires strong invocation provenance and a tool registry. Identity and
    binding resolution MUST occur on the trusted server side; NEVER use
    client-provided metadata or tool arguments for those values.

    This guard does not provide atomic execution fencing or idempotency.
    """

    def __init__(
        self,
        authorization: Ruhusa,
        *,
        invocation_factory: TrustedInvocationFactory,
        invocation_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if authorization.invocation_store is None or authorization.tool_registry is None:
            raise ValueError("MCP enforcement requires invocation_store and tool_registry")
        if invocation_ttl <= timedelta(0):
            raise ValueError("invocation_ttl must be positive")
        self._authorization = authorization
        self._factory = invocation_factory
        self._ttl = invocation_ttl

    async def call(
        self,
        *,
        binding: MCPToolBinding,
        trusted: TrustedMCPContext,
        arguments: Mapping[str, Any],
        handler: Callable[[Mapping[str, Any]], Awaitable[T]],
    ) -> T:
        """Execute the handler only if the actual Ruhusa decision is ALLOW.

        Failures in provenance, audit, policy, or authorization block execution.
        Handler exceptions are propagated, not masked as authorization errors.
        """
        try:
            now = datetime.now(UTC)
            expiry = min(trusted.task.expires_at, now + self._ttl)
            prepared = self._factory.create(
                invoking_principal_id=trusted.invoking_principal_id,
                executing_principal=trusted.executing_principal,
                task=trusted.task,
                action=binding.action,
                resource=binding.resource,
                arguments=arguments,
                expires_at=expiry,
                tool_id=binding.tool_id,
                implementation_id=binding.implementation_id,
                delegation_chain=trusted.delegation_chain,
                now=now,
            )
            decision = self._authorization.authorize(prepared.request, now=now)
        except Exception as exc:
            raise MCPAuthorizationDenied("authorization infrastructure unavailable") from exc

        if decision.effect != DecisionEffect.ALLOW:
            raise MCPAuthorizationDenied(f"tool call not authorized: {decision.effect.value}")

        # Use canonical arguments stored in the request, not a potentially mutable
        # client mapping that could change between authorization and execution.
        return await handler(prepared.request.arguments)
