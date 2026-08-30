from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime
from typing import Any

from fastapi import Request

from ..models import DelegationGrant, Principal, TaskContext
from .trusted import PreparedInvocation, TrustedInvocationFactory

InvokingPrincipalResolver = Callable[[Request], str | Awaitable[str]]
ExecutingPrincipalResolver = Callable[[Request], Principal | Awaitable[Principal]]


class FastAPIIntegrationError(RuntimeError):
    """Trusted FastAPI integration state is missing or invalid."""


async def _resolve(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


class FastAPITrustedInvocationAdapter:
    """Bridge authenticated FastAPI request state into trusted Ruhusa provenance.

    Resolvers must derive identity from authentication state established by
    trusted server-side middleware or dependencies. The adapter deliberately
    does not parse identity from arbitrary request headers.
    """

    def __init__(
        self,
        factory: TrustedInvocationFactory,
        *,
        invoking_principal_resolver: InvokingPrincipalResolver,
        executing_principal_resolver: ExecutingPrincipalResolver,
    ) -> None:
        self._factory = factory
        self._invoking_principal_resolver = invoking_principal_resolver
        self._executing_principal_resolver = executing_principal_resolver

    @classmethod
    def from_request_state(
        cls,
        factory: TrustedInvocationFactory,
        *,
        invoking_principal_attribute: str = "ruhusa_invoking_principal_id",
        executing_principal_attribute: str = "ruhusa_executing_principal",
    ) -> "FastAPITrustedInvocationAdapter":
        """Resolve trusted identity from values placed on ``request.state``.

        The application is responsible for populating those values only after
        authenticating the request. This helper never falls back to headers.
        """

        def resolve_invoker(request: Request) -> str:
            try:
                value = getattr(request.state, invoking_principal_attribute)
            except AttributeError as exc:
                raise FastAPIIntegrationError(
                    f"trusted request state {invoking_principal_attribute!r} is missing"
                ) from exc
            if not isinstance(value, str) or not value.strip():
                raise FastAPIIntegrationError(
                    f"trusted request state {invoking_principal_attribute!r} must be a non-empty string"
                )
            return value

        def resolve_executor(request: Request) -> Principal:
            try:
                value = getattr(request.state, executing_principal_attribute)
            except AttributeError as exc:
                raise FastAPIIntegrationError(
                    f"trusted request state {executing_principal_attribute!r} is missing"
                ) from exc
            if not isinstance(value, Principal):
                raise FastAPIIntegrationError(
                    f"trusted request state {executing_principal_attribute!r} must be a Ruhusa Principal"
                )
            return value

        return cls(
            factory,
            invoking_principal_resolver=resolve_invoker,
            executing_principal_resolver=resolve_executor,
        )

    async def prepare(
        self,
        request: Request,
        *,
        task: TaskContext,
        action: str,
        resource: str,
        arguments: Mapping[str, Any],
        expires_at: datetime,
        tool_id: str | None = None,
        implementation_id: str | None = None,
        delegation_chain: tuple[DelegationGrant, ...] = (),
        context: Mapping[str, Any] | None = None,
        invocation_id: str | None = None,
        now: datetime | None = None,
    ) -> PreparedInvocation:
        """Resolve trusted runtime identity and create canonical provenance."""
        invoking_principal_id = await _resolve(self._invoking_principal_resolver(request))
        executing_principal = await _resolve(self._executing_principal_resolver(request))

        if not isinstance(invoking_principal_id, str) or not invoking_principal_id.strip():
            raise FastAPIIntegrationError(
                "invoking principal resolver must return a non-empty string"
            )
        if not isinstance(executing_principal, Principal):
            raise FastAPIIntegrationError(
                "executing principal resolver must return a Ruhusa Principal"
            )

        return self._factory.create(
            invoking_principal_id=invoking_principal_id,
            executing_principal=executing_principal,
            task=task,
            action=action,
            resource=resource,
            arguments=arguments,
            expires_at=expires_at,
            tool_id=tool_id,
            implementation_id=implementation_id,
            delegation_chain=delegation_chain,
            context=context,
            invocation_id=invocation_id,
            now=now,
        )
