from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from ..interfaces import InvocationStore
from ..invocations import InvocationRecord, compute_arguments_digest
from ..models import AuthorizationRequest, DelegationGrant, Principal, TaskContext


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _require_non_empty(name: str, value: str) -> str:
    if not value.strip():
        raise ValueError(f"{name} must not be empty")
    return value


@dataclass(frozen=True)
class PreparedInvocation:
    """Canonical provenance plus the matching authorization request."""

    record: InvocationRecord
    request: AuthorizationRequest


class TrustedInvocationFactory:
    """Create canonical invocation provenance from trusted runtime observations."""

    def __init__(self, invocation_store: InvocationStore) -> None:
        self._invocation_store = invocation_store

    def create(
        self,
        *,
        invoking_principal_id: str,
        executing_principal: Principal,
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
        invoking_principal_id = _require_non_empty("invoking_principal_id", invoking_principal_id)
        _require_non_empty(
            "executing_principal.principal_id",
            executing_principal.principal_id,
        )
        action = _require_non_empty("action", action)
        resource = _require_non_empty("resource", resource)

        if (tool_id is None) != (implementation_id is None):
            raise ValueError(
                "tool_id and implementation_id must either both be provided or both be omitted"
            )

        if tool_id is not None:
            tool_id = _require_non_empty("tool_id", tool_id)
            implementation_id = _require_non_empty(
                "implementation_id",
                implementation_id or "",
            )

        observed_at = _as_utc(now or datetime.now(UTC))
        invocation_expiry = _as_utc(expires_at)
        task_expiry = _as_utc(task.expires_at)

        if observed_at >= task_expiry:
            raise ValueError("cannot create an invocation for an expired task")

        if observed_at >= invocation_expiry:
            raise ValueError("invocation expiry must be in the future")

        if invocation_expiry > task_expiry:
            raise ValueError("invocation expiry must not exceed task expiry")

        canonical_arguments = deepcopy(dict(arguments))
        canonical_context = deepcopy(dict(context or {}))
        canonical_chain = tuple(delegation_chain)

        canonical_id = invocation_id or uuid4().hex
        canonical_id = _require_non_empty("invocation_id", canonical_id)

        record = InvocationRecord(
            invocation_id=canonical_id,
            invoking_principal_id=invoking_principal_id,
            executing_principal_id=executing_principal.principal_id,
            task_id=task.task_id,
            action=action,
            resource=resource,
            arguments_digest=compute_arguments_digest(canonical_arguments),
            tool_id=tool_id,
            implementation_id=implementation_id,
            recorded_at=observed_at,
            expires_at=invocation_expiry,
        )

        registered = self._invocation_store.register(record)

        if registered != record:
            raise RuntimeError("invocation store returned a different canonical record")

        request = AuthorizationRequest(
            principal=executing_principal,
            action=action,
            resource=resource,
            arguments=canonical_arguments,
            task=task,
            delegation_chain=canonical_chain,
            context=canonical_context,
            invocation_id=canonical_id,
            invoking_principal_id=None,
            tool_id=None,
            implementation_id=None,
        )

        return PreparedInvocation(record=record, request=request)
