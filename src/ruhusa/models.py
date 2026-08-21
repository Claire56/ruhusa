from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class DecisionEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    principal_type: str = "agent"
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TaskContext:
    task_id: str
    initiated_by: str
    purpose: str
    expires_at: datetime
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return now >= expiry


@dataclass(frozen=True)
class Scope:
    actions: frozenset[str]
    resource_prefixes: tuple[str, ...] = ()
    max_numeric_arguments: Mapping[str, float] = field(default_factory=dict)

    def allows_action(self, action: str) -> bool:
        return action in self.actions

    def allows_resource(self, resource: str) -> bool:
        if not self.resource_prefixes:
            return True
        return any(resource.startswith(prefix) for prefix in self.resource_prefixes)

    def allows_arguments(self, arguments: Mapping[str, Any]) -> bool:
        for key, max_value in self.max_numeric_arguments.items():
            if key not in arguments:
                continue
            value = arguments[key]
            if not isinstance(value, (int, float)):
                return False
            if float(value) > max_value:
                return False
        return True

    def is_subset_of(self, parent: Scope) -> bool:
        if not self.actions.issubset(parent.actions):
            return False

        # A child resource prefix must be equal to or narrower than at least one parent prefix.
        if parent.resource_prefixes:
            if not self.resource_prefixes:
                # Child would become unrestricted while the parent is restricted.
                return False
            for child_prefix in self.resource_prefixes:
                if not any(
                    child_prefix.startswith(parent_prefix)
                    for parent_prefix in parent.resource_prefixes
                ):
                    return False
        elif self.resource_prefixes:
            # Parent is unrestricted, so any child restriction is narrower and valid.
            pass

        for arg_name, child_max in self.max_numeric_arguments.items():
            parent_max = parent.max_numeric_arguments.get(arg_name)
            if parent_max is not None and child_max > parent_max:
                return False

        # If the child drops a numeric limit that the parent had, that would widen authority.
        for arg_name in parent.max_numeric_arguments:
            if arg_name not in self.max_numeric_arguments:
                return False

        return True


@dataclass(frozen=True)
class DelegationGrant:
    grant_id: str
    grantor_id: str
    grantee_id: str
    task_id: str
    scope: Scope
    issued_at: datetime
    expires_at: datetime

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return now >= expiry


@dataclass(frozen=True)
class AuthorizationRequest:
    principal: Principal
    action: str
    resource: str
    arguments: Mapping[str, Any]
    task: TaskContext
    delegation_chain: tuple[DelegationGrant, ...] = ()
    context: Mapping[str, Any] = field(default_factory=dict)
    invocation_id: str | None = None
    """Opaque reference to an :class:`~ruhusa.invocations.InvocationRecord`
    registered by the trusted orchestration layer.

    When Ruhusa is configured with an
    :class:`~ruhusa.invocations.InMemoryInvocationStore`, this field is
    **required** and used for *strong* invocation provenance (INV-17): the
    record in the store — not any field the executing agent supplies — is the
    authoritative source of the invoking principal's identity.  Omitting this
    field when a store is configured is a hard ``DENY``.

    When no store is configured, ``invoking_principal_id`` is used instead
    (weak / backward-compatible mode).
    """

    invoking_principal_id: str | None = None
    """*Self-asserted* identity of the invoking principal.

    .. warning::

        This field is supplied by the executing agent through the
        :class:`AuthorizationRequest` it constructs.  An attacker who controls
        the agent can forge any value here.  For production deployments, prefer
        the :class:`~ruhusa.invocations.InMemoryInvocationStore` + ``invocation_id``
        flow (strong provenance) over relying on this field alone.

    Used for INV-17 only when **no** invocation store is configured (weak
    mode, backward-compatible).  When a store is configured, this field is
    ignored — only the store's
    :attr:`~ruhusa.invocations.InvocationRecord.invoking_principal_id` is
    authoritative.
    """

    tool_id: str | None = None
    """Logical name of the tool that will execute this action
    (e.g. ``"billing_refund_tool"``).  Must be populated by the orchestration
    layer; an executing agent must not supply its own ``tool_id``.

    When Ruhusa is configured with a :class:`~ruhusa.tools.InMemoryToolRegistry`,
    both ``tool_id`` and ``implementation_id`` are required.  Omitting either
    field is treated as a tool-identity failure and results in ``DENY``.
    """

    implementation_id: str | None = None
    """Content-addressed identity of the specific tool implementation
    (e.g. ``"billing_refund_tool@v1.2.0-sha256:abc..."``).  Must be populated
    by the orchestration layer and must match a registration in the
    :class:`~ruhusa.tools.InMemoryToolRegistry`.

    A logical tool name alone (``tool_id``) is insufficient — two implementations
    may share the same name while differing in behaviour.  The pair
    ``(tool_id, implementation_id)`` is the unit of trust enforced by INV-18.
    """


@dataclass(frozen=True)
class AuthorizationDecision:
    effect: DecisionEffect
    reason: str
    policy_id: str | None = None
    obligations: tuple[str, ...] = ()
    audit_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.effect == DecisionEffect.ALLOW
