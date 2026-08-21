from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolRegistration:
    """A trusted tool implementation registered through the orchestration boundary.

    ``tool_id`` identifies the logical tool (e.g. ``"billing_refund_tool"``).
    ``implementation_id`` identifies the specific implementation, typically a
    content-addressed string such as
    ``"billing_refund_tool@v1.2.0-sha256:abc..."``.

    Both must be supplied to establish tool identity.  A logical name alone is
    insufficient because different implementations — including adversarial ones —
    can claim the same name.  The pair ``(tool_id, implementation_id)`` is the
    unit of trust.
    """

    tool_id: str
    implementation_id: str
    allowed_actions: frozenset[str]


class InMemoryToolRegistry:
    """Trusted registry of tool implementations.

    Registration is immutable: once a ``(tool_id, implementation_id)`` pair is
    registered it cannot be overwritten.  This mirrors :class:`InMemoryGrantStore`
    and prevents registry-poisoning attacks where a malicious caller could replace
    a trusted entry with a substitute.

    The registry is populated by the orchestration layer, not by agents.

    **Weak mode** (no :class:`~ruhusa.invocations.InMemoryInvocationStore`
    configured): Ruhusa reads ``tool_id`` and ``implementation_id`` from the
    :class:`~ruhusa.models.AuthorizationRequest`.  These fields are supplied by
    the executing agent and are therefore self-asserted — a compromised agent can
    forge them to claim any registered identity.  This mode blocks unregistered
    implementations but cannot detect an agent that falsely claims a registered
    implementation it is not actually using.

    **Strong mode** (:class:`~ruhusa.invocations.InMemoryInvocationStore`
    configured): Ruhusa reads ``tool_id`` and ``implementation_id`` from the
    :class:`~ruhusa.invocations.InvocationRecord` registered by the orchestrator.
    The orchestrator observes the actual tool implementation at invocation time;
    the executing agent cannot influence the record.  The self-asserted fields on
    the request are ignored entirely in this mode.  See INV-18 in the
    :class:`~ruhusa.core.Ruhusa` security invariants.
    """

    def __init__(self) -> None:
        self._tools: dict[tuple[str, str], ToolRegistration] = {}

    def register(self, tool: ToolRegistration) -> ToolRegistration:
        """Register a tool implementation through the trusted boundary.

        Raises :exc:`ValueError` if this ``(tool_id, implementation_id)`` pair is
        already registered, enforcing immutability of the registry.
        """
        key = (tool.tool_id, tool.implementation_id)
        if key in self._tools:
            raise ValueError(
                f"tool {tool.tool_id!r} implementation"
                f" {tool.implementation_id!r} is already registered"
            )
        self._tools[key] = tool
        return tool

    def is_trusted(self, tool_id: str, implementation_id: str) -> bool:
        """Return ``True`` if ``(tool_id, implementation_id)`` is in the registry."""
        return (tool_id, implementation_id) in self._tools

    def get(self, tool_id: str, implementation_id: str) -> ToolRegistration | None:
        """Return the registration for ``(tool_id, implementation_id)``, or ``None``."""
        return self._tools.get((tool_id, implementation_id))

    def allows_action(self, tool_id: str, implementation_id: str, action: str) -> bool:
        """Return ``True`` if the registered tool is authorized to perform ``action``."""
        registration = self.get(tool_id, implementation_id)
        if registration is None:
            return False
        return action in registration.allowed_actions
