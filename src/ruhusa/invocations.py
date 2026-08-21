from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any


def compute_arguments_digest(arguments: Mapping[str, Any]) -> str:
    """Return a deterministic SHA-256 hex digest of an arguments mapping.

    The digest is derived from a canonical JSON serialisation: keys sorted
    alphabetically, no extra whitespace.  Use this helper both when creating
    an :class:`InvocationRecord` and when verifying one so that both sides
    always compare identically serialised data.

    Example::

        record = InvocationRecord(
            ...
            arguments_digest=compute_arguments_digest({"amount": 250}),
            ...
        )
    """
    canonical = json.dumps(dict(arguments), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class InvocationRecord:
    """Authenticated record of a single agent invocation.

    Created and registered by the trusted orchestration layer at the moment
    an agent is invoked.  The orchestrator observes the actual caller identity,
    the actual tool implementation, and the exact operation parameters from its
    own runtime context — not from any field supplied by the executing agent —
    and embeds them here.

    The executing agent cannot forge this record: it does not hold write access
    to the :class:`InMemoryInvocationStore`.  The record is therefore a trusted
    provenance artifact for:

    * **Invocation identity** (INV-17): who caused this invocation to happen.
    * **Operation binding**: exactly which action, resource, and arguments this
      invocation was created to perform.  Ruhusa cross-checks these against the
      live request so that an ``invocation_id`` cannot be replayed for a
      different operation.
    * **Tool identity** (INV-18, strong mode): which tool implementation the
      orchestrator actually resolved.  The self-asserted ``tool_id`` /
      ``implementation_id`` fields on the request are ignored in strong mode.
    * **Temporal validity**: the record carries its own ``expires_at`` so that
      stale invocation IDs are rejected even when the parent task is still
      active.

    Attributes:
        invocation_id: Opaque reference placed in
            :attr:`~ruhusa.models.AuthorizationRequest.invocation_id` by the
            orchestrator.
        invoking_principal_id: Authenticated identity of the principal that
            caused this invocation (the caller the orchestrator actually
            observed — not a field the agent supplies).
        executing_principal_id: Identity of the agent that will perform the
            authorized action.
        task_id: Task this invocation belongs to.  Ruhusa cross-checks this
            against :attr:`~ruhusa.models.TaskContext.task_id` in the request.
        action: The exact action this invocation is authorised to perform.
            Ruhusa cross-checks this against
            :attr:`~ruhusa.models.AuthorizationRequest.action`.
        resource: The exact resource this invocation is authorised to operate
            on.  Ruhusa cross-checks this against
            :attr:`~ruhusa.models.AuthorizationRequest.resource`.
        arguments_digest: SHA-256 digest of the canonical JSON serialisation of
            the authorised arguments (see :func:`compute_arguments_digest`).
            Ruhusa recomputes the digest from the live request arguments and
            compares it here, preventing argument substitution within an
            otherwise valid invocation.
        tool_id: Logical name of the tool the orchestrator resolved for this
            invocation.  When present and a tool registry is configured in
            strong mode, Ruhusa verifies this pair against the registry instead
            of the self-asserted ``tool_id`` on the request.  ``None`` means
            the invocation is not tool-mediated and no registry check is
            performed.
        implementation_id: Content-addressed identity of the actual tool
            implementation the orchestrator resolved.  See ``tool_id``.
        recorded_at: Timestamp set by the orchestrator at the moment of
            registration.
        expires_at: After this point the invocation record is considered stale
            and Ruhusa will deny any request that references it, even if the
            parent task is still active.
    """

    invocation_id: str
    invoking_principal_id: str
    executing_principal_id: str
    task_id: str

    # Operation binding — what this invocation was created to do.
    action: str
    resource: str
    arguments_digest: str

    # Tool identity — the orchestrator's resolved tool, not the agent's claim.
    tool_id: str | None
    implementation_id: str | None

    recorded_at: datetime
    expires_at: datetime


class InMemoryInvocationStore:
    """Trusted registry of invocation records.

    Populated by the orchestration layer; inaccessible for writes to executing
    agents.  Registration is immutable: once an ``invocation_id`` is registered
    it cannot be overwritten, preventing a *replacement* attack (where an
    attacker overwrites a legitimate record with a forged one).

    .. note::
        Immutability alone does not prevent *replay* — an attacker who
        observes a legitimate ``invocation_id`` could attempt to present it for
        a different operation.  Replay is addressed by the operation-binding
        fields on :class:`InvocationRecord` (``action``, ``resource``,
        ``arguments_digest``) and the ``expires_at`` timestamp, which Ruhusa
        cross-checks against the live request.

    The security model mirrors :class:`~ruhusa.grants.InMemoryGrantStore`:

    * The trusted boundary (orchestrator) creates and registers records.
    * Ruhusa reads records to verify invocation provenance.
    * Agents can supply an ``invocation_id`` in their request but cannot
      influence what the store says about that id.

    When Ruhusa is configured with an :class:`InMemoryInvocationStore`:

    * The request's ``invoking_principal_id`` field is **not used** for the
      INV-17 check — only the store's record is authoritative.
    * The request's ``tool_id`` / ``implementation_id`` fields are **not used**
      for the INV-18 registry check — only the record's tool fields are used.
    """

    def __init__(self) -> None:
        self._records: dict[str, InvocationRecord] = {}

    def register(self, record: InvocationRecord) -> InvocationRecord:
        """Register an invocation record through the trusted boundary.

        Raises :exc:`ValueError` if this ``invocation_id`` is already
        registered, enforcing immutability of the store.
        """
        if record.invocation_id in self._records:
            raise ValueError(f"invocation {record.invocation_id!r} is already registered")
        self._records[record.invocation_id] = record
        return record

    def get(self, invocation_id: str) -> InvocationRecord | None:
        """Return the :class:`InvocationRecord` for ``invocation_id``, or ``None``."""
        return self._records.get(invocation_id)

    def is_registered(self, invocation_id: str) -> bool:
        """Return ``True`` if ``invocation_id`` is in the trusted store."""
        return invocation_id in self._records
