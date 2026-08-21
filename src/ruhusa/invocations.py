from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class InvocationRecord:
    """Authenticated record of a single agent invocation.

    Created and registered by the trusted orchestration layer at the moment
    an agent is invoked.  The orchestrator observes the actual caller identity
    from its own runtime context — not from any field supplied by the executing
    agent — and embeds it here.

    The executing agent cannot forge this record: it does not hold write access
    to the :class:`InMemoryInvocationStore`.  The record is therefore a trusted
    provenance artifact, equivalent in trust level to a
    :class:`~ruhusa.grants.DelegationGrant` registered through the grant store.

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
        recorded_at: Timestamp set by the orchestrator.
    """

    invocation_id: str
    invoking_principal_id: str
    executing_principal_id: str
    task_id: str
    recorded_at: datetime


class InMemoryInvocationStore:
    """Trusted registry of invocation records.

    Populated by the orchestration layer; inaccessible for writes to executing
    agents.  Registration is immutable: once an ``invocation_id`` is registered
    it cannot be overwritten, preventing a replay or replacement attack.

    The security model mirrors :class:`~ruhusa.grants.InMemoryGrantStore`:

    * The trusted boundary (orchestrator) creates and registers records.
    * Ruhusa reads records to authenticate invocation provenance.
    * Agents can supply an ``invocation_id`` in their request but cannot
      influence what the store says about that id.

    When Ruhusa is configured with an :class:`InMemoryInvocationStore`, the
    :attr:`~ruhusa.models.AuthorizationRequest.invoking_principal_id` field
    on the request is **not used** for the INV-17 provenance check — only the
    store's :attr:`InvocationRecord.invoking_principal_id` is authoritative.
    This closes the forged-invoker gap documented in Experiment 9.
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
