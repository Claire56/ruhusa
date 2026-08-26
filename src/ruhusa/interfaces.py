from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .execution import (
        ExecutionClaimResult,
        ExecutionPermit,
        ExecutionRecord,
        ExecutionRecoveryOutcome,
    )
    from .invocations import InvocationRecord
    from .models import AuthorizationDecision, AuthorizationRequest, DelegationGrant
    from .policy import PolicyRule
    from .revocation import RevocationRecord
    from .tools import ToolRegistration


@runtime_checkable
class PolicyStore(Protocol):
    """Policy-decision dependency used by ``Ruhusa``.

    Implementations must raise when policy state cannot be read reliably.
    Ruhusa translates such failures into a fail-closed decision.
    """

    def evaluate(self, request: AuthorizationRequest) -> PolicyRule | None:
        """Return the matching policy rule, or ``None`` for no match."""


@runtime_checkable
class AuditLog(Protocol):
    """Audit dependency used by ``Ruhusa``.

    A would-be ALLOW must not be returned when required audit persistence fails.
    """

    def append(
        self,
        request: AuthorizationRequest,
        decision: AuthorizationDecision,
    ) -> str:
        """Persist the decision and return its audit identifier."""


@runtime_checkable
class GrantStore(Protocol):
    """Trusted delegation-grant issuance boundary."""

    def register(self, grant: DelegationGrant) -> DelegationGrant:
        """Persist a canonically issued grant."""

    def get(self, grant_id: str) -> DelegationGrant | None:
        """Return the canonical grant, or ``None`` when unknown."""

    def contains(self, grant_id: str) -> bool:
        """Return whether a grant identifier exists."""

    def is_registered(self, grant: DelegationGrant) -> bool:
        """Return whether the complete grant equals the canonical issued grant."""


@runtime_checkable
class RevocationStore(Protocol):
    """Continuous revocation boundary for delegated authority."""

    def revoke(
        self,
        grant_id: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> RevocationRecord:
        """Create or strengthen a revocation."""

    def is_revoked(
        self,
        grant_id: str,
        *,
        at: datetime | None = None,
    ) -> bool:
        """Return whether the grant is revoked at the supplied instant."""

    def get(self, grant_id: str) -> RevocationRecord | None:
        """Return the revocation record, if any."""

    def snapshot(self) -> tuple[RevocationRecord, ...]:
        """Return an immutable point-in-time view of revocations."""


@runtime_checkable
class InvocationStore(Protocol):
    """Canonical invocation-provenance boundary."""

    def register(self, record: InvocationRecord) -> InvocationRecord:
        """Persist trusted invocation provenance."""

    def get(self, invocation_id: str) -> InvocationRecord | None:
        """Return canonical invocation provenance, or ``None``."""

    def is_registered(self, invocation_id: str) -> bool:
        """Return whether canonical provenance exists."""


@runtime_checkable
class ToolRegistry(Protocol):
    """Trusted registry of tool implementations."""

    def register(self, tool: ToolRegistration) -> ToolRegistration:
        """Register one trusted implementation."""

    def get(
        self,
        tool_id: str,
        implementation_id: str,
    ) -> ToolRegistration | None:
        """Return the canonical tool registration, or ``None``."""

    def is_trusted(self, tool_id: str, implementation_id: str) -> bool:
        """Return whether the exact implementation is trusted."""

    def allows_action(
        self,
        tool_id: str,
        implementation_id: str,
        action: str,
    ) -> bool:
        """Return whether the implementation may perform ``action``."""


@runtime_checkable
class ExecutionStore(Protocol):
    """Execution-lifecycle boundary introduced in v0.6.

    A production implementation must make each state-changing operation atomic
    for one invocation identifier. This protocol does not itself imply
    distributed consensus, durability, or transactionality with remote side
    effects.
    """

    def get(self, invocation_id: str) -> ExecutionRecord | None:
        """Return current execution state, or ``None``."""

    def claim(
        self,
        invocation_id: str,
        *,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> ExecutionClaimResult:
        """Atomically attempt to claim execution authority."""

    def is_active(self, permit: ExecutionPermit) -> bool:
        """Return whether ``permit`` owns the active attempt."""

    def complete(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Transition the owned attempt to COMPLETED."""

    def release_before_execution(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Return a definitely-unused attempt to AVAILABLE."""

    def mark_unknown(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Quarantine an uncertain outcome as UNKNOWN."""

    def mark_stale_claim_unknown(
        self,
        invocation_id: str,
        *,
        stale_after: timedelta,
        now: datetime | None = None,
    ) -> bool:
        """Quarantine a stale or abandoned claim as UNKNOWN."""

    def reconcile_unknown(
        self,
        invocation_id: str,
        *,
        outcome: ExecutionRecoveryOutcome,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        """Resolve UNKNOWN from trusted reconciliation infrastructure."""

    def cancel(
        self,
        permit: ExecutionPermit,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        """Cancel an active attempt whose authority became invalid."""
