from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from threading import Lock
from uuid import uuid4

from .core import Ruhusa
from .models import AuthorizationDecision, AuthorizationRequest


def _as_utc(value: datetime) -> datetime:
    """Normalize a datetime to UTC for deterministic lifecycle comparisons."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class ExecutionState(str, Enum):
    """Lifecycle state for one canonical invocation's execution authority."""

    AVAILABLE = "available"
    CLAIMED = "claimed"
    COMPLETED = "completed"
    UNKNOWN = "unknown"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ExecutionPermit:
    """Opaque proof that one execution attempt won the atomic claim.

    A permit is required for lifecycle transitions after ``claim``. The
    ``claim_id`` and ``attempt`` fields prevent an older or unrelated worker
    from completing, releasing, cancelling, or marking unknown a newer
    execution attempt.
    """

    invocation_id: str
    claim_id: str
    attempt: int


@dataclass(frozen=True)
class ExecutionRecord:
    """Mutable-by-store execution state associated with an immutable invocation.

    Invocation provenance remains in ``InMemoryInvocationStore``. This record
    tracks only whether the already-authorized operation has been claimed or
    used.

    AVAILABLE
        No execution attempt currently owns the invocation.

    CLAIMED
        Exactly one execution attempt currently owns the invocation.

    COMPLETED
        The protected side effect is reported complete. Automatic replay is
        permanently blocked.

    UNKNOWN
        The executor cannot determine whether the side effect occurred.
        Automatic retry fails closed until a future reconciliation mechanism
        explicitly resolves the state.

    CANCELLED
        Execution-time authorization became invalid before the side effect.
        The old invocation is not automatically resurrected even if policy or
        authority changes again; a new trusted invocation is required.
    """

    invocation_id: str
    expires_at: datetime
    state: ExecutionState = ExecutionState.AVAILABLE
    attempt_count: int = 0
    claim_id: str | None = None
    claimed_at: datetime | None = None
    completed_at: datetime | None = None
    released_at: datetime | None = None
    unknown_at: datetime | None = None
    cancelled_at: datetime | None = None
    cancel_reason: str | None = None


@dataclass(frozen=True)
class ExecutionClaimResult:
    allowed: bool
    reason: str
    record: ExecutionRecord | None = None
    permit: ExecutionPermit | None = None


@dataclass(frozen=True)
class ExecutionDecision:
    """Combined authorization and execution-admission result."""

    allowed: bool
    reason: str
    authorization: AuthorizationDecision
    permit: ExecutionPermit | None = None


class InMemoryExecutionStore:
    """Thread-safe research implementation of invocation execution state.

    The store provides process-local atomic claim semantics. Concurrent
    threads racing for the same invocation can produce at most one winning
    permit.

    It intentionally does *not* claim distributed consensus, cross-process
    atomicity, durable crash recovery, atomic authorization with an external
    side effect, or exactly-once external side effects.
    """

    def __init__(self) -> None:
        self._records: dict[str, ExecutionRecord] = {}
        self._lock = Lock()

    def get(self, invocation_id: str) -> ExecutionRecord | None:
        with self._lock:
            return self._records.get(invocation_id)

    def claim(
        self,
        invocation_id: str,
        *,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> ExecutionClaimResult:
        """Atomically claim execution authority for a canonical invocation."""
        now = _as_utc(now or datetime.now(UTC))
        canonical_expiry = _as_utc(expires_at)

        if now >= canonical_expiry:
            return ExecutionClaimResult(
                allowed=False,
                reason="execution authority has expired",
            )

        with self._lock:
            record = self._records.get(invocation_id)

            if record is None:
                record = ExecutionRecord(
                    invocation_id=invocation_id,
                    expires_at=canonical_expiry,
                )
                self._records[invocation_id] = record
            elif _as_utc(record.expires_at) != canonical_expiry:
                # Invocation provenance is immutable. A different expiry for
                # the same invocation id indicates inconsistent trusted state.
                return ExecutionClaimResult(
                    allowed=False,
                    reason="execution lifecycle expiry does not match canonical invocation",
                    record=record,
                )

            if record.state is not ExecutionState.AVAILABLE:
                return ExecutionClaimResult(
                    allowed=False,
                    reason=f"execution authority is already {record.state.value}",
                    record=record,
                )

            claim_id = uuid4().hex
            attempt = record.attempt_count + 1
            updated = replace(
                record,
                state=ExecutionState.CLAIMED,
                attempt_count=attempt,
                claim_id=claim_id,
                claimed_at=now,
                completed_at=None,
                released_at=None,
                unknown_at=None,
                cancelled_at=None,
                cancel_reason=None,
            )
            self._records[invocation_id] = updated

            return ExecutionClaimResult(
                allowed=True,
                reason="execution authority claimed",
                record=updated,
                permit=ExecutionPermit(
                    invocation_id=invocation_id,
                    claim_id=claim_id,
                    attempt=attempt,
                ),
            )

    def is_active(self, permit: ExecutionPermit) -> bool:
        """Return whether ``permit`` still owns the current CLAIMED attempt."""
        with self._lock:
            record = self._records.get(permit.invocation_id)
            return self._owns_active_claim(record, permit)

    def complete(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Mark the permit's active execution attempt as completed."""
        now = _as_utc(now or datetime.now(UTC))

        with self._lock:
            record = self._records.get(permit.invocation_id)
            if not self._owns_active_claim(record, permit):
                return False

            self._records[permit.invocation_id] = replace(
                record,
                state=ExecutionState.COMPLETED,
                completed_at=now,
            )
            return True

    def release_before_execution(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Release only when the protected side effect definitely did not start.

        This transition is intended for failures known to occur before any
        external request or side effect. If the outcome may have occurred,
        callers must use ``mark_unknown`` instead.
        """
        now = _as_utc(now or datetime.now(UTC))

        with self._lock:
            record = self._records.get(permit.invocation_id)
            if not self._owns_active_claim(record, permit):
                return False

            self._records[permit.invocation_id] = replace(
                record,
                state=ExecutionState.AVAILABLE,
                claim_id=None,
                released_at=now,
            )
            return True

    def mark_unknown(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Fail closed when external side-effect outcome cannot be determined."""
        now = _as_utc(now or datetime.now(UTC))

        with self._lock:
            record = self._records.get(permit.invocation_id)
            if not self._owns_active_claim(record, permit):
                return False

            self._records[permit.invocation_id] = replace(
                record,
                state=ExecutionState.UNKNOWN,
                unknown_at=now,
            )
            return True

    def cancel(
        self,
        permit: ExecutionPermit,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        """Cancel an active claim whose authority became invalid before use.

        Cancellation is terminal for the invocation. A caller that later
        obtains authority again must obtain a new canonical invocation rather
        than resurrecting the old one.
        """
        if not reason.strip():
            raise ValueError("cancellation reason must not be empty")

        now = _as_utc(now or datetime.now(UTC))

        with self._lock:
            record = self._records.get(permit.invocation_id)
            if not self._owns_active_claim(record, permit):
                return False

            self._records[permit.invocation_id] = replace(
                record,
                state=ExecutionState.CANCELLED,
                cancelled_at=now,
                cancel_reason=reason,
            )
            return True

    @staticmethod
    def _owns_active_claim(
        record: ExecutionRecord | None,
        permit: ExecutionPermit,
    ) -> bool:
        return (
            record is not None
            and record.state is ExecutionState.CLAIMED
            and record.claim_id == permit.claim_id
            and record.attempt_count == permit.attempt
        )


class ExecutionController:
    """Trusted execution boundary layered on top of ``Ruhusa.authorize``.

    ``authorize`` remains deliberately non-consuming so the v0.5 baseline and
    Experiment 16 remain reproducible.

    Side-effecting integrations that opt into v0.6 execution protection should:

    1. call ``begin`` to authorize and atomically claim the invocation;
    2. call ``revalidate_before_execution`` immediately before the protected
       side effect;
    3. execute only when revalidation returns ``allowed=True``;
    4. call ``complete`` after a known successful side effect, or
       ``mark_unknown`` if the external outcome cannot be determined.

    This separates:

        InvocationStore -> what operation was authentically created?
        ExecutionStore  -> has that operation's execution authority been used?

    v0.6-B reduces the authorization-to-use time-of-check/time-of-use window by
    re-evaluating live authority at the execution boundary. It does not make
    that revalidation atomic with an external system's side effect.
    """

    def __init__(
        self,
        authorizer: Ruhusa,
        execution_store: InMemoryExecutionStore | None = None,
    ) -> None:
        if authorizer.invocation_store is None:
            raise ValueError(
                "ExecutionController requires Ruhusa to be configured with an invocation store"
            )

        self.authorizer = authorizer
        self.execution_store = (
            execution_store if execution_store is not None else InMemoryExecutionStore()
        )

    def begin(
        self,
        request: AuthorizationRequest,
        *,
        now: datetime | None = None,
    ) -> ExecutionDecision:
        """Authorize the operation, then atomically claim execution authority."""
        now = _as_utc(now or datetime.now(UTC))
        authorization = self.authorizer.authorize(request, now=now)

        if not authorization.allowed:
            return ExecutionDecision(
                allowed=False,
                reason=f"authorization denied: {authorization.reason}",
                authorization=authorization,
            )

        invocation_id = request.invocation_id
        if invocation_id is None:
            # Strong-mode authorize should already deny this, but the execution
            # boundary independently preserves fail-closed behavior.
            return ExecutionDecision(
                allowed=False,
                reason="execution requires a canonical invocation id",
                authorization=authorization,
            )

        try:
            invocation_store = self.authorizer.invocation_store
            if invocation_store is None:
                return ExecutionDecision(
                    allowed=False,
                    reason="trusted invocation provenance is unavailable",
                    authorization=authorization,
                )

            canonical = invocation_store.get(invocation_id)
            if canonical is None:
                return ExecutionDecision(
                    allowed=False,
                    reason="canonical invocation record is unavailable",
                    authorization=authorization,
                )

            claim = self.execution_store.claim(
                invocation_id,
                expires_at=canonical.expires_at,
                now=now,
            )
        except Exception:
            return ExecutionDecision(
                allowed=False,
                reason="execution lifecycle state unavailable; default deny",
                authorization=authorization,
            )

        return ExecutionDecision(
            allowed=claim.allowed,
            reason=claim.reason,
            authorization=authorization,
            permit=claim.permit,
        )

    def revalidate_before_execution(
        self,
        request: AuthorizationRequest,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> ExecutionDecision:
        """Re-check live authority immediately before the protected side effect.

        The request is sent through the full Ruhusa authorization path again so
        task expiry, delegation validity, revocation, trusted provenance, tool
        identity, scope, and current policy are evaluated at execution time.

        If authority is no longer valid, the active claim is moved to the
        terminal ``CANCELLED`` state. The old invocation must not be reused.

        A successful result means authority was valid at this revalidation
        point. It is *not* a guarantee that authority cannot change immediately
        afterward; the remaining post-check TOCTOU window is an explicit v0.6
        research boundary.
        """
        now = _as_utc(now or datetime.now(UTC))
        authorization = self.authorizer.authorize(request, now=now)

        if not authorization.allowed:
            try:
                self.execution_store.cancel(
                    permit,
                    reason=f"execution-time authorization denied: {authorization.reason}",
                    now=now,
                )
            except Exception:
                # The authorization decision is already DENY. A lifecycle
                # backend failure must never convert that result into ALLOW.
                pass

            return ExecutionDecision(
                allowed=False,
                reason=f"execution-time authorization denied: {authorization.reason}",
                authorization=authorization,
            )

        if request.invocation_id != permit.invocation_id:
            return ExecutionDecision(
                allowed=False,
                reason="execution permit is bound to a different invocation",
                authorization=authorization,
            )

        try:
            if not self.execution_store.is_active(permit):
                return ExecutionDecision(
                    allowed=False,
                    reason="execution permit is not the active claimed attempt",
                    authorization=authorization,
                )
        except Exception:
            return ExecutionDecision(
                allowed=False,
                reason="execution lifecycle state unavailable during revalidation; default deny",
                authorization=authorization,
            )

        return ExecutionDecision(
            allowed=True,
            reason="execution-time authority remains valid",
            authorization=authorization,
            permit=permit,
        )

    def complete(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        return self.execution_store.complete(permit, now=now)

    def release_before_execution(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        return self.execution_store.release_before_execution(permit, now=now)

    def mark_unknown(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        return self.execution_store.mark_unknown(permit, now=now)
