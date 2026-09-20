from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from threading import Lock
from typing import Protocol, runtime_checkable
from uuid import uuid4

from .execution import ExecutionPermit
from .interfaces import InvocationStore
from .invocations import InvocationRecord, compute_arguments_digest
from .models import AuthorizationDecision, AuthorizationRequest, DecisionEffect


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _require_non_empty(name: str, value: str) -> str:
    if not value.strip():
        raise ValueError(f"{name} must not be empty")
    return value


class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    CONSUMED = "consumed"
    REJECTED = "rejected"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    invocation_id: str
    task_id: str
    requested_at: datetime
    expires_at: datetime
    state: ApprovalState = ApprovalState.PENDING
    approved_by: str | None = None
    approved_at: datetime | None = None
    rejected_by: str | None = None
    rejected_at: datetime | None = None
    revoked_by: str | None = None
    revoked_at: datetime | None = None
    consumed_at: datetime | None = None
    consumed_claim_id: str | None = None
    consumed_attempt: int | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        observed_at = _as_utc(now or datetime.now(UTC))
        return observed_at >= _as_utc(self.expires_at)


@dataclass(frozen=True)
class ApprovalTransitionResult:
    allowed: bool
    reason: str
    record: ApprovalRecord | None = None


@runtime_checkable
class ApprovalStore(Protocol):
    def create(self, record: ApprovalRecord) -> ApprovalRecord: ...
    def get(self, approval_id: str) -> ApprovalRecord | None: ...
    def approve(
        self, approval_id: str, *, approved_by: str, now: datetime | None = None
    ) -> ApprovalTransitionResult: ...
    def reject(
        self, approval_id: str, *, rejected_by: str, now: datetime | None = None
    ) -> ApprovalTransitionResult: ...
    def revoke(
        self, approval_id: str, *, revoked_by: str, now: datetime | None = None
    ) -> ApprovalTransitionResult: ...
    def consume(
        self, approval_id: str, *, permit: ExecutionPermit, now: datetime | None = None
    ) -> ApprovalTransitionResult: ...


class InMemoryApprovalStore:
    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = Lock()

    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        with self._lock:
            if record.approval_id in self._records:
                raise ValueError(f"approval {record.approval_id!r} is already registered")
            self._records[record.approval_id] = record
            return record

    def get(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock:
            return self._records.get(approval_id)

    def approve(
        self, approval_id: str, *, approved_by: str, now: datetime | None = None
    ) -> ApprovalTransitionResult:
        approved_by = _require_non_empty("approved_by", approved_by)
        observed_at = _as_utc(now or datetime.now(UTC))
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return ApprovalTransitionResult(False, "approval not found")
            record = self._expire_if_needed(record, observed_at)
            if record.state is not ApprovalState.PENDING:
                return ApprovalTransitionResult(
                    False, f"approval is already {record.state.value}", record
                )
            updated = replace(
                record,
                state=ApprovalState.APPROVED,
                approved_by=approved_by,
                approved_at=observed_at,
            )
            self._records[approval_id] = updated
            return ApprovalTransitionResult(True, "approval granted", updated)

    def reject(
        self, approval_id: str, *, rejected_by: str, now: datetime | None = None
    ) -> ApprovalTransitionResult:
        rejected_by = _require_non_empty("rejected_by", rejected_by)
        observed_at = _as_utc(now or datetime.now(UTC))
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return ApprovalTransitionResult(False, "approval not found")
            record = self._expire_if_needed(record, observed_at)
            if record.state is not ApprovalState.PENDING:
                return ApprovalTransitionResult(
                    False, f"approval is already {record.state.value}", record
                )
            updated = replace(
                record,
                state=ApprovalState.REJECTED,
                rejected_by=rejected_by,
                rejected_at=observed_at,
            )
            self._records[approval_id] = updated
            return ApprovalTransitionResult(True, "approval rejected", updated)

    def revoke(
        self, approval_id: str, *, revoked_by: str, now: datetime | None = None
    ) -> ApprovalTransitionResult:
        revoked_by = _require_non_empty("revoked_by", revoked_by)
        observed_at = _as_utc(now or datetime.now(UTC))
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return ApprovalTransitionResult(False, "approval not found")
            record = self._expire_if_needed(record, observed_at)
            if record.state not in {ApprovalState.PENDING, ApprovalState.APPROVED}:
                return ApprovalTransitionResult(
                    False, f"approval is already {record.state.value}", record
                )
            updated = replace(
                record, state=ApprovalState.REVOKED, revoked_by=revoked_by, revoked_at=observed_at
            )
            self._records[approval_id] = updated
            return ApprovalTransitionResult(True, "approval revoked", updated)

    def consume(
        self, approval_id: str, *, permit: ExecutionPermit, now: datetime | None = None
    ) -> ApprovalTransitionResult:
        if not permit.claim_id.strip():
            raise ValueError("permit.claim_id must not be empty")
        if permit.attempt <= 0:
            raise ValueError("permit.attempt must be greater than zero")
        observed_at = _as_utc(now or datetime.now(UTC))
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return ApprovalTransitionResult(False, "approval not found")
            record = self._expire_if_needed(record, observed_at)
            if record.invocation_id != permit.invocation_id:
                return ApprovalTransitionResult(
                    False, "approval is bound to a different invocation", record
                )
            if record.state is not ApprovalState.APPROVED:
                return ApprovalTransitionResult(
                    False, f"approval is already {record.state.value}", record
                )
            updated = replace(
                record,
                state=ApprovalState.CONSUMED,
                consumed_at=observed_at,
                consumed_claim_id=permit.claim_id,
                consumed_attempt=permit.attempt,
            )
            self._records[approval_id] = updated
            return ApprovalTransitionResult(True, "approval consumed by execution attempt", updated)

    def _expire_if_needed(self, record: ApprovalRecord, observed_at: datetime) -> ApprovalRecord:
        if record.state in {
            ApprovalState.PENDING,
            ApprovalState.APPROVED,
        } and observed_at >= _as_utc(record.expires_at):
            record = replace(record, state=ApprovalState.EXPIRED)
            self._records[record.approval_id] = record
        return record


class ApprovalController:
    def __init__(self, *, approval_store: ApprovalStore, invocation_store: InvocationStore) -> None:
        self._approval_store = approval_store
        self._invocation_store = invocation_store

    def request(
        self,
        *,
        request: AuthorizationRequest,
        decision: AuthorizationDecision,
        approval_id: str | None = None,
        expires_at: datetime | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        if decision.effect is not DecisionEffect.REQUIRE_APPROVAL:
            raise ValueError("approval requests may only be created for REQUIRE_APPROVAL decisions")
        invocation_id = request.invocation_id
        if invocation_id is None or not invocation_id.strip():
            raise ValueError("approval requires canonical invocation provenance")
        canonical = self._invocation_store.get(invocation_id)
        if canonical is None:
            raise ValueError("approval requires a registered canonical invocation")
        self._validate_request_matches_invocation(request, canonical)
        observed_at = _as_utc(now or datetime.now(UTC))
        task_expiry = _as_utc(request.task.expires_at)
        invocation_expiry = _as_utc(canonical.expires_at)
        if observed_at >= task_expiry:
            raise ValueError("cannot request approval for an expired task")
        if observed_at >= invocation_expiry:
            raise ValueError("cannot request approval for an expired invocation")
        canonical_expiry = min(task_expiry, invocation_expiry)
        if expires_at is not None:
            requested_expiry = _as_utc(expires_at)
            if requested_expiry <= observed_at:
                raise ValueError("approval expiry must be in the future")
            if requested_expiry > canonical_expiry:
                raise ValueError("approval expiry must not exceed task or invocation expiry")
            canonical_expiry = requested_expiry
        canonical_approval_id = (
            uuid4().hex if approval_id is None else _require_non_empty("approval_id", approval_id)
        )
        record = ApprovalRecord(
            approval_id=canonical_approval_id,
            invocation_id=canonical.invocation_id,
            task_id=canonical.task_id,
            requested_at=observed_at,
            expires_at=canonical_expiry,
        )
        registered = self._approval_store.create(record)
        if registered != record:
            raise RuntimeError("approval store returned a different canonical record")
        return registered

    def require_approved(
        self, approval_id: str, *, invocation_id: str, now: datetime | None = None
    ) -> ApprovalRecord:
        approval_id = _require_non_empty("approval_id", approval_id)
        invocation_id = _require_non_empty("invocation_id", invocation_id)
        observed_at = _as_utc(now or datetime.now(UTC))
        record = self._approval_store.get(approval_id)
        if record is None:
            raise PermissionError("approval not found")
        if record.invocation_id != invocation_id:
            raise PermissionError("approval is bound to a different invocation")
        if record.state is not ApprovalState.APPROVED:
            raise PermissionError(f"approval is {record.state.value}")
        if observed_at >= _as_utc(record.expires_at):
            raise PermissionError("approval has expired")
        return record

    def consume_for_execution(
        self, approval_id: str, *, permit: ExecutionPermit, now: datetime | None = None
    ) -> ApprovalRecord:
        result = self._approval_store.consume(
            _require_non_empty("approval_id", approval_id), permit=permit, now=now
        )
        if not result.allowed or result.record is None:
            raise PermissionError(result.reason)
        return result.record

    @staticmethod
    def _validate_request_matches_invocation(
        request: AuthorizationRequest, canonical: InvocationRecord
    ) -> None:
        if request.principal.principal_id != canonical.executing_principal_id:
            raise ValueError("request principal does not match canonical invocation")
        if request.task.task_id != canonical.task_id:
            raise ValueError("request task does not match canonical invocation")
        if request.action != canonical.action:
            raise ValueError("request action does not match canonical invocation")
        if request.resource != canonical.resource:
            raise ValueError("request resource does not match canonical invocation")
        if compute_arguments_digest(request.arguments) != canonical.arguments_digest:
            raise ValueError("request arguments do not match canonical invocation")
