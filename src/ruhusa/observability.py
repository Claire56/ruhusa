from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from threading import Lock
from types import MappingProxyType
from typing import Protocol, TypeAlias, runtime_checkable

from .execution import (
    ExecutionClaimResult,
    ExecutionPermit,
    ExecutionRecord,
    ExecutionRecoveryOutcome,
    ExecutionState,
)
from .interfaces import AuditLog, ExecutionStore
from .models import AuthorizationDecision, AuthorizationRequest

TelemetryScalar: TypeAlias = str | int | float | bool | None


class TelemetryEventName(str, Enum):
    AUTHORIZATION_DECISION = "authorization.decision"
    AUDIT_FAILURE = "audit.persistence_failure"
    BACKEND_FAILURE = "backend.failure"
    EXECUTION_CLAIMED = "execution.claimed"
    EXECUTION_CLAIM_BLOCKED = "execution.claim_blocked"
    EXECUTION_REPLAY_BLOCKED = "execution.replay_blocked"
    EXECUTION_COMPLETED = "execution.completed"
    EXECUTION_RELEASED = "execution.released"
    EXECUTION_UNKNOWN = "execution.unknown"
    EXECUTION_STALE_UNKNOWN = "execution.stale_unknown"
    EXECUTION_RECONCILED = "execution.reconciled"
    EXECUTION_CANCELLED = "execution.cancelled"
    EXECUTION_TRANSITION_REJECTED = "execution.transition_rejected"


@dataclass(frozen=True)
class TelemetryContext:
    trace_id: str | None = None
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        for name, value in (("trace_id", self.trace_id), ("correlation_id", self.correlation_id)):
            if value is not None and not value.strip():
                raise ValueError(f"{name} must not be empty")


_current_context: ContextVar[TelemetryContext] = ContextVar(
    "ruhusa_telemetry_context", default=TelemetryContext()
)


def current_telemetry_context() -> TelemetryContext:
    return _current_context.get()


@contextmanager
def telemetry_context(
    *, trace_id: str | None = None, correlation_id: str | None = None
) -> Iterator[TelemetryContext]:
    current = current_telemetry_context()
    updated = TelemetryContext(
        trace_id=current.trace_id if trace_id is None else trace_id,
        correlation_id=current.correlation_id if correlation_id is None else correlation_id,
    )
    token = _current_context.set(updated)
    try:
        yield updated
    finally:
        _current_context.reset(token)


@dataclass(frozen=True)
class TelemetryEvent:
    name: TelemetryEventName
    timestamp: datetime
    attributes: Mapping[str, TelemetryScalar] = field(default_factory=dict)
    trace_id: str | None = None
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@runtime_checkable
class TelemetrySink(Protocol):
    def emit(self, event: TelemetryEvent) -> None: ...


class InMemoryTelemetrySink:
    def __init__(self) -> None:
        self._events: list[TelemetryEvent] = []
        self._lock = Lock()

    def emit(self, event: TelemetryEvent) -> None:
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> tuple[TelemetryEvent, ...]:
        with self._lock:
            return tuple(self._events)


def _safe_emit(
    sink: TelemetrySink,
    name: TelemetryEventName,
    attributes: Mapping[str, TelemetryScalar] | None = None,
) -> None:
    context = current_telemetry_context()
    event = TelemetryEvent(
        name, datetime.now(UTC), attributes or {}, context.trace_id, context.correlation_id
    )
    try:
        sink.emit(event)
    except Exception:
        pass


class InstrumentedAuditLog:
    """Add best-effort telemetry without weakening mandatory audit semantics."""

    def __init__(self, audit_log: AuditLog, sink: TelemetrySink) -> None:
        self._audit_log = audit_log
        self._sink = sink

    def append(self, request: AuthorizationRequest, decision: AuthorizationDecision) -> str:
        try:
            audit_id = self._audit_log.append(request, decision)
        except Exception:
            _safe_emit(self._sink, TelemetryEventName.AUDIT_FAILURE, {"operation": "append"})
            raise

        _safe_emit(
            self._sink,
            TelemetryEventName.AUTHORIZATION_DECISION,
            {"effect": decision.effect.value, "allowed": decision.allowed, "audited": True},
        )
        return audit_id


class InstrumentedExecutionStore:
    """Add low-cardinality lifecycle telemetry to any ExecutionStore."""

    def __init__(self, execution_store: ExecutionStore, sink: TelemetrySink) -> None:
        self._execution_store = execution_store
        self._sink = sink

    def _failure(self, operation: str) -> None:
        _safe_emit(
            self._sink,
            TelemetryEventName.BACKEND_FAILURE,
            {"component": "execution_store", "operation": operation},
        )

    def _transition(
        self,
        name: TelemetryEventName,
        operation: str,
        changed: bool,
        extra: Mapping[str, TelemetryScalar] | None = None,
    ) -> None:
        attrs: dict[str, TelemetryScalar] = {"operation": operation, "changed": changed}
        if extra:
            attrs.update(extra)
        _safe_emit(
            self._sink, name if changed else TelemetryEventName.EXECUTION_TRANSITION_REJECTED, attrs
        )

    def get(self, invocation_id: str) -> ExecutionRecord | None:
        try:
            return self._execution_store.get(invocation_id)
        except Exception:
            self._failure("get")
            raise

    def claim(
        self, invocation_id: str, *, expires_at: datetime, now: datetime | None = None
    ) -> ExecutionClaimResult:
        try:
            result = self._execution_store.claim(invocation_id, expires_at=expires_at, now=now)
        except Exception:
            self._failure("claim")
            raise
        state = result.record.state.value if result.record is not None else None
        if result.allowed:
            name = TelemetryEventName.EXECUTION_CLAIMED
        elif result.record is not None and result.record.state in {
            ExecutionState.CLAIMED,
            ExecutionState.COMPLETED,
            ExecutionState.UNKNOWN,
            ExecutionState.CANCELLED,
        }:
            name = TelemetryEventName.EXECUTION_REPLAY_BLOCKED
        else:
            name = TelemetryEventName.EXECUTION_CLAIM_BLOCKED
        _safe_emit(self._sink, name, {"allowed": result.allowed, "state": state})
        return result

    def is_active(self, permit: ExecutionPermit) -> bool:
        try:
            return self._execution_store.is_active(permit)
        except Exception:
            self._failure("is_active")
            raise

    def complete(self, permit: ExecutionPermit, *, now: datetime | None = None) -> bool:
        try:
            changed = self._execution_store.complete(permit, now=now)
        except Exception:
            self._failure("complete")
            raise
        self._transition(TelemetryEventName.EXECUTION_COMPLETED, "complete", changed)
        return changed

    def release_before_execution(
        self, permit: ExecutionPermit, *, now: datetime | None = None
    ) -> bool:
        try:
            changed = self._execution_store.release_before_execution(permit, now=now)
        except Exception:
            self._failure("release_before_execution")
            raise
        self._transition(TelemetryEventName.EXECUTION_RELEASED, "release_before_execution", changed)
        return changed

    def mark_unknown(self, permit: ExecutionPermit, *, now: datetime | None = None) -> bool:
        try:
            changed = self._execution_store.mark_unknown(permit, now=now)
        except Exception:
            self._failure("mark_unknown")
            raise
        self._transition(TelemetryEventName.EXECUTION_UNKNOWN, "mark_unknown", changed)
        return changed

    def mark_stale_claim_unknown(
        self, invocation_id: str, *, stale_after: timedelta, now: datetime | None = None
    ) -> bool:
        try:
            changed = self._execution_store.mark_stale_claim_unknown(
                invocation_id, stale_after=stale_after, now=now
            )
        except Exception:
            self._failure("mark_stale_claim_unknown")
            raise
        self._transition(
            TelemetryEventName.EXECUTION_STALE_UNKNOWN, "mark_stale_claim_unknown", changed
        )
        return changed

    def reconcile_unknown(
        self,
        invocation_id: str,
        *,
        outcome: ExecutionRecoveryOutcome,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        try:
            changed = self._execution_store.reconcile_unknown(
                invocation_id, outcome=outcome, reason=reason, now=now
            )
        except Exception:
            self._failure("reconcile_unknown")
            raise
        self._transition(
            TelemetryEventName.EXECUTION_RECONCILED,
            "reconcile_unknown",
            changed,
            {"outcome": outcome.value},
        )
        return changed

    def cancel(self, permit: ExecutionPermit, *, reason: str, now: datetime | None = None) -> bool:
        try:
            changed = self._execution_store.cancel(permit, reason=reason, now=now)
        except Exception:
            self._failure("cancel")
            raise
        self._transition(TelemetryEventName.EXECUTION_CANCELLED, "cancel", changed)
        return changed
