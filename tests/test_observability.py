from datetime import UTC, datetime, timedelta

import pytest

from ruhusa.audit import InMemoryAuditLog
from ruhusa.execution import ExecutionRecoveryOutcome, InMemoryExecutionStore
from ruhusa.models import (
    AuthorizationDecision,
    AuthorizationRequest,
    DecisionEffect,
    Principal,
    TaskContext,
)
from ruhusa.observability import (
    InMemoryTelemetrySink,
    InstrumentedAuditLog,
    InstrumentedExecutionStore,
    TelemetryEventName,
    current_telemetry_context,
    telemetry_context,
)


def _request(now: datetime) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=Principal("agent-1"),
        action="read",
        resource="customer/1",
        arguments={},
        task=TaskContext("task-1", "user-1", "observability test", now + timedelta(minutes=30)),
    )


def test_audit_telemetry_preserves_security_semantics() -> None:
    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)
    sink = InMemoryTelemetrySink()
    audit = InstrumentedAuditLog(InMemoryAuditLog(), sink)
    audit_id = audit.append(_request(now), AuthorizationDecision(DecisionEffect.ALLOW, "allow"))
    assert audit_id
    event = sink.snapshot()[0]
    assert event.name is TelemetryEventName.AUTHORIZATION_DECISION
    assert event.attributes["effect"] == "allow"
    assert "reason" not in event.attributes
    assert "resource" not in event.attributes


def test_audit_failure_re_raises() -> None:
    class BrokenAudit:
        def append(self, request, decision):
            raise RuntimeError("down")

    sink = InMemoryTelemetrySink()
    with pytest.raises(RuntimeError, match="down"):
        InstrumentedAuditLog(BrokenAudit(), sink).append(
            _request(datetime(2026, 8, 29, 17, 0, tzinfo=UTC)),
            AuthorizationDecision(DecisionEffect.ALLOW, "allow"),
        )
    assert sink.snapshot()[0].name is TelemetryEventName.AUDIT_FAILURE


def test_context_propagates_and_resets() -> None:
    sink = InMemoryTelemetrySink()
    audit = InstrumentedAuditLog(InMemoryAuditLog(), sink)
    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)
    with telemetry_context(trace_id="trace-1", correlation_id="corr-1"):
        audit.append(_request(now), AuthorizationDecision(DecisionEffect.DENY, "deny"))
    assert sink.snapshot()[0].trace_id == "trace-1"
    assert current_telemetry_context().trace_id is None


def test_execution_lifecycle_events() -> None:
    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)
    sink = InMemoryTelemetrySink()
    store = InstrumentedExecutionStore(InMemoryExecutionStore(), sink)
    expiry = now + timedelta(minutes=5)
    claim = store.claim("inv-1", expires_at=expiry, now=now)
    assert claim.permit is not None
    assert store.mark_unknown(claim.permit, now=now + timedelta(seconds=1))
    assert store.reconcile_unknown(
        "inv-1",
        outcome=ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED,
        reason="trusted reconciliation",
        now=now + timedelta(seconds=2),
    )
    claim2 = store.claim("inv-1", expires_at=expiry, now=now + timedelta(seconds=3))
    assert claim2.permit is not None
    assert store.complete(claim2.permit, now=now + timedelta(seconds=4))
    replay = store.claim("inv-1", expires_at=expiry, now=now + timedelta(seconds=5))
    assert replay.allowed is False
    names = {event.name for event in sink.snapshot()}
    assert TelemetryEventName.EXECUTION_UNKNOWN in names
    assert TelemetryEventName.EXECUTION_RECONCILED in names
    assert TelemetryEventName.EXECUTION_COMPLETED in names
    assert TelemetryEventName.EXECUTION_REPLAY_BLOCKED in names


def test_telemetry_sink_failure_does_not_change_execution() -> None:
    class BrokenSink:
        def emit(self, event):
            raise RuntimeError("telemetry unavailable")

    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)
    result = InstrumentedExecutionStore(InMemoryExecutionStore(), BrokenSink()).claim(
        "inv-1", expires_at=now + timedelta(minutes=5), now=now
    )
    assert result.allowed is True
