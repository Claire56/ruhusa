from __future__ import annotations

import pytest

import ruhusa
from ruhusa import (
    AuditLog,
    ConfigurationError,
    ExecutionController,
    ExecutionStore,
    GrantStore,
    InMemoryAuditLog,
    InMemoryExecutionStore,
    InMemoryGrantStore,
    InMemoryInvocationStore,
    InMemoryRevocationStore,
    InMemoryToolRegistry,
    InvocationStore,
    PolicyStore,
    RevocationStore,
    Ruhusa,
    RuhusaError,
    StaticPolicyStore,
    StoreError,
    StoreUnavailableError,
    ToolRegistry,
)

EXPECTED_PUBLIC_API = {
    "AuditEvent",
    "AuditLog",
    "AuthorizationDecision",
    "AuthorizationRequest",
    "ConfigurationError",
    "DecisionEffect",
    "DelegationGrant",
    "ExecutionClaimResult",
    "ExecutionController",
    "ExecutionDecision",
    "ExecutionPermit",
    "ExecutionRecord",
    "ExecutionRecoveryOutcome",
    "ExecutionState",
    "ExecutionStore",
    "GrantStore",
    "HealthCheckResult",
    "HealthRegistry",
    "HealthReport",
    "HealthStatus",
    "InMemoryAuditLog",
    "InMemoryExecutionStore",
    "InMemoryGrantStore",
    "InMemoryInvocationStore",
    "InMemoryRevocationStore",
    "InMemoryTelemetrySink",
    "InMemoryToolRegistry",
    "InstrumentedAuditLog",
    "InstrumentedExecutionStore",
    "InvalidStateTransitionError",
    "InvocationRecord",
    "InvocationStore",
    "LifecycleError",
    "NoopTelemetrySink",
    "PolicyRule",
    "PolicyStore",
    "Principal",
    "ProvenanceError",
    "ResourceClosedError",
    "RevocationRecord",
    "RevocationStore",
    "Ruhusa",
    "RuhusaError",
    "RuhusaRuntime",
    "RuntimeConfig",
    "RuntimeState",
    "Scope",
    "ShutdownError",
    "StartupError",
    "StaticPolicyStore",
    "StoreError",
    "StoreUnavailableError",
    "TaskContext",
    "TelemetryContext",
    "TelemetryEvent",
    "TelemetryEventName",
    "TelemetrySink",
    "ToolRegistration",
    "ToolRegistry",
    "compute_arguments_digest",
    "current_telemetry_context",
    "telemetry_context",
}


def test_public_api_is_deliberate_and_has_no_duplicate_exports() -> None:
    assert len(ruhusa.__all__) == len(set(ruhusa.__all__))
    assert set(ruhusa.__all__) == EXPECTED_PUBLIC_API


@pytest.mark.parametrize(
    ("instance", "protocol"),
    [
        (StaticPolicyStore(), PolicyStore),
        (InMemoryAuditLog(), AuditLog),
        (InMemoryGrantStore(), GrantStore),
        (InMemoryRevocationStore(), RevocationStore),
        (InMemoryInvocationStore(), InvocationStore),
        (InMemoryToolRegistry(), ToolRegistry),
        (InMemoryExecutionStore(), ExecutionStore),
    ],
)
def test_reference_implementations_satisfy_public_protocols(instance, protocol) -> None:
    assert isinstance(instance, protocol)


def test_stable_error_hierarchy() -> None:
    assert issubclass(ConfigurationError, RuhusaError)
    assert issubclass(ConfigurationError, ValueError)
    assert issubclass(StoreError, RuhusaError)
    assert issubclass(StoreUnavailableError, StoreError)


def test_execution_controller_configuration_error_is_backward_compatible() -> None:
    gate = Ruhusa()

    with pytest.raises(ConfigurationError):
        ExecutionController(gate)

    with pytest.raises(ValueError):
        ExecutionController(gate)


class FalseyPolicyStore:
    def __bool__(self) -> bool:
        return False

    def evaluate(self, request):
        return None


class FalseyAuditLog:
    def __bool__(self) -> bool:
        return False

    def append(self, request, decision):
        return "audit-falsey"


def test_falsey_protocol_dependencies_are_not_replaced() -> None:
    policy_store = FalseyPolicyStore()
    audit_log = FalseyAuditLog()
    gate = Ruhusa(
        policy_store=policy_store,
        audit_log=audit_log,
    )
    assert gate.policy_store is policy_store
    assert gate.audit_log is audit_log
