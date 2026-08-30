from __future__ import annotations

from importlib.metadata import version

import ruhusa

EXPECTED_ROOT_EXPORTS = {
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


def test_distribution_version_is_v080() -> None:
    assert version("ruhusa") == "0.8.0"


def test_root_export_surface_is_deliberate() -> None:
    assert len(ruhusa.__all__) == len(set(ruhusa.__all__))
    assert set(ruhusa.__all__) == EXPECTED_ROOT_EXPORTS

    for name in ruhusa.__all__:
        assert getattr(ruhusa, name) is not None


def test_optional_integration_types_do_not_leak_into_root_api() -> None:
    assert "FastAPITrustedInvocationAdapter" not in ruhusa.__all__
    assert "PostgresGrantStore" not in ruhusa.__all__
    assert "PostgresExecutionStore" not in ruhusa.__all__


def test_framework_neutral_trusted_integration_stays_namespaced() -> None:
    from ruhusa.integrations import PreparedInvocation, TrustedInvocationFactory

    assert PreparedInvocation is not None
    assert TrustedInvocationFactory is not None
