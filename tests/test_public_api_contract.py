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
    "InMemoryAuditLog",
    "InMemoryExecutionStore",
    "InMemoryGrantStore",
    "InMemoryInvocationStore",
    "InMemoryRevocationStore",
    "InMemoryToolRegistry",
    "InvalidStateTransitionError",
    "InvocationRecord",
    "InvocationStore",
    "PolicyRule",
    "PolicyStore",
    "Principal",
    "ProvenanceError",
    "RevocationRecord",
    "RevocationStore",
    "Ruhusa",
    "RuhusaError",
    "Scope",
    "StaticPolicyStore",
    "StoreError",
    "StoreUnavailableError",
    "TaskContext",
    "ToolRegistration",
    "ToolRegistry",
    "compute_arguments_digest",
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
