from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from ruhusa.invocations import compute_arguments_digest

from ruhusa import InMemoryInvocationStore, Principal, TaskContext
from ruhusa.integrations import TrustedInvocationFactory


def _task(*, now: datetime) -> TaskContext:
    return TaskContext(
        task_id="task-1",
        initiated_by="user-1",
        purpose="test trusted integration",
        expires_at=now + timedelta(minutes=30),
    )


def test_factory_registers_canonical_record_before_returning_request() -> None:
    now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    store = InMemoryInvocationStore()
    factory = TrustedInvocationFactory(store)

    prepared = factory.create(
        invoking_principal_id="orchestrator",
        executing_principal=Principal("billing-agent"),
        task=_task(now=now),
        action="refund",
        resource="account/123",
        arguments={"amount": 50},
        expires_at=now + timedelta(minutes=5),
        tool_id="refund-tool",
        implementation_id="sha256:abc",
        now=now,
    )

    assert store.get(prepared.record.invocation_id) == prepared.record
    assert prepared.request.invocation_id == prepared.record.invocation_id
    assert prepared.record.arguments_digest == compute_arguments_digest({"amount": 50})


def test_request_does_not_duplicate_self_asserted_trusted_identity() -> None:
    now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    factory = TrustedInvocationFactory(InMemoryInvocationStore())

    prepared = factory.create(
        invoking_principal_id="gateway",
        executing_principal=Principal("agent-1"),
        task=_task(now=now),
        action="read",
        resource="customer/1",
        arguments={},
        expires_at=now + timedelta(minutes=5),
        tool_id="reader",
        implementation_id="reader@sha256:1",
        now=now,
    )

    assert prepared.record.invoking_principal_id == "gateway"
    assert prepared.record.tool_id == "reader"
    assert prepared.record.implementation_id == "reader@sha256:1"
    assert prepared.request.invoking_principal_id is None
    assert prepared.request.tool_id is None
    assert prepared.request.implementation_id is None


def test_arguments_are_snapshotted_before_registration() -> None:
    now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    store = InMemoryInvocationStore()
    factory = TrustedInvocationFactory(store)
    arguments = {"amount": 25}

    prepared = factory.create(
        invoking_principal_id="gateway",
        executing_principal=Principal("agent-1"),
        task=_task(now=now),
        action="refund",
        resource="account/1",
        arguments=arguments,
        expires_at=now + timedelta(minutes=5),
        now=now,
    )

    arguments["amount"] = 999

    assert prepared.request.arguments["amount"] == 25
    assert prepared.record.arguments_digest == compute_arguments_digest({"amount": 25})


@pytest.mark.parametrize(
    ("tool_id", "implementation_id"),
    [
        ("tool", None),
        (None, "impl"),
        ("", "impl"),
        ("tool", ""),
    ],
)
def test_tool_identity_must_be_complete_pair(
    tool_id: str | None,
    implementation_id: str | None,
) -> None:
    now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    factory = TrustedInvocationFactory(InMemoryInvocationStore())

    with pytest.raises(ValueError):
        factory.create(
            invoking_principal_id="gateway",
            executing_principal=Principal("agent-1"),
            task=_task(now=now),
            action="read",
            resource="customer/1",
            arguments={},
            expires_at=now + timedelta(minutes=5),
            tool_id=tool_id,
            implementation_id=implementation_id,
            now=now,
        )


def test_invocation_cannot_outlive_task() -> None:
    now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    task = _task(now=now)
    factory = TrustedInvocationFactory(InMemoryInvocationStore())

    with pytest.raises(ValueError, match="must not exceed task expiry"):
        factory.create(
            invoking_principal_id="gateway",
            executing_principal=Principal("agent-1"),
            task=task,
            action="read",
            resource="customer/1",
            arguments={},
            expires_at=task.expires_at + timedelta(seconds=1),
            now=now,
        )


def test_expired_task_cannot_create_invocation() -> None:
    now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    task = TaskContext(
        task_id="expired",
        initiated_by="user",
        purpose="expired",
        expires_at=now,
    )
    factory = TrustedInvocationFactory(InMemoryInvocationStore())

    with pytest.raises(ValueError, match="expired task"):
        factory.create(
            invoking_principal_id="gateway",
            executing_principal=Principal("agent-1"),
            task=task,
            action="read",
            resource="customer/1",
            arguments={},
            expires_at=now + timedelta(minutes=1),
            now=now,
        )


def test_duplicate_explicit_invocation_id_fails_closed() -> None:
    now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    store = InMemoryInvocationStore()
    factory = TrustedInvocationFactory(store)

    kwargs = dict(
        invoking_principal_id="gateway",
        executing_principal=Principal("agent-1"),
        task=_task(now=now),
        action="read",
        resource="customer/1",
        arguments={},
        expires_at=now + timedelta(minutes=5),
        invocation_id="inv-fixed",
        now=now,
    )

    factory.create(**kwargs)

    with pytest.raises(ValueError, match="already registered"):
        factory.create(**kwargs)


def test_store_failure_propagates_without_returning_request() -> None:
    class FailingStore:
        def register(self, record):
            raise RuntimeError("store unavailable")

        def get(self, invocation_id):
            return None

        def is_registered(self, invocation_id):
            return False

    now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    factory = TrustedInvocationFactory(FailingStore())

    with pytest.raises(RuntimeError, match="store unavailable"):
        factory.create(
            invoking_principal_id="gateway",
            executing_principal=Principal("agent-1"),
            task=_task(now=now),
            action="read",
            resource="customer/1",
            arguments={},
            expires_at=now + timedelta(minutes=5),
            now=now,
        )
