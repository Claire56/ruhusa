from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("fastapi")

from fastapi import Request  # noqa: E402

from ruhusa import InMemoryInvocationStore, Principal, TaskContext  # noqa: E402
from ruhusa.integrations import TrustedInvocationFactory  # noqa: E402
from ruhusa.integrations.fastapi import (  # noqa: E402
    FastAPIIntegrationError,
    FastAPITrustedInvocationAdapter,
)


def _request(*, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/protected",
            "raw_path": b"/protected",
            "query_string": b"",
            "headers": headers or [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 443),
        }
    )


def _task(now: datetime) -> TaskContext:
    return TaskContext(
        task_id="task-fastapi",
        initiated_by="user-1",
        purpose="test FastAPI integration",
        expires_at=now + timedelta(minutes=30),
    )


@pytest.mark.asyncio
async def test_request_state_adapter_creates_canonical_invocation() -> None:
    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)
    store = InMemoryInvocationStore()
    adapter = FastAPITrustedInvocationAdapter.from_request_state(TrustedInvocationFactory(store))
    request = _request()
    request.state.ruhusa_invoking_principal_id = "authenticated-gateway"
    request.state.ruhusa_executing_principal = Principal("billing-agent")

    prepared = await adapter.prepare(
        request,
        task=_task(now),
        action="refund",
        resource="account/123",
        arguments={"amount": 50},
        expires_at=now + timedelta(minutes=5),
        tool_id="refund-tool",
        implementation_id="refund-tool@sha256:abc",
        now=now,
    )

    assert store.get(prepared.record.invocation_id) == prepared.record
    assert prepared.record.invoking_principal_id == "authenticated-gateway"
    assert prepared.record.executing_principal_id == "billing-agent"
    assert prepared.request.invocation_id == prepared.record.invocation_id


@pytest.mark.asyncio
async def test_missing_trusted_state_fails_closed() -> None:
    adapter = FastAPITrustedInvocationAdapter.from_request_state(
        TrustedInvocationFactory(InMemoryInvocationStore())
    )
    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)

    with pytest.raises(FastAPIIntegrationError, match="is missing"):
        await adapter.prepare(
            _request(),
            task=_task(now),
            action="read",
            resource="customer/1",
            arguments={},
            expires_at=now + timedelta(minutes=5),
            now=now,
        )


@pytest.mark.asyncio
async def test_raw_identity_headers_are_never_used_as_fallback() -> None:
    adapter = FastAPITrustedInvocationAdapter.from_request_state(
        TrustedInvocationFactory(InMemoryInvocationStore())
    )
    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)
    request = _request(
        headers=[
            (b"x-principal-id", b"attacker"),
            (b"x-invoking-principal-id", b"attacker"),
        ]
    )

    with pytest.raises(FastAPIIntegrationError, match="is missing"):
        await adapter.prepare(
            request,
            task=_task(now),
            action="read",
            resource="customer/1",
            arguments={},
            expires_at=now + timedelta(minutes=5),
            now=now,
        )


@pytest.mark.asyncio
async def test_invalid_request_state_types_fail_closed() -> None:
    adapter = FastAPITrustedInvocationAdapter.from_request_state(
        TrustedInvocationFactory(InMemoryInvocationStore())
    )
    request = _request()
    request.state.ruhusa_invoking_principal_id = 123
    request.state.ruhusa_executing_principal = "agent-1"
    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)

    with pytest.raises(FastAPIIntegrationError):
        await adapter.prepare(
            request,
            task=_task(now),
            action="read",
            resource="customer/1",
            arguments={},
            expires_at=now + timedelta(minutes=5),
            now=now,
        )


@pytest.mark.asyncio
async def test_custom_async_resolvers_are_supported() -> None:
    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)
    store = InMemoryInvocationStore()

    async def invoker(request: Request) -> str:
        return "oidc-subject"

    async def executor(request: Request) -> Principal:
        return Principal("agent-from-auth")

    adapter = FastAPITrustedInvocationAdapter(
        TrustedInvocationFactory(store),
        invoking_principal_resolver=invoker,
        executing_principal_resolver=executor,
    )

    prepared = await adapter.prepare(
        _request(),
        task=_task(now),
        action="read",
        resource="customer/1",
        arguments={},
        expires_at=now + timedelta(minutes=5),
        now=now,
    )

    assert prepared.record.invoking_principal_id == "oidc-subject"
    assert prepared.record.executing_principal_id == "agent-from-auth"


@pytest.mark.asyncio
async def test_custom_resolver_invalid_result_fails_closed() -> None:
    now = datetime(2026, 8, 29, 17, 0, tzinfo=UTC)

    def invoker(request: Request):
        return None

    def executor(request: Request):
        return Principal("agent-1")

    adapter = FastAPITrustedInvocationAdapter(
        TrustedInvocationFactory(InMemoryInvocationStore()),
        invoking_principal_resolver=invoker,
        executing_principal_resolver=executor,
    )

    with pytest.raises(FastAPIIntegrationError, match="non-empty string"):
        await adapter.prepare(
            _request(),
            task=_task(now),
            action="read",
            resource="customer/1",
            arguments={},
            expires_at=now + timedelta(minutes=5),
            now=now,
        )
