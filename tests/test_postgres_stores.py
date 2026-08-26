from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa.interfaces import (  # noqa: E402
    GrantStore,
    InvocationStore,
    RevocationStore,
    ToolRegistry,
)
from ruhusa.invocations import InvocationRecord, compute_arguments_digest  # noqa: E402
from ruhusa.models import DelegationGrant, Scope  # noqa: E402
from ruhusa.postgres import (  # noqa: E402
    PostgresGrantStore,
    PostgresInvocationStore,
    PostgresRevocationStore,
    PostgresToolRegistry,
    create_postgres_pool,
    initialize_postgres_schema,
)
from ruhusa.tools import ToolRegistration  # noqa: E402

TEST_DSN = os.getenv("RUHUSA_TEST_POSTGRES_DSN")

pytestmark = pytest.mark.skipif(
    TEST_DSN is None,
    reason="RUHUSA_TEST_POSTGRES_DSN is not configured",
)


@pytest.fixture
def pool():
    assert TEST_DSN is not None

    pool = create_postgres_pool(
        TEST_DSN,
        min_size=1,
        max_size=20,
    )
    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                TRUNCATE TABLE
                    ruhusa_revocations,
                    ruhusa_invocations,
                    ruhusa_tools,
                    ruhusa_grants
                """
            )

    try:
        yield pool
    finally:
        pool.close()


def _grant(grant_id: str = "grant-1") -> DelegationGrant:
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)

    return DelegationGrant(
        grant_id=grant_id,
        grantor_id="supervisor",
        grantee_id="billing-agent",
        task_id="task-1",
        scope=Scope(
            actions=frozenset({"refund", "read"}),
            resource_prefixes=("account/",),
            max_numeric_arguments={"amount": 500.0},
        ),
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )


def _invocation(
    invocation_id: str = "inv-1",
) -> InvocationRecord:
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)

    return InvocationRecord(
        invocation_id=invocation_id,
        invoking_principal_id="supervisor",
        executing_principal_id="billing-agent",
        task_id="task-1",
        action="refund",
        resource="account/123",
        arguments_digest=compute_arguments_digest({"amount": 100}),
        tool_id="billing-refund",
        implementation_id="billing-refund@sha256:abc",
        recorded_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def test_postgres_stores_satisfy_v07a_protocols(
    pool,
) -> None:
    assert isinstance(
        PostgresGrantStore(pool),
        GrantStore,
    )
    assert isinstance(
        PostgresRevocationStore(pool),
        RevocationStore,
    )
    assert isinstance(
        PostgresInvocationStore(pool),
        InvocationStore,
    )
    assert isinstance(
        PostgresToolRegistry(pool),
        ToolRegistry,
    )


def test_grant_round_trip_and_duplicate_registration_is_immutable(
    pool,
) -> None:
    store = PostgresGrantStore(pool)
    grant = _grant()

    assert store.register(grant) == grant
    assert store.get(grant.grant_id) == grant
    assert store.contains(grant.grant_id)
    assert store.is_registered(grant)

    widened = DelegationGrant(
        grant_id=grant.grant_id,
        grantor_id=grant.grantor_id,
        grantee_id=grant.grantee_id,
        task_id=grant.task_id,
        scope=Scope(
            actions=frozenset({"refund", "read", "delete"}),
        ),
        issued_at=grant.issued_at,
        expires_at=grant.expires_at,
    )

    assert not store.is_registered(widened)

    with pytest.raises(
        ValueError,
        match="already registered",
    ):
        store.register(widened)

    assert store.get(grant.grant_id) == grant


def test_invocation_round_trip_and_duplicate_registration_is_immutable(
    pool,
) -> None:
    store = PostgresInvocationStore(pool)
    record = _invocation()

    assert store.register(record) == record
    assert store.get(record.invocation_id) == record
    assert store.is_registered(record.invocation_id)

    replacement = replace(
        record,
        resource="account/attacker-controlled",
    )

    with pytest.raises(
        ValueError,
        match="already registered",
    ):
        store.register(replacement)

    assert store.get(record.invocation_id) == record


def test_tool_round_trip_and_duplicate_registration_is_immutable(
    pool,
) -> None:
    store = PostgresToolRegistry(pool)

    tool = ToolRegistration(
        tool_id="billing-refund",
        implementation_id="billing-refund@sha256:abc",
        allowed_actions=frozenset({"refund", "read"}),
    )

    assert store.register(tool) == tool
    assert (
        store.get(
            tool.tool_id,
            tool.implementation_id,
        )
        == tool
    )

    assert store.is_trusted(
        tool.tool_id,
        tool.implementation_id,
    )

    assert store.allows_action(
        tool.tool_id,
        tool.implementation_id,
        "refund",
    )

    assert not store.allows_action(
        tool.tool_id,
        tool.implementation_id,
        "delete",
    )

    replacement = ToolRegistration(
        tool_id=tool.tool_id,
        implementation_id=tool.implementation_id,
        allowed_actions=frozenset({"delete"}),
    )

    with pytest.raises(
        ValueError,
        match="already registered",
    ):
        store.register(replacement)

    assert (
        store.get(
            tool.tool_id,
            tool.implementation_id,
        )
        == tool
    )


def test_revocation_preserves_earliest_effective_time(
    pool,
) -> None:
    store = PostgresRevocationStore(pool)
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)

    first = store.revoke(
        "grant-1",
        reason="scheduled",
        revoked_at=now + timedelta(hours=1),
    )

    later = store.revoke(
        "grant-1",
        reason="later",
        revoked_at=now + timedelta(hours=2),
    )

    earlier = store.revoke(
        "grant-1",
        reason="emergency",
        revoked_at=now,
    )

    assert later == first
    assert earlier.revoked_at == now
    assert earlier.reason == "emergency"
    assert store.get("grant-1") == earlier
    assert store.is_revoked("grant-1", at=now)
    assert store.snapshot() == (earlier,)


def test_concurrent_revocations_converge_on_earliest_time(
    pool,
) -> None:
    store = PostgresRevocationStore(pool)

    base = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)

    candidates = [
        (base + timedelta(minutes=offset), f"reason-{offset}")
        for offset in (50, 40, 30, 20, 10, 0, 60, 70, 80, 90)
    ]

    def revoke(candidate: tuple[datetime, str]):
        revoked_at, reason = candidate
        return store.revoke(
            "grant-concurrent",
            reason=reason,
            revoked_at=revoked_at,
        )

    with ThreadPoolExecutor(max_workers=len(candidates)) as executor:
        list(executor.map(revoke, candidates))

    record = store.get("grant-concurrent")

    assert record is not None
    assert record.revoked_at == base
    assert record.reason == "reason-0"


def test_database_failure_is_not_translated_to_not_found(
    pool,
) -> None:
    store = PostgresGrantStore(pool)

    pool.close()

    with pytest.raises(Exception):
        store.get("missing")
