from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest

pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from ruhusa.interfaces import AuditLog  # noqa: E402
from ruhusa.models import (  # noqa: E402
    AuthorizationDecision,
    AuthorizationRequest,
    DecisionEffect,
    Principal,
    TaskContext,
)
from ruhusa.postgres import (  # noqa: E402
    PostgresAuditLog,
    create_postgres_pool,
    initialize_postgres_schema,
)

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
        max_size=30,
    )

    initialize_postgres_schema(pool)

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE ruhusa_audit_events")
            cur.execute(
                """
                UPDATE ruhusa_audit_chain
                SET
                    last_sequence = 0,
                    last_hash = 'GENESIS',
                    updated_at = CURRENT_TIMESTAMP
                WHERE singleton = TRUE
                """
            )

    try:
        yield pool
    finally:
        pool.close()


def _request(
    *,
    principal_id: str = "agent-1",
    action: str = "read",
    arguments=None,
) -> AuthorizationRequest:
    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)

    return AuthorizationRequest(
        principal=Principal(principal_id),
        action=action,
        resource="record:123",
        arguments=(arguments if arguments is not None else {"value": 1}),
        task=TaskContext(
            task_id="task-1",
            initiated_by="user-1",
            purpose="test",
            expires_at=(now + timedelta(hours=1)),
        ),
    )


def _decision(
    *,
    effect: DecisionEffect = DecisionEffect.ALLOW,
    reason: str = "allowed",
) -> AuthorizationDecision:
    return AuthorizationDecision(
        effect=effect,
        reason=reason,
        policy_id="policy-1",
    )


def test_postgres_audit_log_satisfies_protocol(pool) -> None:
    assert isinstance(PostgresAuditLog(pool), AuditLog)


def test_audit_round_trip_and_chain_verifies(pool) -> None:
    log = PostgresAuditLog(pool)

    audit_id = log.append(_request(), _decision())
    event = log.get(audit_id)

    assert event is not None
    assert event.audit_id == audit_id
    assert event.previous_hash == "GENESIS"
    assert event.effect == "allow"
    assert log.verify_chain()


def test_sensitive_arguments_are_redacted(pool) -> None:
    log = PostgresAuditLog(pool)

    audit_id = log.append(
        _request(
            arguments={
                "amount": 100,
                "token": "super-secret",
                "nested": {
                    "password": "hidden",
                    "safe": "visible",
                },
            }
        ),
        _decision(),
    )

    event = log.get(audit_id)

    assert event is not None
    assert event.arguments["token"] == "[REDACTED]"
    assert event.arguments["nested"]["password"] == "[REDACTED]"
    assert event.arguments["nested"]["safe"] == "visible"
    assert log.verify_chain()


def test_multiple_events_form_continuous_chain(pool) -> None:
    log = PostgresAuditLog(pool)

    for index in range(10):
        log.append(
            _request(principal_id=f"agent-{index}"),
            _decision(reason=f"decision-{index}"),
        )

    events = log.snapshot()

    assert len(events) == 10
    assert events[0].previous_hash == "GENESIS"

    for previous, current in zip(events, events[1:], strict=True):
        assert current.previous_hash == previous.event_hash

    assert log.verify_chain()


def test_concurrent_appends_create_one_chain(pool) -> None:
    worker_count = 25
    barrier = Barrier(worker_count)

    def append(index: int) -> str:
        worker_log = PostgresAuditLog(pool)
        barrier.wait()

        return worker_log.append(
            _request(principal_id=f"worker-{index}"),
            _decision(reason=f"concurrent-{index}"),
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        audit_ids = list(executor.map(append, range(worker_count)))

    assert len(set(audit_ids)) == worker_count

    log = PostgresAuditLog(pool)
    events = log.snapshot()

    assert len(events) == worker_count
    assert events[0].previous_hash == "GENESIS"

    for previous, current in zip(events, events[1:], strict=True):
        assert current.previous_hash == previous.event_hash

    assert log.verify_chain()


def test_event_tampering_is_detected(pool) -> None:
    log = PostgresAuditLog(pool)

    audit_id = log.append(_request(), _decision())
    assert log.verify_chain()

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE ruhusa_audit_events SET reason = %s WHERE audit_id = %s",
                ("tampered", audit_id),
            )

    assert not log.verify_chain()


def test_chain_head_corruption_blocks_append(pool) -> None:
    log = PostgresAuditLog(pool)

    log.append(_request(), _decision())

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE ruhusa_audit_chain SET last_hash = %s WHERE singleton = TRUE",
                ("corrupted",),
            )

    with pytest.raises(RuntimeError, match="chain head"):
        log.append(_request(principal_id="agent-2"), _decision())


def test_missing_event_blocks_chain_extension(pool) -> None:
    log = PostgresAuditLog(pool)

    first = log.append(_request(principal_id="agent-1"), _decision())

    log.append(_request(principal_id="agent-2"), _decision())

    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM ruhusa_audit_events WHERE audit_id = %s",
                (first,),
            )

    assert not log.verify_chain()

    with pytest.raises(RuntimeError, match="inconsistent"):
        log.append(_request(principal_id="agent-3"), _decision())


def test_database_failure_propagates(pool) -> None:
    log = PostgresAuditLog(pool)

    pool.close()

    with pytest.raises(Exception):
        log.append(_request(), _decision())


def test_postgres_audit_outage_prevents_allow(pool) -> None:
    from ruhusa.core import Ruhusa
    from ruhusa.policy import PolicyRule, StaticPolicyStore

    log = PostgresAuditLog(pool)

    policy_store = StaticPolicyStore(
        [
            PolicyRule(
                policy_id="allow-read",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"read"}),
                principal_ids=frozenset({"agent-1"}),
                reason="read allowed",
            )
        ]
    )

    gate = Ruhusa(
        policy_store=policy_store,
        audit_log=log,
    )

    pool.close()

    decision = gate.authorize(
        _request(),
        now=datetime(2026, 8, 27, 12, 0, tzinfo=UTC),
    )

    assert decision.effect is DecisionEffect.DENY
    assert decision.reason == "audit log unavailable; default deny"
    assert decision.audit_id is None
