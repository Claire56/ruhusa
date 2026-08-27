from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .audit import AuditEvent, _redact
from .execution import (
    ExecutionClaimResult,
    ExecutionPermit,
    ExecutionRecord,
    ExecutionRecoveryOutcome,
    ExecutionState,
)
from .invocations import InvocationRecord
from .models import (
    AuthorizationDecision,
    AuthorizationRequest,
    DelegationGrant,
    Scope,
)
from .revocation import RevocationRecord
from .tools import ToolRegistration

SCHEMA_VERSION = 1

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS ruhusa_schema_metadata (
        singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
        version INTEGER NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ruhusa_grants (
        grant_id TEXT PRIMARY KEY,
        grantor_id TEXT NOT NULL,
        grantee_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        actions JSONB NOT NULL,
        resource_prefixes JSONB NOT NULL,
        max_numeric_arguments JSONB NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ruhusa_revocations (
        grant_id TEXT PRIMARY KEY,
        revoked_at TIMESTAMPTZ NOT NULL,
        reason TEXT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ruhusa_invocations (
        invocation_id TEXT PRIMARY KEY,
        invoking_principal_id TEXT NOT NULL,
        executing_principal_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        arguments_digest TEXT NOT NULL,
        tool_id TEXT,
        implementation_id TEXT,
        recorded_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ruhusa_tools (
        tool_id TEXT NOT NULL,
        implementation_id TEXT NOT NULL,
        allowed_actions JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (tool_id, implementation_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ruhusa_audit_chain (
        singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
        last_sequence BIGINT NOT NULL DEFAULT 0
            CHECK (last_sequence >= 0),
        last_hash TEXT NOT NULL DEFAULT 'GENESIS',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ruhusa_audit_events (
        sequence BIGINT PRIMARY KEY
            CHECK (sequence > 0),
        audit_id TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        arguments JSONB NOT NULL,
        effect TEXT NOT NULL
            CHECK (
                effect IN (
                    'allow',
                    'deny',
                    'require_approval'
                )
            ),
        reason TEXT NOT NULL,
        policy_id TEXT,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    INSERT INTO ruhusa_audit_chain (
        singleton,
        last_sequence,
        last_hash
    )
    VALUES (
        TRUE,
        0,
        'GENESIS'
    )
    ON CONFLICT (singleton) DO NOTHING
    """,
    """
    CREATE TABLE IF NOT EXISTS ruhusa_executions (
        invocation_id TEXT PRIMARY KEY,
        expires_at TIMESTAMPTZ NOT NULL,
        state TEXT NOT NULL DEFAULT 'available'
            CHECK (
                state IN (
                    'available',
                    'claimed',
                    'completed',
                    'unknown',
                    'cancelled'
                )
            ),
        attempt_count INTEGER NOT NULL DEFAULT 0
            CHECK (attempt_count >= 0),
        claim_id TEXT,
        claimed_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        released_at TIMESTAMPTZ,
        unknown_at TIMESTAMPTZ,
        cancelled_at TIMESTAMPTZ,
        cancel_reason TEXT,
        recovered_at TIMESTAMPTZ,
        recovery_outcome TEXT
            CHECK (
                recovery_outcome IS NULL
                OR recovery_outcome IN (
                    'side_effect_confirmed',
                    'side_effect_not_applied'
                )
            ),
        recovery_reason TEXT,
        recovery_count INTEGER NOT NULL DEFAULT 0
            CHECK (recovery_count >= 0),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
)


def create_postgres_pool(
    conninfo: str,
    *,
    min_size: int = 1,
    max_size: int = 10,
    timeout: float = 30.0,
) -> ConnectionPool:
    """Create and validate a synchronous Psycopg connection pool."""
    pool = ConnectionPool(
        conninfo=conninfo,
        min_size=min_size,
        max_size=max_size,
        timeout=timeout,
        open=True,
    )
    try:
        pool.wait(timeout=timeout)
    except Exception:
        pool.close()
        raise
    return pool


def initialize_postgres_schema(pool: ConnectionPool) -> None:
    """Create the v0.7-B PostgreSQL schema and verify its version."""
    with pool.connection() as conn:
        with conn.cursor() as cur:
            for statement in _SCHEMA_STATEMENTS:
                cur.execute(statement)

            cur.execute(
                """
                INSERT INTO ruhusa_schema_metadata (singleton, version)
                VALUES (TRUE, %s)
                ON CONFLICT (singleton) DO NOTHING
                """,
                (SCHEMA_VERSION,),
            )

            cur.execute("SELECT version FROM ruhusa_schema_metadata WHERE singleton = TRUE")
            row = cur.fetchone()

            if row is None or row[0] != SCHEMA_VERSION:
                found = None if row is None else row[0]
                raise RuntimeError(
                    f"unsupported Ruhusa PostgreSQL schema version {found!r}; "
                    f"expected {SCHEMA_VERSION}"
                )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _optional_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return _as_utc(value)


def _grant_from_row(row: tuple[Any, ...]) -> DelegationGrant:
    return DelegationGrant(
        grant_id=row[0],
        grantor_id=row[1],
        grantee_id=row[2],
        task_id=row[3],
        scope=Scope(
            actions=frozenset(row[4]),
            resource_prefixes=tuple(row[5]),
            max_numeric_arguments=dict(row[6]),
        ),
        issued_at=datetime.fromisoformat(row[7]),
        expires_at=datetime.fromisoformat(row[8]),
    )


def _invocation_from_row(row: tuple[Any, ...]) -> InvocationRecord:
    return InvocationRecord(
        invocation_id=row[0],
        invoking_principal_id=row[1],
        executing_principal_id=row[2],
        task_id=row[3],
        action=row[4],
        resource=row[5],
        arguments_digest=row[6],
        tool_id=row[7],
        implementation_id=row[8],
        recorded_at=datetime.fromisoformat(row[9]),
        expires_at=datetime.fromisoformat(row[10]),
    )


def _tool_from_row(row: tuple[Any, ...]) -> ToolRegistration:
    return ToolRegistration(
        tool_id=row[0],
        implementation_id=row[1],
        allowed_actions=frozenset(row[2]),
    )


def _execution_from_row(row: tuple[Any, ...]) -> ExecutionRecord:
    recovery_outcome = None if row[12] is None else ExecutionRecoveryOutcome(row[12])

    return ExecutionRecord(
        invocation_id=row[0],
        expires_at=_as_utc(row[1]),
        state=ExecutionState(row[2]),
        attempt_count=row[3],
        claim_id=row[4],
        claimed_at=_optional_utc(row[5]),
        completed_at=_optional_utc(row[6]),
        released_at=_optional_utc(row[7]),
        unknown_at=_optional_utc(row[8]),
        cancelled_at=_optional_utc(row[9]),
        cancel_reason=row[10],
        recovered_at=_optional_utc(row[11]),
        recovery_outcome=recovery_outcome,
        recovery_reason=row[13],
        recovery_count=row[14],
    )


_EXECUTION_COLUMNS = """
    invocation_id,
    expires_at,
    state,
    attempt_count,
    claim_id,
    claimed_at,
    completed_at,
    released_at,
    unknown_at,
    cancelled_at,
    cancel_reason,
    recovered_at,
    recovery_outcome,
    recovery_reason,
    recovery_count
"""

_AUDIT_EVENT_COLUMNS = """
    audit_id,
    timestamp,
    principal_id,
    task_id,
    action,
    resource,
    arguments,
    effect,
    reason,
    policy_id,
    previous_hash,
    event_hash
"""


def _audit_event_from_row(row: tuple[Any, ...]) -> AuditEvent:
    return AuditEvent(
        audit_id=row[0],
        timestamp=row[1],
        principal_id=row[2],
        task_id=row[3],
        action=row[4],
        resource=row[5],
        arguments=dict(row[6]),
        effect=row[7],
        reason=row[8],
        policy_id=row[9],
        previous_hash=row[10],
        event_hash=row[11],
    )


def _build_audit_payload(
    request: AuthorizationRequest,
    decision: AuthorizationDecision,
    *,
    audit_id: str,
    timestamp: str,
    previous_hash: str,
) -> dict[str, Any]:
    return {
        "audit_id": audit_id,
        "timestamp": timestamp,
        "principal_id": request.principal.principal_id,
        "task_id": request.task.task_id,
        "action": request.action,
        "resource": request.resource,
        "arguments": _redact(dict(request.arguments)),
        "effect": decision.effect.value,
        "reason": decision.reason,
        "policy_id": decision.policy_id,
        "previous_hash": previous_hash,
    }


def _serialize_audit_payload(
    payload: dict[str, Any],
) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _calculate_audit_hash(
    payload: dict[str, Any],
) -> str:
    serialized = _serialize_audit_payload(payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class PostgresGrantStore:
    """Durable immutable grant registry backed by PostgreSQL."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def register(self, grant: DelegationGrant) -> DelegationGrant:
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ruhusa_grants (
                            grant_id,
                            grantor_id,
                            grantee_id,
                            task_id,
                            actions,
                            resource_prefixes,
                            max_numeric_arguments,
                            issued_at,
                            expires_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            grant.grant_id,
                            grant.grantor_id,
                            grant.grantee_id,
                            grant.task_id,
                            Jsonb(sorted(grant.scope.actions)),
                            Jsonb(list(grant.scope.resource_prefixes)),
                            Jsonb(dict(grant.scope.max_numeric_arguments)),
                            grant.issued_at.isoformat(),
                            grant.expires_at.isoformat(),
                        ),
                    )
        except UniqueViolation as exc:
            raise ValueError(
                f"grant {grant.grant_id!r} is already registered; "
                "grant IDs are immutable — use a new grant_id for re-issuance"
            ) from exc

        return grant

    def get(self, grant_id: str) -> DelegationGrant | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        grant_id,
                        grantor_id,
                        grantee_id,
                        task_id,
                        actions,
                        resource_prefixes,
                        max_numeric_arguments,
                        issued_at,
                        expires_at
                    FROM ruhusa_grants
                    WHERE grant_id = %s
                    """,
                    (grant_id,),
                )
                row = cur.fetchone()

        return None if row is None else _grant_from_row(row)

    def contains(self, grant_id: str) -> bool:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT EXISTS(SELECT 1 FROM ruhusa_grants WHERE grant_id = %s)",
                    (grant_id,),
                )
                row = cur.fetchone()

        return bool(row and row[0])

    def is_registered(self, grant: DelegationGrant) -> bool:
        stored = self.get(grant.grant_id)
        return stored == grant


class PostgresRevocationStore:
    """Durable monotonic revocation store backed by PostgreSQL."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def revoke(
        self,
        grant_id: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> RevocationRecord:
        candidate = RevocationRecord(
            grant_id=grant_id,
            revoked_at=revoked_at or datetime.now(UTC),
            reason=reason,
        )

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO ruhusa_revocations (grant_id, revoked_at, reason)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (grant_id) DO UPDATE
                    SET
                        revoked_at = LEAST(
                            ruhusa_revocations.revoked_at,
                            EXCLUDED.revoked_at
                        ),
                        reason = CASE
                            WHEN EXCLUDED.revoked_at < ruhusa_revocations.revoked_at
                                THEN EXCLUDED.reason
                            ELSE ruhusa_revocations.reason
                        END,
                        updated_at = CURRENT_TIMESTAMP
                    RETURNING grant_id, revoked_at, reason
                    """,
                    (
                        candidate.grant_id,
                        candidate.revoked_at,
                        candidate.reason,
                    ),
                )
                row = cur.fetchone()

        if row is None:
            raise RuntimeError("revocation upsert returned no row")

        return RevocationRecord(
            grant_id=row[0],
            revoked_at=row[1],
            reason=row[2],
        )

    def is_revoked(
        self,
        grant_id: str,
        *,
        at: datetime | None = None,
    ) -> bool:
        check_time = _as_utc(at or datetime.now(UTC))

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT revoked_at <= %s
                    FROM ruhusa_revocations
                    WHERE grant_id = %s
                    """,
                    (check_time, grant_id),
                )
                row = cur.fetchone()

        return bool(row and row[0])

    def get(self, grant_id: str) -> RevocationRecord | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT grant_id, revoked_at, reason
                    FROM ruhusa_revocations
                    WHERE grant_id = %s
                    """,
                    (grant_id,),
                )
                row = cur.fetchone()

        if row is None:
            return None

        return RevocationRecord(
            grant_id=row[0],
            revoked_at=row[1],
            reason=row[2],
        )

    def snapshot(self) -> tuple[RevocationRecord, ...]:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT grant_id, revoked_at, reason
                    FROM ruhusa_revocations
                    ORDER BY grant_id
                    """
                )
                rows = cur.fetchall()

        return tuple(
            RevocationRecord(
                grant_id=row[0],
                revoked_at=row[1],
                reason=row[2],
            )
            for row in rows
        )


class PostgresInvocationStore:
    """Durable immutable invocation-provenance registry backed by PostgreSQL."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def register(self, record: InvocationRecord) -> InvocationRecord:
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ruhusa_invocations (
                            invocation_id,
                            invoking_principal_id,
                            executing_principal_id,
                            task_id,
                            action,
                            resource,
                            arguments_digest,
                            tool_id,
                            implementation_id,
                            recorded_at,
                            expires_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            record.invocation_id,
                            record.invoking_principal_id,
                            record.executing_principal_id,
                            record.task_id,
                            record.action,
                            record.resource,
                            record.arguments_digest,
                            record.tool_id,
                            record.implementation_id,
                            record.recorded_at.isoformat(),
                            record.expires_at.isoformat(),
                        ),
                    )
        except UniqueViolation as exc:
            raise ValueError(f"invocation {record.invocation_id!r} is already registered") from exc

        return record

    def get(self, invocation_id: str) -> InvocationRecord | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        invocation_id,
                        invoking_principal_id,
                        executing_principal_id,
                        task_id,
                        action,
                        resource,
                        arguments_digest,
                        tool_id,
                        implementation_id,
                        recorded_at,
                        expires_at
                    FROM ruhusa_invocations
                    WHERE invocation_id = %s
                    """,
                    (invocation_id,),
                )
                row = cur.fetchone()

        return None if row is None else _invocation_from_row(row)

    def is_registered(self, invocation_id: str) -> bool:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1
                        FROM ruhusa_invocations
                        WHERE invocation_id = %s
                    )
                    """,
                    (invocation_id,),
                )
                row = cur.fetchone()

        return bool(row and row[0])


class PostgresToolRegistry:
    """Durable immutable registry of trusted tool implementations."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def register(self, tool: ToolRegistration) -> ToolRegistration:
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ruhusa_tools (
                            tool_id,
                            implementation_id,
                            allowed_actions
                        )
                        VALUES (%s, %s, %s)
                        """,
                        (
                            tool.tool_id,
                            tool.implementation_id,
                            Jsonb(sorted(tool.allowed_actions)),
                        ),
                    )
        except UniqueViolation as exc:
            raise ValueError(
                f"tool {tool.tool_id!r} implementation "
                f"{tool.implementation_id!r} is already registered"
            ) from exc

        return tool

    def get(
        self,
        tool_id: str,
        implementation_id: str,
    ) -> ToolRegistration | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT tool_id, implementation_id, allowed_actions
                    FROM ruhusa_tools
                    WHERE tool_id = %s AND implementation_id = %s
                    """,
                    (tool_id, implementation_id),
                )
                row = cur.fetchone()

        return None if row is None else _tool_from_row(row)

    def is_trusted(
        self,
        tool_id: str,
        implementation_id: str,
    ) -> bool:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1
                        FROM ruhusa_tools
                        WHERE tool_id = %s AND implementation_id = %s
                    )
                    """,
                    (tool_id, implementation_id),
                )
                row = cur.fetchone()

        return bool(row and row[0])

    def allows_action(
        self,
        tool_id: str,
        implementation_id: str,
        action: str,
    ) -> bool:
        registration = self.get(tool_id, implementation_id)

        if registration is None:
            return False

        return action in registration.allowed_actions


class PostgresExecutionStore:
    """Durable distributed execution lifecycle backed by PostgreSQL.

    PostgreSQL is the concurrency authority. Claim ownership is fenced by the
    tuple ``(invocation_id, claim_id, attempt_count)`` so stale workers cannot
    mutate a newer execution attempt.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def get(self, invocation_id: str) -> ExecutionRecord | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT {_EXECUTION_COLUMNS}
                    FROM ruhusa_executions
                    WHERE invocation_id = %s
                    """,
                    (invocation_id,),
                )
                row = cur.fetchone()

        return None if row is None else _execution_from_row(row)

    def claim(
        self,
        invocation_id: str,
        *,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> ExecutionClaimResult:
        now = _as_utc(now or datetime.now(UTC))
        canonical_expiry = _as_utc(expires_at)

        if now >= canonical_expiry:
            return ExecutionClaimResult(
                allowed=False,
                reason="execution authority has expired",
            )

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                # The PK guarantees one canonical execution row.
                #
                # Concurrent inserts for the same invocation serialize through
                # PostgreSQL's unique constraint. The following SELECT FOR
                # UPDATE then makes the state inspection/update atomic.
                cur.execute(
                    """
                    INSERT INTO ruhusa_executions (
                        invocation_id,
                        expires_at
                    )
                    VALUES (%s, %s)
                    ON CONFLICT (invocation_id) DO NOTHING
                    """,
                    (
                        invocation_id,
                        canonical_expiry,
                    ),
                )

                cur.execute(
                    f"""
                    SELECT {_EXECUTION_COLUMNS}
                    FROM ruhusa_executions
                    WHERE invocation_id = %s
                    FOR UPDATE
                    """,
                    (invocation_id,),
                )
                row = cur.fetchone()

                if row is None:
                    raise RuntimeError("execution lifecycle row disappeared during claim")

                record = _execution_from_row(row)

                if _as_utc(record.expires_at) != canonical_expiry:
                    return ExecutionClaimResult(
                        allowed=False,
                        reason=("execution lifecycle expiry does not match canonical invocation"),
                        record=record,
                    )

                if record.state is not ExecutionState.AVAILABLE:
                    return ExecutionClaimResult(
                        allowed=False,
                        reason=(f"execution authority is already {record.state.value}"),
                        record=record,
                    )

                claim_id = uuid4().hex
                attempt = record.attempt_count + 1

                cur.execute(
                    f"""
                    UPDATE ruhusa_executions
                    SET
                        state = %s,
                        attempt_count = %s,
                        claim_id = %s,
                        claimed_at = %s,
                        completed_at = NULL,
                        released_at = NULL,
                        unknown_at = NULL,
                        cancelled_at = NULL,
                        cancel_reason = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE invocation_id = %s
                    RETURNING {_EXECUTION_COLUMNS}
                    """,
                    (
                        ExecutionState.CLAIMED.value,
                        attempt,
                        claim_id,
                        now,
                        invocation_id,
                    ),
                )
                updated_row = cur.fetchone()

                if updated_row is None:
                    raise RuntimeError("execution lifecycle claim update returned no row")

        updated = _execution_from_row(updated_row)

        return ExecutionClaimResult(
            allowed=True,
            reason="execution authority claimed",
            record=updated,
            permit=ExecutionPermit(
                invocation_id=invocation_id,
                claim_id=claim_id,
                attempt=attempt,
            ),
        )

    def is_active(self, permit: ExecutionPermit) -> bool:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT EXISTS(
                        SELECT 1
                        FROM ruhusa_executions
                        WHERE
                            invocation_id = %s
                            AND state = %s
                            AND claim_id = %s
                            AND attempt_count = %s
                    )
                    """,
                    (
                        permit.invocation_id,
                        ExecutionState.CLAIMED.value,
                        permit.claim_id,
                        permit.attempt,
                    ),
                )
                row = cur.fetchone()

        return bool(row and row[0])

    def complete(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        now = _as_utc(now or datetime.now(UTC))

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE ruhusa_executions
                    SET
                        state = %s,
                        completed_at = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE
                        invocation_id = %s
                        AND state = %s
                        AND claim_id = %s
                        AND attempt_count = %s
                    RETURNING invocation_id
                    """,
                    (
                        ExecutionState.COMPLETED.value,
                        now,
                        permit.invocation_id,
                        ExecutionState.CLAIMED.value,
                        permit.claim_id,
                        permit.attempt,
                    ),
                )
                return cur.fetchone() is not None

    def release_before_execution(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        now = _as_utc(now or datetime.now(UTC))

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE ruhusa_executions
                    SET
                        state = %s,
                        claim_id = NULL,
                        released_at = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE
                        invocation_id = %s
                        AND state = %s
                        AND claim_id = %s
                        AND attempt_count = %s
                    RETURNING invocation_id
                    """,
                    (
                        ExecutionState.AVAILABLE.value,
                        now,
                        permit.invocation_id,
                        ExecutionState.CLAIMED.value,
                        permit.claim_id,
                        permit.attempt,
                    ),
                )
                return cur.fetchone() is not None

    def mark_unknown(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> bool:
        now = _as_utc(now or datetime.now(UTC))

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE ruhusa_executions
                    SET
                        state = %s,
                        unknown_at = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE
                        invocation_id = %s
                        AND state = %s
                        AND claim_id = %s
                        AND attempt_count = %s
                    RETURNING invocation_id
                    """,
                    (
                        ExecutionState.UNKNOWN.value,
                        now,
                        permit.invocation_id,
                        ExecutionState.CLAIMED.value,
                        permit.claim_id,
                        permit.attempt,
                    ),
                )
                return cur.fetchone() is not None

    def mark_stale_claim_unknown(
        self,
        invocation_id: str,
        *,
        stale_after: timedelta,
        now: datetime | None = None,
    ) -> bool:
        if stale_after <= timedelta(0):
            raise ValueError("stale_after must be greater than zero")

        now = _as_utc(now or datetime.now(UTC))
        stale_cutoff = now - stale_after

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE ruhusa_executions
                    SET
                        state = %s,
                        unknown_at = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE
                        invocation_id = %s
                        AND state = %s
                        AND claimed_at IS NOT NULL
                        AND claimed_at <= %s
                    RETURNING invocation_id
                    """,
                    (
                        ExecutionState.UNKNOWN.value,
                        now,
                        invocation_id,
                        ExecutionState.CLAIMED.value,
                        stale_cutoff,
                    ),
                )
                return cur.fetchone() is not None

    def reconcile_unknown(
        self,
        invocation_id: str,
        *,
        outcome: ExecutionRecoveryOutcome,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        reason = reason.strip()

        if not reason:
            raise ValueError("recovery reason must not be empty")

        now = _as_utc(now or datetime.now(UTC))

        if outcome is ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED:
            new_state = ExecutionState.COMPLETED
        elif outcome is ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED:
            new_state = ExecutionState.AVAILABLE
        else:
            raise ValueError(f"unsupported recovery outcome: {outcome}")

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                if outcome is ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED:
                    cur.execute(
                        """
                        UPDATE ruhusa_executions
                        SET
                            state = %s,
                            completed_at = %s,
                            recovered_at = %s,
                            recovery_outcome = %s,
                            recovery_reason = %s,
                            recovery_count = recovery_count + 1,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE
                            invocation_id = %s
                            AND state = %s
                        RETURNING invocation_id
                        """,
                        (
                            new_state.value,
                            now,
                            now,
                            outcome.value,
                            reason,
                            invocation_id,
                            ExecutionState.UNKNOWN.value,
                        ),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE ruhusa_executions
                        SET
                            state = %s,
                            claim_id = NULL,
                            released_at = %s,
                            recovered_at = %s,
                            recovery_outcome = %s,
                            recovery_reason = %s,
                            recovery_count = recovery_count + 1,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE
                            invocation_id = %s
                            AND state = %s
                        RETURNING invocation_id
                        """,
                        (
                            new_state.value,
                            now,
                            now,
                            outcome.value,
                            reason,
                            invocation_id,
                            ExecutionState.UNKNOWN.value,
                        ),
                    )

                return cur.fetchone() is not None

    def cancel(
        self,
        permit: ExecutionPermit,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> bool:
        if not reason.strip():
            raise ValueError("cancellation reason must not be empty")

        now = _as_utc(now or datetime.now(UTC))

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE ruhusa_executions
                    SET
                        state = %s,
                        cancelled_at = %s,
                        cancel_reason = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE
                        invocation_id = %s
                        AND state = %s
                        AND claim_id = %s
                        AND attempt_count = %s
                    RETURNING invocation_id
                    """,
                    (
                        ExecutionState.CANCELLED.value,
                        now,
                        reason,
                        permit.invocation_id,
                        ExecutionState.CLAIMED.value,
                        permit.claim_id,
                        permit.attempt,
                    ),
                )
                return cur.fetchone() is not None


class PostgresAuditLog:
    """Durable serialized hash-chain audit log backed by PostgreSQL.

    PostgreSQL serializes writers through one chain-head row. Each event is
    committed atomically with the corresponding chain-head update, preventing
    concurrent writers from creating independent audit branches.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def append(
        self,
        request: AuthorizationRequest,
        decision: AuthorizationDecision,
    ) -> str:
        audit_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC).isoformat()

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                # Serialize every writer on the canonical chain head.
                cur.execute(
                    """
                    SELECT
                        last_sequence,
                        last_hash
                    FROM ruhusa_audit_chain
                    WHERE singleton = TRUE
                    FOR UPDATE
                    """
                )
                head = cur.fetchone()

                if head is None:
                    raise RuntimeError("PostgreSQL audit chain head is missing")

                last_sequence = int(head[0])
                previous_hash = str(head[1])

                # Cheap consistency check before extending the chain.
                cur.execute(
                    """
                    SELECT
                        COUNT(*),
                        COALESCE(MAX(sequence), 0)
                    FROM ruhusa_audit_events
                    """
                )
                statistics = cur.fetchone()

                if statistics is None:
                    raise RuntimeError("unable to inspect PostgreSQL audit chain")

                event_count = int(statistics[0])
                maximum_sequence = int(statistics[1])

                if event_count != last_sequence or maximum_sequence != last_sequence:
                    raise RuntimeError(
                        "PostgreSQL audit chain head is inconsistent with persisted events"
                    )

                if last_sequence == 0:
                    if previous_hash != "GENESIS":
                        raise RuntimeError(
                            "empty PostgreSQL audit chain does not reference GENESIS"
                        )
                else:
                    cur.execute(
                        """
                        SELECT event_hash
                        FROM ruhusa_audit_events
                        WHERE sequence = %s
                        """,
                        (last_sequence,),
                    )
                    tail = cur.fetchone()

                    if tail is None or tail[0] != previous_hash:
                        raise RuntimeError(
                            "PostgreSQL audit chain head does not match persisted tail"
                        )

                next_sequence = last_sequence + 1

                payload = _build_audit_payload(
                    request,
                    decision,
                    audit_id=audit_id,
                    timestamp=timestamp,
                    previous_hash=previous_hash,
                )

                # Normalize types through JSON round-trip so stored values
                # match what will be re-serialized during verify_chain.
                serialized = _serialize_audit_payload(payload)
                canonical_payload = json.loads(serialized)

                event_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

                cur.execute(
                    """
                    INSERT INTO ruhusa_audit_events (
                        sequence,
                        audit_id,
                        timestamp,
                        principal_id,
                        task_id,
                        action,
                        resource,
                        arguments,
                        effect,
                        reason,
                        policy_id,
                        previous_hash,
                        event_hash
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        next_sequence,
                        canonical_payload["audit_id"],
                        canonical_payload["timestamp"],
                        canonical_payload["principal_id"],
                        canonical_payload["task_id"],
                        canonical_payload["action"],
                        canonical_payload["resource"],
                        Jsonb(canonical_payload["arguments"]),
                        canonical_payload["effect"],
                        canonical_payload["reason"],
                        canonical_payload["policy_id"],
                        canonical_payload["previous_hash"],
                        event_hash,
                    ),
                )

                cur.execute(
                    """
                    UPDATE ruhusa_audit_chain
                    SET
                        last_sequence = %s,
                        last_hash = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE
                        singleton = TRUE
                        AND last_sequence = %s
                        AND last_hash = %s
                    RETURNING singleton
                    """,
                    (
                        next_sequence,
                        event_hash,
                        last_sequence,
                        previous_hash,
                    ),
                )

                if cur.fetchone() is None:
                    raise RuntimeError("PostgreSQL audit chain head changed during append")

        return audit_id

    def get(
        self,
        audit_id: str,
    ) -> AuditEvent | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT {_AUDIT_EVENT_COLUMNS}
                    FROM ruhusa_audit_events
                    WHERE audit_id = %s
                    """,
                    (audit_id,),
                )
                row = cur.fetchone()

        if row is None:
            return None

        return _audit_event_from_row(row)

    def snapshot(
        self,
    ) -> tuple[AuditEvent, ...]:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                # Prevent an append from changing the chain while the
                # point-in-time snapshot is being assembled.
                cur.execute(
                    """
                    SELECT
                        last_sequence,
                        last_hash
                    FROM ruhusa_audit_chain
                    WHERE singleton = TRUE
                    FOR SHARE
                    """
                )

                if cur.fetchone() is None:
                    raise RuntimeError("PostgreSQL audit chain head is missing")

                cur.execute(
                    f"""
                    SELECT {_AUDIT_EVENT_COLUMNS}
                    FROM ruhusa_audit_events
                    ORDER BY sequence
                    """
                )
                rows = cur.fetchall()

        return tuple(_audit_event_from_row(row) for row in rows)

    def verify_chain(self) -> bool:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                # SHARE conflicts with the writer's FOR UPDATE lock, giving
                # verification a stable chain while it runs.
                cur.execute(
                    """
                    SELECT
                        last_sequence,
                        last_hash
                    FROM ruhusa_audit_chain
                    WHERE singleton = TRUE
                    FOR SHARE
                    """
                )
                head = cur.fetchone()

                if head is None:
                    raise RuntimeError("PostgreSQL audit chain head is missing")

                last_sequence = int(head[0])
                last_hash = str(head[1])

                cur.execute(
                    f"""
                    SELECT
                        sequence,
                        {_AUDIT_EVENT_COLUMNS}
                    FROM ruhusa_audit_events
                    ORDER BY sequence
                    """
                )
                rows = cur.fetchall()

                if len(rows) != last_sequence:
                    return False

                previous_hash = "GENESIS"
                expected_sequence = 1

                for row in rows:
                    sequence = int(row[0])

                    if sequence != expected_sequence:
                        return False

                    event = _audit_event_from_row(row[1:])

                    if event.previous_hash != previous_hash:
                        return False

                    payload = asdict(event)
                    persisted_event_hash = payload.pop("event_hash")
                    calculated_hash = _calculate_audit_hash(payload)

                    if calculated_hash != persisted_event_hash:
                        return False

                    previous_hash = persisted_event_hash
                    expected_sequence += 1

                if last_sequence == 0:
                    return last_hash == "GENESIS"

                return previous_hash == last_hash
