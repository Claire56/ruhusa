from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .invocations import InvocationRecord
from .models import DelegationGrant, Scope
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
