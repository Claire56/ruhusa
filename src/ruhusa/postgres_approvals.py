from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from psycopg import Cursor
from psycopg.errors import UniqueViolation
from psycopg_pool import ConnectionPool

from .approvals import (
    ApprovalRecord,
    ApprovalState,
    ApprovalTransitionResult,
)
from .execution import ExecutionPermit

_APPROVAL_COLUMNS = """
    approval_id,
    invocation_id,
    task_id,
    requested_at,
    expires_at,
    state,
    approved_by,
    approved_at,
    rejected_by,
    rejected_at,
    revoked_by,
    revoked_at,
    consumed_at,
    consumed_claim_id,
    consumed_attempt
"""


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _optional_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return _as_utc(value)


def _approval_from_row(row: tuple[Any, ...]) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=row[0],
        invocation_id=row[1],
        task_id=row[2],
        requested_at=_as_utc(row[3]),
        expires_at=_as_utc(row[4]),
        state=ApprovalState(row[5]),
        approved_by=row[6],
        approved_at=_optional_utc(row[7]),
        rejected_by=row[8],
        rejected_at=_optional_utc(row[9]),
        revoked_by=row[10],
        revoked_at=_optional_utc(row[11]),
        consumed_at=_optional_utc(row[12]),
        consumed_claim_id=row[13],
        consumed_attempt=row[14],
    )


class PostgresApprovalStore:
    """Durable approval lifecycle backed by PostgreSQL.

    PostgreSQL is the concurrency authority. Every state transition locks the
    canonical approval row before inspecting or changing it. Approval
    consumption is fenced by the exact execution permit
    ``(invocation_id, claim_id, attempt)``.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        self._validate_new_record(record)

        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        INSERT INTO ruhusa_approvals (
                            approval_id,
                            invocation_id,
                            task_id,
                            requested_at,
                            expires_at,
                            state
                        )
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING {_APPROVAL_COLUMNS}
                        """,
                        (
                            record.approval_id,
                            record.invocation_id,
                            record.task_id,
                            _as_utc(record.requested_at),
                            _as_utc(record.expires_at),
                            ApprovalState.PENDING.value,
                        ),
                    )
                    row = cur.fetchone()
        except UniqueViolation as exc:
            raise ValueError(
                "approval ID already exists or invocation already has an active approval"
            ) from exc

        if row is None:
            raise RuntimeError("approval insert returned no row")

        return _approval_from_row(row)

    def get(self, approval_id: str) -> ApprovalRecord | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT {_APPROVAL_COLUMNS}
                    FROM ruhusa_approvals
                    WHERE approval_id = %s
                    """,
                    (approval_id,),
                )
                row = cur.fetchone()

        return None if row is None else _approval_from_row(row)

    def approve(
        self,
        approval_id: str,
        *,
        approved_by: str,
        now: datetime | None = None,
    ) -> ApprovalTransitionResult:
        approved_by = self._require_non_empty("approved_by", approved_by)
        observed_at = _as_utc(now or datetime.now(UTC))

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                record = self._lock_current(cur, approval_id)
                if record is None:
                    return ApprovalTransitionResult(False, "approval not found")

                record = self._expire_if_needed(cur, record, observed_at)
                if record.state is not ApprovalState.PENDING:
                    return ApprovalTransitionResult(
                        False,
                        f"approval is already {record.state.value}",
                        record,
                    )

                cur.execute(
                    f"""
                    UPDATE ruhusa_approvals
                    SET
                        state = %s,
                        approved_by = %s,
                        approved_at = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE approval_id = %s
                    RETURNING {_APPROVAL_COLUMNS}
                    """,
                    (
                        ApprovalState.APPROVED.value,
                        approved_by,
                        observed_at,
                        approval_id,
                    ),
                )
                row = cur.fetchone()

        if row is None:
            raise RuntimeError("approval update returned no row")

        return ApprovalTransitionResult(
            True,
            "approval granted",
            _approval_from_row(row),
        )

    def reject(
        self,
        approval_id: str,
        *,
        rejected_by: str,
        now: datetime | None = None,
    ) -> ApprovalTransitionResult:
        rejected_by = self._require_non_empty("rejected_by", rejected_by)
        observed_at = _as_utc(now or datetime.now(UTC))

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                record = self._lock_current(cur, approval_id)
                if record is None:
                    return ApprovalTransitionResult(False, "approval not found")

                record = self._expire_if_needed(cur, record, observed_at)
                if record.state is not ApprovalState.PENDING:
                    return ApprovalTransitionResult(
                        False,
                        f"approval is already {record.state.value}",
                        record,
                    )

                cur.execute(
                    f"""
                    UPDATE ruhusa_approvals
                    SET
                        state = %s,
                        rejected_by = %s,
                        rejected_at = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE approval_id = %s
                    RETURNING {_APPROVAL_COLUMNS}
                    """,
                    (
                        ApprovalState.REJECTED.value,
                        rejected_by,
                        observed_at,
                        approval_id,
                    ),
                )
                row = cur.fetchone()

        if row is None:
            raise RuntimeError("approval reject update returned no row")

        return ApprovalTransitionResult(
            True,
            "approval rejected",
            _approval_from_row(row),
        )

    def revoke(
        self,
        approval_id: str,
        *,
        revoked_by: str,
        now: datetime | None = None,
    ) -> ApprovalTransitionResult:
        revoked_by = self._require_non_empty("revoked_by", revoked_by)
        observed_at = _as_utc(now or datetime.now(UTC))

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                record = self._lock_current(cur, approval_id)
                if record is None:
                    return ApprovalTransitionResult(False, "approval not found")

                record = self._expire_if_needed(cur, record, observed_at)
                if record.state not in {
                    ApprovalState.PENDING,
                    ApprovalState.APPROVED,
                }:
                    return ApprovalTransitionResult(
                        False,
                        f"approval is already {record.state.value}",
                        record,
                    )

                cur.execute(
                    f"""
                    UPDATE ruhusa_approvals
                    SET
                        state = %s,
                        revoked_by = %s,
                        revoked_at = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE approval_id = %s
                    RETURNING {_APPROVAL_COLUMNS}
                    """,
                    (
                        ApprovalState.REVOKED.value,
                        revoked_by,
                        observed_at,
                        approval_id,
                    ),
                )
                row = cur.fetchone()

        if row is None:
            raise RuntimeError("approval revoke update returned no row")

        return ApprovalTransitionResult(
            True,
            "approval revoked",
            _approval_from_row(row),
        )

    def consume(
        self,
        approval_id: str,
        *,
        permit: ExecutionPermit,
        now: datetime | None = None,
    ) -> ApprovalTransitionResult:
        if not permit.claim_id.strip():
            raise ValueError("permit.claim_id must not be empty")
        if permit.attempt <= 0:
            raise ValueError("permit.attempt must be greater than zero")

        observed_at = _as_utc(now or datetime.now(UTC))

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                record = self._lock_current(cur, approval_id)
                if record is None:
                    return ApprovalTransitionResult(False, "approval not found")

                record = self._expire_if_needed(cur, record, observed_at)

                if record.invocation_id != permit.invocation_id:
                    return ApprovalTransitionResult(
                        False,
                        "approval is bound to a different invocation",
                        record,
                    )

                if record.state is not ApprovalState.APPROVED:
                    return ApprovalTransitionResult(
                        False,
                        f"approval is already {record.state.value}",
                        record,
                    )

                cur.execute(
                    f"""
                    UPDATE ruhusa_approvals
                    SET
                        state = %s,
                        consumed_at = %s,
                        consumed_claim_id = %s,
                        consumed_attempt = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE approval_id = %s
                    RETURNING {_APPROVAL_COLUMNS}
                    """,
                    (
                        ApprovalState.CONSUMED.value,
                        observed_at,
                        permit.claim_id,
                        permit.attempt,
                        approval_id,
                    ),
                )
                row = cur.fetchone()

        if row is None:
            raise RuntimeError("approval consume update returned no row")

        return ApprovalTransitionResult(
            True,
            "approval consumed by execution attempt",
            _approval_from_row(row),
        )

    @staticmethod
    def _validate_new_record(record: ApprovalRecord) -> None:
        if record.state is not ApprovalState.PENDING:
            raise ValueError("new approval records must start in pending state")
        if _as_utc(record.expires_at) <= _as_utc(record.requested_at):
            raise ValueError("approval expiry must be after request time")

        transition_values = (
            record.approved_by,
            record.approved_at,
            record.rejected_by,
            record.rejected_at,
            record.revoked_by,
            record.revoked_at,
            record.consumed_at,
            record.consumed_claim_id,
            record.consumed_attempt,
        )
        if any(value is not None for value in transition_values):
            raise ValueError("new approval records must not contain transition metadata")

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(f"{name} must not be empty")
        return value

    @staticmethod
    def _lock_current(
        cur: Cursor,
        approval_id: str,
    ) -> ApprovalRecord | None:
        cur.execute(
            f"""
            SELECT {_APPROVAL_COLUMNS}
            FROM ruhusa_approvals
            WHERE approval_id = %s
            FOR UPDATE
            """,
            (approval_id,),
        )
        row = cur.fetchone()
        return None if row is None else _approval_from_row(row)

    @staticmethod
    def _expire_if_needed(
        cur: Cursor,
        record: ApprovalRecord,
        observed_at: datetime,
    ) -> ApprovalRecord:
        if record.state in {
            ApprovalState.PENDING,
            ApprovalState.APPROVED,
        } and observed_at >= _as_utc(record.expires_at):
            cur.execute(
                f"""
                UPDATE ruhusa_approvals
                SET
                    state = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE approval_id = %s
                RETURNING {_APPROVAL_COLUMNS}
                """,
                (
                    ApprovalState.EXPIRED.value,
                    record.approval_id,
                ),
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError("approval expiry update returned no row")
            return _approval_from_row(row)

        return record
