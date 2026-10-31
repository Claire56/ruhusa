"""Opt-in PostgreSQL atomic recovery (v0.9-D2 development).

The trusted reconciler must be the ONLY role permitted to invoke this service.
Legacy raw reconciliation methods remain privileged and are not gated here.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .execution import ExecutionRecoveryOutcome, ExecutionState
from .postgres_migrations import RECOVERY_RECEIPTS_SCHEMA_DDL as RECOVERY_RECEIPTS_DDL
from .recovery_evidence import RecoveryEvidence, RecoveryEvidenceVerifier, _utc


class PostgresAuthenticatedRecoveryService:
    """Verify and atomically persist evidence + UNKNOWN transition.

    Requires a schema v4 database initialized by initialize_postgres_schema().
    Database errors propagate fail closed.
    """

    def __init__(self, pool, verifier: RecoveryEvidenceVerifier) -> None:
        self._pool = pool
        self._verifier = verifier

    @staticmethod
    def initialize(pool) -> None:
        """Backward-compatible idempotent initializer; prefer schema v4 migrations."""
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(RECOVERY_RECEIPTS_DDL)

    def reconcile(self, evidence: RecoveryEvidence, *, now: datetime | None = None) -> bool:
        now = _utc(now or datetime.now(UTC))
        if not self._verifier.verify(evidence, now=now):
            return False

        if evidence.outcome is ExecutionRecoveryOutcome.SIDE_EFFECT_CONFIRMED:
            state = ExecutionState.COMPLETED
        elif evidence.outcome is ExecutionRecoveryOutcome.SIDE_EFFECT_NOT_APPLIED:
            state = ExecutionState.AVAILABLE
        else:
            return False

        # A single transaction locks the specific UNKNOWN attempt, then
        # inserts the one-use receipt and changes state. On any exception,
        # PostgreSQL rolls back both changes. Separate processes serialize on
        # the execution row and cannot accept two receipts for an attempt.
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT state, claim_id, attempt_count
                       FROM ruhusa_executions WHERE invocation_id = %s FOR UPDATE""",
                    (evidence.invocation_id,),
                )
                row = cur.fetchone()
                if row != (ExecutionState.UNKNOWN.value, evidence.claim_id, evidence.attempt):
                    return False
                cur.execute(
                    """INSERT INTO ruhusa_recovery_receipts
                       (evidence_id, invocation_id, claim_id, attempt, issuer,
                        key_id, outcome, signature, reconciled_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        evidence.evidence_id,
                        evidence.invocation_id,
                        evidence.claim_id,
                        evidence.attempt,
                        evidence.issuer,
                        evidence.key_id,
                        evidence.outcome.value,
                        evidence.signature,
                        now,
                    ),
                )
                cur.execute(
                    """UPDATE ruhusa_executions SET
                         state = %s,
                         claim_id = CASE WHEN %s = 'available' THEN NULL ELSE claim_id END,
                         completed_at = CASE WHEN %s = 'completed' THEN %s ELSE completed_at END,
                         released_at = CASE WHEN %s = 'available' THEN %s ELSE released_at END,
                         recovered_at = %s,
                         recovery_outcome = %s,
                         recovery_reason = %s,
                         recovery_count = recovery_count + 1,
                         updated_at = CURRENT_TIMESTAMP
                       WHERE invocation_id = %s AND state = 'unknown'
                         AND claim_id = %s AND attempt_count = %s
                       RETURNING invocation_id""",
                    (
                        state.value,
                        state.value,
                        state.value,
                        now,
                        state.value,
                        now,
                        now,
                        evidence.outcome.value,
                        evidence.reason,
                        evidence.invocation_id,
                        evidence.claim_id,
                        evidence.attempt,
                    ),
                )
                if cur.fetchone() is None:
                    # This should be unreachable with the row lock; don't
                    # commit a spent receipt without the state transition.
                    raise RuntimeError("atomic recovery update failed")
        return True
