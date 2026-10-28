"""Authenticated recovery evidence for quarantined execution attempts.

This module deliberately does not change the legacy trusted ExecutionStore API.
Only trusted reconciliation services should hold signing keys or store access.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Mapping, Protocol

from .execution import ExecutionRecoveryOutcome, ExecutionState
from .interfaces import ExecutionStore


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("recovery evidence timestamps must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True)
class RecoveryEvidence:
    """Signed claim from a trusted reconciliation authority about one attempt."""

    evidence_id: str
    issuer: str
    key_id: str
    invocation_id: str
    claim_id: str
    attempt: int
    outcome: ExecutionRecoveryOutcome
    reason: str
    issued_at: datetime
    expires_at: datetime
    signature: str


def _payload(evidence: RecoveryEvidence) -> bytes:
    fields = {
        "attempt": evidence.attempt,
        "claim_id": evidence.claim_id,
        "evidence_id": evidence.evidence_id,
        "expires_at": _utc(evidence.expires_at).isoformat(),
        "invocation_id": evidence.invocation_id,
        "issued_at": _utc(evidence.issued_at).isoformat(),
        "issuer": evidence.issuer,
        "key_id": evidence.key_id,
        "outcome": evidence.outcome.value,
        "reason": evidence.reason,
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_recovery_evidence(evidence: RecoveryEvidence, *, key: bytes) -> RecoveryEvidence:
    """Sign evidence in trusted reconciliation infrastructure only.

    Never expose signing keys or this operation to an LLM or MCP tool caller.
    """
    if len(key) < 32:
        raise ValueError("recovery signing key must be at least 32 bytes")
    signature = hmac.new(key, _payload(evidence), hashlib.sha256).hexdigest()
    return replace(evidence, signature=signature)


class RecoveryEvidenceVerifier:
    """Verify provenance, binding, validity period, and HMAC signature."""

    def __init__(
        self,
        trusted_keys: Mapping[tuple[str, str], bytes],
        *,
        max_lifetime: timedelta = timedelta(minutes=10),
    ) -> None:
        self._keys = dict(trusted_keys)
        self._max_lifetime = max_lifetime

    def verify(self, evidence: RecoveryEvidence, *, now: datetime) -> bool:
        try:
            now = _utc(now)
            issued = _utc(evidence.issued_at)
            expires = _utc(evidence.expires_at)
            if (
                not evidence.evidence_id
                or not evidence.issuer
                or not evidence.key_id
                or not evidence.invocation_id
                or not evidence.claim_id
                or not evidence.reason.strip()
                or evidence.attempt < 1
                or not isinstance(evidence.outcome, ExecutionRecoveryOutcome)
                or issued > now
                or expires <= now
                or expires <= issued
                or expires - issued > self._max_lifetime
            ):
                return False
            key = self._keys.get((evidence.issuer, evidence.key_id))
            if key is None or len(key) < 32:
                return False
            expected = hmac.new(key, _payload(evidence), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, evidence.signature)
        except (ValueError, TypeError, AttributeError):
            return False


class RecoveryEvidenceReplayStore(Protocol):
    """One-time-use evidence registry; production backends must be durable and shared."""

    def claim(self, evidence_id: str) -> bool: ...


class InMemoryRecoveryEvidenceReplayStore:
    """Atomic replay tracking in one process; not suitable for multi-replica use."""

    def __init__(self) -> None:
        self._used: set[str] = set()
        self._lock = Lock()

    def claim(self, evidence_id: str) -> bool:
        with self._lock:
            if evidence_id in self._used:
                return False
            self._used.add(evidence_id)
            return True


class AuthenticatedRecoveryService:
    """Fail closed until signed evidence is verified for the exact UNKNOWN attempt.

    Only provide this service to trusted reconciliation infrastructure. The legacy
    raw store recovery entrypoint must not be exposed to agents or untrusted APIs.
    """

    def __init__(
        self,
        execution_store: ExecutionStore,
        verifier: RecoveryEvidenceVerifier,
        replay_store: RecoveryEvidenceReplayStore,
    ) -> None:
        self._store = execution_store
        self._verifier = verifier
        self._replay_store = replay_store
        self._lock = Lock()

    def reconcile(self, evidence: RecoveryEvidence, *, now: datetime | None = None) -> bool:
        now = _utc(now or datetime.now(UTC))
        if not self._verifier.verify(evidence, now=now):
            return False
        with self._lock:
            record = self._store.get(evidence.invocation_id)
            if (
                record is None
                or record.state is not ExecutionState.UNKNOWN
                or record.claim_id != evidence.claim_id
                or record.attempt_count != evidence.attempt
            ):
                return False
            # Fail closed: replay claim precedes transition. If a backend fails,
            # the evidence is spent and the operation remains quarantined.
            if not self._replay_store.claim(evidence.evidence_id):
                return False
            return self._store.reconcile_unknown(
                evidence.invocation_id,
                outcome=evidence.outcome,
                reason=evidence.reason,
                now=now,
            )
