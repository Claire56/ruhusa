from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .models import AuthorizationDecision, AuthorizationRequest


SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "authorization"}


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(k): "[REDACTED]" if str(k).lower() in SENSITIVE_KEYS else _redact(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


@dataclass(frozen=True)
class AuditEvent:
    audit_id: str
    timestamp: str
    principal_id: str
    task_id: str
    action: str
    resource: str
    arguments: Mapping[str, Any]
    effect: str
    reason: str
    policy_id: str | None
    previous_hash: str
    event_hash: str


class InMemoryAuditLog:
    """Hash-chained in-memory audit log for reproducible tests and demos."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(
        self,
        request: AuthorizationRequest,
        decision: AuthorizationDecision,
    ) -> str:
        audit_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        previous_hash = self.events[-1].event_hash if self.events else "GENESIS"

        payload = {
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
        serialized = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=str
        )
        event_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        event = AuditEvent(event_hash=event_hash, **payload)
        self.events.append(event)
        return audit_id

    def verify_chain(self) -> bool:
        previous_hash = "GENESIS"
        for event in self.events:
            payload = asdict(event)
            event_hash = payload.pop("event_hash")
            if payload["previous_hash"] != previous_hash:
                return False
            serialized = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), default=str
            )
            calculated = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            if calculated != event_hash:
                return False
            previous_hash = event_hash
        return True
