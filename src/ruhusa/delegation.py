from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .models import AuthorizationRequest, Scope


@dataclass(frozen=True)
class DelegationValidation:
    valid: bool
    reason: str
    effective_scope: Scope | None = None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def validate_delegation_chain(
    request: AuthorizationRequest,
    now: datetime | None = None,
) -> DelegationValidation:
    now = _as_utc(now or datetime.now(timezone.utc))
    chain = request.delegation_chain

    if not chain:
        return DelegationValidation(True, "no delegation chain", None)

    # The task initiator must originate the first grant.
    if chain[0].grantor_id != request.task.initiated_by:
        return DelegationValidation(
            False,
            "delegation chain does not originate from task initiator",
        )

    for index, grant in enumerate(chain):
        issued_at = _as_utc(grant.issued_at)
        expires_at = _as_utc(grant.expires_at)

        if issued_at > now:
            return DelegationValidation(
                False,
                f"delegation grant {grant.grant_id} is not active yet",
            )

        if expires_at <= issued_at:
            return DelegationValidation(
                False,
                f"delegation grant {grant.grant_id} has an invalid validity window",
            )

        if grant.is_expired(now):
            return DelegationValidation(
                False,
                f"delegation grant {grant.grant_id} is expired",
            )

        if index > 0:
            parent = chain[index - 1]

            if grant.grantor_id != parent.grantee_id:
                return DelegationValidation(
                    False,
                    "delegation chain identity continuity failed",
                )

            if not grant.scope.is_subset_of(parent.scope):
                return DelegationValidation(
                    False,
                    "delegated authority exceeds parent scope",
                )

    leaf = chain[-1]
    if leaf.grantee_id != request.principal.principal_id:
        return DelegationValidation(
            False,
            "request principal is not the final delegatee",
        )

    return DelegationValidation(True, "delegation chain valid", leaf.scope)
