from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from .audit import InMemoryAuditLog
from .delegation import validate_delegation_chain
from .grants import InMemoryGrantStore
from .models import AuthorizationDecision, AuthorizationRequest, DecisionEffect
from .policy import StaticPolicyStore
from .revocation import InMemoryRevocationStore, RevocationRecord


class Ruhusa:
    """Deterministic authorization boundary for agent actions.

    Security invariants in v0.3:
    - deny by default
    - task must be active
    - delegation chain must be identity-continuous
    - delegated scope may narrow, never expand
    - grants must originate from the task initiator
    - each grant must be bound to the current task
    - if a grant store is configured, every chain grant must have been
      registered through it; unregistered grants are denied regardless
      of their contents
    - revoked authority must not authorize subsequent actions
    - action/resource/arguments must fit effective delegated scope
    - policy evaluation failures deny the action
    - revocation-check failures deny the action
    - every authorization decision is audited
    """

    def __init__(
        self,
        policy_store: StaticPolicyStore | None = None,
        audit_log: InMemoryAuditLog | None = None,
        revocation_store: InMemoryRevocationStore | None = None,
        grant_store: InMemoryGrantStore | None = None,
    ) -> None:
        self.policy_store = policy_store or StaticPolicyStore()
        self.audit_log = audit_log or InMemoryAuditLog()
        self.revocation_store = (
            revocation_store if revocation_store is not None else InMemoryRevocationStore()
        )
        self.grant_store = grant_store

    def revoke_grant(
        self,
        grant_id: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> RevocationRecord:
        """Revoke a delegation grant."""
        return self.revocation_store.revoke(
            grant_id,
            reason=reason,
            revoked_at=revoked_at,
        )

    def authorize(
        self,
        request: AuthorizationRequest,
        *,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        now = now or datetime.now(UTC)

        if request.task.is_expired(now):
            return self._record(
                request,
                AuthorizationDecision(DecisionEffect.DENY, "task expired"),
            )

        delegation = validate_delegation_chain(request, now)
        if not delegation.valid:
            return self._record(
                request,
                AuthorizationDecision(DecisionEffect.DENY, delegation.reason),
            )

        if self.grant_store is not None:
            for grant in request.delegation_chain:
                if not self.grant_store.contains(grant.grant_id):
                    return self._record(
                        request,
                        AuthorizationDecision(
                            DecisionEffect.DENY,
                            f"delegation grant {grant.grant_id} was not issued through a trusted boundary",
                        ),
                    )

        try:
            for grant in request.delegation_chain:
                if self.revocation_store.is_revoked(grant.grant_id, at=now):
                    return self._record(
                        request,
                        AuthorizationDecision(
                            DecisionEffect.DENY,
                            f"delegation grant {grant.grant_id} is revoked",
                        ),
                    )
        except Exception:
            return self._record(
                request,
                AuthorizationDecision(
                    DecisionEffect.DENY,
                    "revocation status unavailable; default deny",
                ),
            )

        scope = delegation.effective_scope
        if scope is not None:
            if not scope.allows_action(request.action):
                return self._record(
                    request,
                    AuthorizationDecision(
                        DecisionEffect.DENY,
                        "action outside delegated scope",
                    ),
                )

            if not scope.allows_resource(request.resource):
                return self._record(
                    request,
                    AuthorizationDecision(
                        DecisionEffect.DENY,
                        "resource outside delegated scope",
                    ),
                )

            if not scope.allows_arguments(request.arguments):
                return self._record(
                    request,
                    AuthorizationDecision(
                        DecisionEffect.DENY,
                        "arguments exceed delegated scope",
                    ),
                )

        try:
            rule = self.policy_store.evaluate(request)
        except Exception:
            return self._record(
                request,
                AuthorizationDecision(
                    DecisionEffect.DENY,
                    "policy evaluation failed; default deny",
                ),
            )

        if rule is None:
            return self._record(
                request,
                AuthorizationDecision(
                    DecisionEffect.DENY,
                    "no policy matched; default deny",
                ),
            )

        decision = AuthorizationDecision(
            effect=rule.effect,
            reason=rule.reason,
            policy_id=rule.policy_id,
            obligations=rule.obligations,
        )
        return self._record(request, decision)

    def _record(
        self,
        request: AuthorizationRequest,
        decision: AuthorizationDecision,
    ) -> AuthorizationDecision:
        audit_id = self.audit_log.append(request, decision)
        return replace(decision, audit_id=audit_id)
