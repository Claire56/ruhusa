from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from .audit import InMemoryAuditLog
from .delegation import validate_delegation_chain
from .models import AuthorizationDecision, AuthorizationRequest, DecisionEffect
from .policy import StaticPolicyStore


class Ruhusa:
    """Deterministic authorization boundary for agent actions.

    Security invariants in v0.1:
    - deny by default
    - task must be active
    - delegation chain must be identity-continuous
    - delegated scope may narrow, never expand
    - action/resource/arguments must fit effective delegated scope
    - policy evaluation failures deny the action
    - every decision is audited
    """

    def __init__(
        self,
        policy_store: StaticPolicyStore | None = None,
        audit_log: InMemoryAuditLog | None = None,
    ) -> None:
        self.policy_store = policy_store or StaticPolicyStore()
        self.audit_log = audit_log or InMemoryAuditLog()

    def authorize(
        self,
        request: AuthorizationRequest,
        *,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        now = now or datetime.now(timezone.utc)

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
            # Policy code must never fail open. Avoid returning exception
            # details because policy backends may contain sensitive context.
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
