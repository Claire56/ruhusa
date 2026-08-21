from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from .audit import InMemoryAuditLog
from .delegation import validate_delegation_chain
from .grants import InMemoryGrantStore
from .invocations import InMemoryInvocationStore, compute_arguments_digest
from .models import AuthorizationDecision, AuthorizationRequest, DecisionEffect
from .policy import StaticPolicyStore
from .revocation import InMemoryRevocationStore, RevocationRecord
from .tools import InMemoryToolRegistry


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class Ruhusa:
    """Deterministic authorization boundary for agent actions.

    Security invariants:
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
    - INV-17: the authenticated immediate invoker of every delegated execution
      must match the grantor of the leaf delegation grant; strong mode
      (invocation store) uses a trusted orchestrator-registered record that also
      binds the operation (action, resource, arguments digest), tool identity,
      and expiry; weak mode (backward-compatible) uses the self-asserted
      invoking_principal_id field; omission is a hard DENY in both modes
    - INV-18 (weak mode only): when a tool registry is configured and no
      invocation store is present, tool_id and implementation_id from the
      request must be present, registered, and authorized; in strong mode
      tool identity is verified from the invocation record instead
    - policy evaluation failures deny the action
    - revocation-check failures deny the action
    - tool-registry failures deny the action
    - every authorization decision is audited
    """

    def __init__(
        self,
        policy_store: StaticPolicyStore | None = None,
        audit_log: InMemoryAuditLog | None = None,
        revocation_store: InMemoryRevocationStore | None = None,
        grant_store: InMemoryGrantStore | None = None,
        tool_registry: InMemoryToolRegistry | None = None,
        invocation_store: InMemoryInvocationStore | None = None,
    ) -> None:
        self.policy_store = policy_store or StaticPolicyStore()
        self.audit_log = audit_log or InMemoryAuditLog()
        self.revocation_store = (
            revocation_store if revocation_store is not None else InMemoryRevocationStore()
        )
        self.grant_store = grant_store
        self.tool_registry = tool_registry
        self.invocation_store = invocation_store

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

        # INV-17: Invocation provenance — required for all delegated requests.
        # Two modes:
        #   Strong (store configured): the orchestrator registered an InvocationRecord
        #     keyed by invocation_id; Ruhusa looks it up and verifies the authenticated
        #     invoker against the leaf grant grantor.  The executing agent cannot forge
        #     this — it does not hold write access to the store.
        #   Weak (no store): backward-compatible; validates the self-asserted
        #     invoking_principal_id field (can be forged by a compromised agent).
        if request.delegation_chain:
            if self.invocation_store is not None:
                try:
                    invocation_id = request.invocation_id
                    if invocation_id is None:
                        return self._record(
                            request,
                            AuthorizationDecision(
                                DecisionEffect.DENY,
                                "invocation id is required when an invocation store is configured",
                            ),
                        )
                    record = self.invocation_store.get(invocation_id)
                    if record is None:
                        return self._record(
                            request,
                            AuthorizationDecision(
                                DecisionEffect.DENY,
                                f"invocation {invocation_id!r} not found in trusted store;"
                                " default deny",
                            ),
                        )
                    leaf = request.delegation_chain[-1]
                    if record.invoking_principal_id != leaf.grantor_id:
                        return self._record(
                            request,
                            AuthorizationDecision(
                                DecisionEffect.DENY,
                                f"authenticated invoker {record.invoking_principal_id!r}"
                                f" does not match leaf grant grantor {leaf.grantor_id!r}",
                            ),
                        )
                    if record.executing_principal_id != request.principal.principal_id:
                        return self._record(
                            request,
                            AuthorizationDecision(
                                DecisionEffect.DENY,
                                f"invocation record executor {record.executing_principal_id!r}"
                                f" does not match request principal"
                                f" {request.principal.principal_id!r}",
                            ),
                        )
                    if record.task_id != request.task.task_id:
                        return self._record(
                            request,
                            AuthorizationDecision(
                                DecisionEffect.DENY,
                                "invocation record is bound to a different task",
                            ),
                        )

                    # Operation binding: the record must match the exact action,
                    # resource, and arguments of the live request.  This prevents
                    # an attacker from reusing a legitimate invocation_id for a
                    # different operation (replay / operation-substitution attack).
                    if record.action != request.action:
                        return self._record(
                            request,
                            AuthorizationDecision(
                                DecisionEffect.DENY,
                                f"invocation record action {record.action!r} does not"
                                f" match request action {request.action!r}",
                            ),
                        )

                    if record.resource != request.resource:
                        return self._record(
                            request,
                            AuthorizationDecision(
                                DecisionEffect.DENY,
                                f"invocation record resource {record.resource!r} does not"
                                f" match request resource {request.resource!r}",
                            ),
                        )

                    req_digest = compute_arguments_digest(request.arguments)
                    if req_digest != record.arguments_digest:
                        return self._record(
                            request,
                            AuthorizationDecision(
                                DecisionEffect.DENY,
                                "invocation record arguments digest does not match"
                                " request arguments",
                            ),
                        )

                    # Temporal validity: the invocation record has its own expiry
                    # independent of the task, so stale records are rejected even
                    # when the task is still active.
                    if _as_utc(record.expires_at) <= now:
                        return self._record(
                            request,
                            AuthorizationDecision(
                                DecisionEffect.DENY,
                                "invocation record has expired",
                            ),
                        )

                    # Tool identity (strong mode): use the orchestrator-observed tool
                    # fields from the record.  The self-asserted request.tool_id /
                    # request.implementation_id are ignored entirely in strong mode.
                    if self.tool_registry is not None and record.tool_id is not None:
                        try:
                            if not self.tool_registry.is_trusted(
                                record.tool_id, record.implementation_id
                            ):
                                return self._record(
                                    request,
                                    AuthorizationDecision(
                                        DecisionEffect.DENY,
                                        f"tool {record.tool_id!r} implementation"
                                        f" {record.implementation_id!r} from invocation"
                                        " record is not in the trusted registry",
                                    ),
                                )
                            if not self.tool_registry.allows_action(
                                record.tool_id, record.implementation_id, request.action
                            ):
                                return self._record(
                                    request,
                                    AuthorizationDecision(
                                        DecisionEffect.DENY,
                                        f"tool {record.tool_id!r} from invocation record"
                                        f" is not authorized to perform action"
                                        f" {request.action!r}",
                                    ),
                                )
                        except Exception:
                            return self._record(
                                request,
                                AuthorizationDecision(
                                    DecisionEffect.DENY,
                                    "tool registry unavailable; default deny",
                                ),
                            )

                except Exception:
                    return self._record(
                        request,
                        AuthorizationDecision(
                            DecisionEffect.DENY,
                            "invocation store unavailable; default deny",
                        ),
                    )
            else:
                # Weak mode: validate the self-asserted invoking_principal_id field.
                # Note: this field is supplied by the executing agent and can be forged.
                # Configure an InMemoryInvocationStore for strong provenance guarantees.
                if request.invoking_principal_id is None:
                    return self._record(
                        request,
                        AuthorizationDecision(
                            DecisionEffect.DENY,
                            "invoking principal is required for delegated authorization",
                        ),
                    )
                leaf = request.delegation_chain[-1]
                if request.invoking_principal_id != leaf.grantor_id:
                    return self._record(
                        request,
                        AuthorizationDecision(
                            DecisionEffect.DENY,
                            f"invoking principal {request.invoking_principal_id!r} is not"
                            f" authorised by the delegation chain"
                            f" (leaf grant grantor is {leaf.grantor_id!r})",
                        ),
                    )

        # INV-18: Tool identity (weak mode) — when a registry is configured and
        # *no* invocation store is present, the request must supply both tool_id
        # and implementation_id, the pair must be registered, and the registration
        # must authorize the requested action.  Omission is a hard DENY.
        #
        # In strong mode (invocation store configured), tool identity is already
        # verified from the invocation record above; this block is skipped so that
        # the self-asserted request fields cannot be used to override the record.
        if self.tool_registry is not None and self.invocation_store is None:
            try:
                tool_id = request.tool_id
                implementation_id = request.implementation_id

                if tool_id is None or implementation_id is None:
                    return self._record(
                        request,
                        AuthorizationDecision(
                            DecisionEffect.DENY,
                            "tool identity is required when a tool registry is configured",
                        ),
                    )

                if not self.tool_registry.is_trusted(tool_id, implementation_id):
                    return self._record(
                        request,
                        AuthorizationDecision(
                            DecisionEffect.DENY,
                            f"tool {tool_id!r} implementation {implementation_id!r}"
                            " is not in the trusted registry",
                        ),
                    )

                if not self.tool_registry.allows_action(tool_id, implementation_id, request.action):
                    return self._record(
                        request,
                        AuthorizationDecision(
                            DecisionEffect.DENY,
                            f"tool {tool_id!r} is not authorized to perform"
                            f" action {request.action!r}",
                        ),
                    )
            except Exception:
                return self._record(
                    request,
                    AuthorizationDecision(
                        DecisionEffect.DENY,
                        "tool registry unavailable; default deny",
                    ),
                )

        if self.grant_store is not None:
            try:
                for grant in request.delegation_chain:
                    if not self.grant_store.is_registered(grant):
                        stored = self.grant_store.get(grant.grant_id)
                        if stored is None:
                            reason = (
                                f"delegation grant {grant.grant_id} was not issued"
                                " through a trusted boundary"
                            )
                        else:
                            reason = (
                                f"delegation grant {grant.grant_id} contents do not"
                                " match the issued grant"
                            )
                        return self._record(
                            request,
                            AuthorizationDecision(DecisionEffect.DENY, reason),
                        )
            except Exception:
                return self._record(
                    request,
                    AuthorizationDecision(
                        DecisionEffect.DENY,
                        "grant issuance status unavailable; default deny",
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
