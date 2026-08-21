"""
tests/test_tool_identity_attacks.py

v0.5 experiments: tool identity and confused-deputy gaps and controls.

Each experiment documents an attack vector and its outcome.

Tests marked GAP document where no control exists (without a tool registry).
Tests marked BLOCKS confirm that the named control prevents the attack.

Seventeen experiments:

  Exp 1 — Authorized action routed through substituted tool
            without registry: GAP: ALLOW
            with registry:    BLOCKS (v0.5-B): DENY
  Exp 2 — Same logical tool name, different implementation
            without registry: GAP: ALLOW
            with registry:    BLOCKS (v0.5-B): DENY
  Exp 3 — Confused-deputy: low-privilege induces privileged agent   BLOCKS (v0.5-A): DENY
  Exp 4 — Completely different action attempted                     BLOCKS: DENY
  Exp 5 — Different resource attempted                              BLOCKS: DENY
  Exp 6 — Missing invoking principal on delegated request           BLOCKS (v0.5-A): DENY
  Exp 7 — Substituted tool blocked by registry                      BLOCKS (v0.5-B): DENY
  Exp 8 — Implementation substitution blocked by registry           BLOCKS (v0.5-B): DENY
  Exp 9 — Forged invoking_principal_id bypasses weak provenance     GAP (weak mode): ALLOW
  Exp 10 — Forged invoker blocked by invocation store               BLOCKS (v0.5-A+): DENY
  Exp 11 — Forged tool identity bypasses weak registry check        GAP (weak mode): ALLOW
  Exp 12 — Forged tool identity blocked by invocation store         BLOCKS (v0.5-A+): DENY
  Exp 13 — Operation substitution blocked by arguments digest       BLOCKS (v0.5-A+): DENY
  Exp 14 — Stale invocation record blocked by expiry                BLOCKS (v0.5-A+): DENY
  Exp 15 — Non-delegated request bypasses strong-mode tool check    BLOCKS (v0.5-C): DENY
  Exp 16 — Exact same-operation invocation replay                   GAP: ALLOW (no consume)
  Exp 17 — Invocation record with tool_id=None skips tool check     BLOCKS (v0.5-C): DENY
"""

from datetime import UTC, datetime, timedelta

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    DelegationGrant,
    InMemoryInvocationStore,
    InMemoryToolRegistry,
    InvocationRecord,
    PolicyRule,
    Principal,
    Ruhusa,
    Scope,
    StaticPolicyStore,
    TaskContext,
    ToolRegistration,
    compute_arguments_digest,
)

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)

REFUND_SCOPE = Scope(
    actions=frozenset({"issue_refund"}),
    resource_prefixes=("customer:123",),
    max_numeric_arguments={"amount": 500},
)


def make_task(task_id: str, initiated_by: str = "user-1") -> TaskContext:
    return TaskContext(
        task_id=task_id,
        initiated_by=initiated_by,
        purpose="billing support",
        expires_at=NOW + timedelta(hours=1),
    )


def make_grant(
    grant_id: str,
    grantor_id: str,
    grantee_id: str,
    task_id: str,
    scope: Scope = REFUND_SCOPE,
) -> DelegationGrant:
    return DelegationGrant(
        grant_id=grant_id,
        grantor_id=grantor_id,
        grantee_id=grantee_id,
        task_id=task_id,
        scope=scope,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
    )


def make_request(
    principal_id: str,
    action: str,
    resource: str,
    arguments: dict,
    task: TaskContext,
    chain: tuple[DelegationGrant, ...] = (),
) -> AuthorizationRequest:
    return AuthorizationRequest(
        principal=Principal(principal_id),
        action=action,
        resource=resource,
        arguments=arguments,
        task=task,
        delegation_chain=chain,
    )


def policy_store() -> StaticPolicyStore:
    return StaticPolicyStore(
        [
            PolicyRule(
                policy_id="allow-small-refund",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"issue_refund"}),
                principal_ids=frozenset({"billing-agent"}),
                resource_prefixes=("customer:123",),
                condition=lambda req: req.arguments["amount"] <= 500,
                reason="small refund allowed",
            ),
        ]
    )


# ---------------------------------------------------------------------------
# Experiment 1: Authorized action routed through a substituted tool
#
# Scenario: billing-agent is authorized to call issue_refund. The original
# authorization assumed a specific trusted tool implementation. An attacker
# substitutes a different implementation — one that exfiltrates data, logs
# credentials, or performs a broader side effect — but uses the same action
# string and arguments.
#
# Ruhusa authorizes by principal, action string, resource, and scope. It has
# no mechanism to verify which implementation will actually execute the action.
# Both the legitimate and substituted implementations receive the same ALLOW.
#
# GAP: ALLOW — tool implementation is not bound to the authorization decision.
#
# v0.5 goal: introduce tool identity so that authorization can be tied to a
# specific registered tool, not just to an action string.
# ---------------------------------------------------------------------------


def test_authorized_action_via_substituted_tool_is_not_detected() -> None:
    """
    GAP: Ruhusa cannot distinguish a request routed through the legitimate
    tool implementation from one routed through a substituted implementation.
    Both receive ALLOW because authorization is based on action string alone.
    """
    task = make_task("task-toolsub-001")

    # Legitimate request: will be routed to the trusted tool implementation.
    legitimate_req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
    )

    # Substituted request: same action, resource, and arguments, but in
    # a real system this would be routed to a different (malicious) tool
    # implementation. Ruhusa has no tool_id field and cannot distinguish them.
    substituted_req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
    )

    gate = Ruhusa(policy_store=policy_store())

    legitimate_decision = gate.authorize(legitimate_req, now=NOW)
    substituted_decision = gate.authorize(substituted_req, now=NOW)

    # GAP: both receive ALLOW — tool implementation is invisible to Ruhusa.
    assert legitimate_decision.effect == DecisionEffect.ALLOW
    assert substituted_decision.effect == DecisionEffect.ALLOW
    # v0.5: with tool identity bound, substituted_decision should be DENY
    # when the tool_id does not match the registered trusted implementation.


# ---------------------------------------------------------------------------
# Experiment 2: Same logical tool name, different implementation
#
# Scenario: A tool registry exposes "billing_refund_tool". The policy was
# authorized against the registered, trusted version of this tool. An attacker
# registers or injects an alternative implementation under the same logical
# name. Both claim to handle issue_refund; Ruhusa sees the same action string
# and returns ALLOW for both.
#
# The gap here is subtler than Experiment 1. Even if Ruhusa eventually checks
# a tool_id string, a name-only check is insufficient — tool identity must be
# tied to a specific cryptographic or canonical registration, not just a name.
#
# GAP: ALLOW — logical tool name alone does not establish identity.
# ---------------------------------------------------------------------------


def test_same_tool_name_different_implementation_is_not_detected() -> None:
    """
    GAP: Ruhusa evaluates authorization against action strings, not tool
    registrations. Two requests that differ only in which implementation
    backs a given tool name are indistinguishable. A hint passed through
    arguments (simulating a tool_id field) is not evaluated by scope checks.
    """
    task = make_task("task-toolname-001")

    # Registered, trusted tool implementation.
    # In a future model: tool_id="billing_refund_tool@v1.2.0-sha256:abc..."
    registered_req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 300, "tool_hint": "billing_refund_tool@trusted"},
        task=task,
    )

    # Substitute: same logical name, different binary / unverified source.
    # The tool_hint field is not evaluated by Ruhusa's scope or policy logic.
    substitute_req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 300, "tool_hint": "billing_refund_tool@attacker"},
        task=task,
    )

    gate = Ruhusa(policy_store=policy_store())

    registered_decision = gate.authorize(registered_req, now=NOW)
    substitute_decision = gate.authorize(substitute_req, now=NOW)

    # GAP: both receive ALLOW — tool_hint is not part of scope evaluation.
    assert registered_decision.effect == DecisionEffect.ALLOW
    assert substitute_decision.effect == DecisionEffect.ALLOW
    # v0.5: with a ToolRegistry, substitute_decision should be DENY when
    # the tool is not in the trusted registry for this action.


# ---------------------------------------------------------------------------
# Experiment 3: Confused-deputy — low-privilege agent induces privileged agent
#
# Scenario: low-privilege-agent wants to issue a refund but has no policy
# that allows it. A direct request is denied. If low-privilege-agent induces
# billing-agent to make the same request, the invoking_principal_id field
# (v0.5-A) exposes the inducer's identity at authorization time.
#
# INV-17: the invoking principal must equal the grantor of the leaf delegation
# grant. If billing-agent was delegated authority by user-1, only user-1
# is an authorised invoker. low-privilege-agent is not in the chain, so the
# request is denied.
#
# BLOCKS (v0.5-A): DENY — invoking principal does not match leaf grantor.
# ---------------------------------------------------------------------------


def test_confused_deputy_low_privilege_induces_privileged_agent() -> None:
    """
    BLOCKS (v0.5-A): Ruhusa now enforces INV-17 — invocation provenance.
    The invoking_principal_id must equal the grantor of the leaf delegation
    grant.

    Legitimate path (ALLOW):

      user-1 -- delegates --> billing-agent
      billing-agent acts; invoking_principal_id = "user-1"
      leaf.grantor_id = "user-1"  →  match  →  ALLOW

    Confused-deputy attack (DENY):

      user-1 -- delegates --> billing-agent
      low-privilege-agent induces billing-agent to act
      billing-agent acts; invoking_principal_id = "low-privilege-agent"
      leaf.grantor_id = "user-1"  →  mismatch  →  DENY
    """
    task = make_task("task-deputy-001")

    grant = make_grant(
        grant_id="grant-deputy",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id="task-deputy-001",
    )

    gate = Ruhusa(policy_store=policy_store())

    # Step 1: low-privilege-agent direct request — still denied.
    direct_req = make_request(
        principal_id="low-privilege-agent",
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
    )
    assert gate.authorize(direct_req, now=NOW).effect == DecisionEffect.DENY

    # Step 2: billing-agent acts but invoker is low-privilege-agent.
    # INV-17: "low-privilege-agent" != leaf.grantor_id ("user-1")  →  DENY.
    deputy_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invoking_principal_id="low-privilege-agent",
    )
    deputy_decision = gate.authorize(deputy_req, now=NOW)
    assert deputy_decision.effect == DecisionEffect.DENY
    assert "invoking principal" in deputy_decision.reason

    # Step 3: legitimate invocation — user-1 is both the delegator and invoker.
    # INV-17: "user-1" == leaf.grantor_id ("user-1")  →  ALLOW.
    legitimate_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invoking_principal_id="user-1",
    )
    assert gate.authorize(legitimate_req, now=NOW).effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 4: Completely different action attempted
#
# Scenario: An attacker attempts to use billing-agent's authority to call an
# action outside the authorized set. The action "delete_account" is not in
# billing-agent's policy.
#
# BLOCKS: existing controls catch this — action is outside policy scope.
# ---------------------------------------------------------------------------


def test_completely_different_action_is_denied() -> None:
    """
    BLOCKS: Ruhusa denies an action that is not in the authorized set for
    this principal, regardless of the resource or arguments. Existing policy
    and scope controls are sufficient here.
    """
    task = make_task("task-wrongaction-001")

    req = make_request(
        principal_id="billing-agent",
        action="delete_account",  # not in policy or delegated scope
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
    )

    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(req, now=NOW)

    assert decision.effect == DecisionEffect.DENY


# ---------------------------------------------------------------------------
# Experiment 5: Different resource attempted
#
# Scenario: billing-agent attempts to apply an authorized action to a resource
# it was not authorized for. The policy is scoped to "customer:123"; a request
# against "customer:456" should be denied.
#
# BLOCKS: existing resource-prefix scope enforcement catches this.
# ---------------------------------------------------------------------------


def test_different_resource_is_denied() -> None:
    """
    BLOCKS: Ruhusa denies an otherwise authorized action applied to a resource
    outside the authorized prefix. Resource scope enforcement is sufficient here.
    """
    task = make_task("task-wrongresource-001")

    req = make_request(
        principal_id="billing-agent",
        action="issue_refund",
        resource="customer:456:billing",  # outside authorized prefix
        arguments={"amount": 250},
        task=task,
    )

    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(req, now=NOW)

    assert decision.effect == DecisionEffect.DENY


# ---------------------------------------------------------------------------
# Experiment 6: Missing invoking principal on a delegated request
#
# Scenario: A delegated request arrives with invoking_principal_id=None.
# Before v0.5-A this was treated as a skip (the INV-17 check was opt-in).
# An attacker could omit the field entirely to bypass the provenance check.
#
# v0.5-A tightens the control: when a delegation chain is present, omitting
# invoking_principal_id is treated as a provenance failure and results in DENY.
# The field cannot be left absent to opt out of the check.
#
# BLOCKS (v0.5-A): DENY — missing invoking principal is fail-closed.
# ---------------------------------------------------------------------------


def test_missing_invoking_principal_is_denied_for_delegated_action() -> None:
    """
    BLOCKS (v0.5-A): Omitting invoking_principal_id on a delegated request is
    treated as a provenance failure, not a skip.  INV-17 is now fail-closed:
    an attacker cannot bypass it by leaving the field None.

    Contrast with the legitimate path (invoking_principal_id supplied and
    matching the leaf grantor), which must remain ALLOW.
    """
    task = make_task("task-noinvoker-001")
    noinvoker_grant = make_grant(
        grant_id="grant-noinvoker",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id="task-noinvoker-001",
    )

    # Delegated request with invoking_principal_id explicitly absent.
    req_no_invoker = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(noinvoker_grant,),
        invoking_principal_id=None,
    )

    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(req_no_invoker, now=NOW)

    assert decision.effect == DecisionEffect.DENY
    assert "invoking principal" in decision.reason

    # Sanity check: the same request with the correct invoking principal is ALLOW.
    req_with_invoker = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(noinvoker_grant,),
        invoking_principal_id="user-1",
    )
    assert gate.authorize(req_with_invoker, now=NOW).effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 7: Authorized action via substituted tool — blocked by registry
#
# This is Experiment 1 re-run with an InMemoryToolRegistry configured.
# The legitimate tool is registered; the substitute is not. Ruhusa now enforces
# INV-18: the (tool_id, implementation_id) pair must be in the trusted registry.
#
# BLOCKS (v0.5-B): DENY — substitute implementation is not registered.
# ---------------------------------------------------------------------------

TRUSTED_IMPL_ID = "billing_refund_tool@v1.2.0-sha256:abc123"
SUBSTITUTE_IMPL_ID = "billing_refund_tool@attacker-sha256:evil"


def _refund_registry() -> InMemoryToolRegistry:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolRegistration(
            tool_id="billing_refund_tool",
            implementation_id=TRUSTED_IMPL_ID,
            allowed_actions=frozenset({"issue_refund"}),
        )
    )
    return registry


def test_substituted_tool_is_blocked_by_registry() -> None:
    """
    BLOCKS (v0.5-B): With a ToolRegistry configured, a request routed through
    an unregistered tool implementation is denied even though the action, resource,
    and arguments are identical to a legitimate request.

    The (tool_id, implementation_id) pair is the unit of trust.  The substitute
    shares the tool_id but presents a different implementation_id that was never
    registered through the trusted boundary — Ruhusa enforces INV-18 and returns DENY.
    """
    task = make_task("task-toolsub-v5b-001")
    gate = Ruhusa(policy_store=policy_store(), tool_registry=_refund_registry())

    # Legitimate: registered (tool_id, implementation_id)
    legitimate_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        tool_id="billing_refund_tool",
        implementation_id=TRUSTED_IMPL_ID,
    )

    # Substitute: same tool_id, unregistered implementation_id
    substituted_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        tool_id="billing_refund_tool",
        implementation_id=SUBSTITUTE_IMPL_ID,
    )

    legitimate_decision = gate.authorize(legitimate_req, now=NOW)
    substituted_decision = gate.authorize(substituted_req, now=NOW)

    # BLOCKS (v0.5-B): legitimate is ALLOW; substitute is DENY.
    assert legitimate_decision.effect == DecisionEffect.ALLOW
    assert substituted_decision.effect == DecisionEffect.DENY
    assert "not in the trusted registry" in substituted_decision.reason


# ---------------------------------------------------------------------------
# Experiment 8: Same logical tool name, different implementation — blocked by registry
#
# This is Experiment 2 re-run with an InMemoryToolRegistry configured.
# The registered, trusted implementation is accepted; the attacker's
# implementation, which shares the same logical name, is denied.
#
# A name-only check would be insufficient: two implementations can share a
# tool_id.  The registry enforces exact (tool_id, implementation_id) matching,
# which closes the name-collision gap identified in Experiment 2.
#
# BLOCKS (v0.5-B): DENY — attacker's implementation not in registry.
# ---------------------------------------------------------------------------


def test_same_tool_name_different_implementation_blocked_by_registry() -> None:
    """
    BLOCKS (v0.5-B): With a ToolRegistry configured, two requests that share
    a logical tool name but differ in implementation_id are distinguishable.
    Only the registered (trusted) implementation is authorized; the unregistered
    (attacker) implementation is denied.

    This closes the gap documented in Experiment 2: a name-only tool_id check
    would ALLOW both, but the pair (tool_id, implementation_id) is unambiguous.
    """
    task = make_task("task-toolname-v5b-001")
    gate = Ruhusa(policy_store=policy_store(), tool_registry=_refund_registry())

    # Registered, trusted implementation.
    registered_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 300},
        task=task,
        tool_id="billing_refund_tool",
        implementation_id=TRUSTED_IMPL_ID,
    )

    # Attacker's implementation: same logical name, different (unregistered) impl.
    attacker_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 300},
        task=task,
        tool_id="billing_refund_tool",
        implementation_id=SUBSTITUTE_IMPL_ID,
    )

    registered_decision = gate.authorize(registered_req, now=NOW)
    attacker_decision = gate.authorize(attacker_req, now=NOW)

    # BLOCKS (v0.5-B): registered is ALLOW; attacker's implementation is DENY.
    assert registered_decision.effect == DecisionEffect.ALLOW
    assert attacker_decision.effect == DecisionEffect.DENY
    assert "not in the trusted registry" in attacker_decision.reason


# ---------------------------------------------------------------------------
# Experiment 9: Forged invoking_principal_id bypasses weak provenance check
#
# Scenario: A compromised or malicious agent constructs an AuthorizationRequest
# and sets invoking_principal_id to "user-1" — the legitimate leaf grant
# grantor — even though the actual caller is a low-privilege agent. In weak
# mode (no InMemoryInvocationStore configured), Ruhusa trusts this self-asserted
# field and returns ALLOW.
#
# This documents the gap that v0.5-A+ closes: invoking_principal_id is
# self-asserted, not authenticated.  An attacker who controls the executing
# agent controls the request object and can forge this field freely.
#
# GAP (weak mode): ALLOW — self-asserted invoker is not authenticated.
# ---------------------------------------------------------------------------


def test_forged_invoking_principal_bypasses_current_provenance_check() -> None:
    """
    GAP: In weak mode (no invocation store), invoking_principal_id is
    self-asserted.  An attacker who controls the executing agent can forge
    it to match the leaf grant grantor, bypassing INV-17 and receiving ALLOW.

    This test documents the gap that InMemoryInvocationStore (v0.5-A+) closes.
    Compare with Experiment 10, which confirms the same forgery attempt is DENY
    when an invocation store is configured.
    """
    task = make_task("task-forged-invoker-001")
    grant = make_grant(
        grant_id="grant-forged-invoker",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
    )

    # The attacker forges invoking_principal_id="user-1" — the leaf grantor —
    # even though the actual caller is a low-privilege agent.
    forged_request = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invoking_principal_id="user-1",  # forged — actual caller is low-privilege-agent
    )

    gate = Ruhusa(policy_store=policy_store())
    decision = gate.authorize(forged_request, now=NOW)

    # GAP: weak mode trusts the asserted invoker; forgery succeeds.
    assert decision.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 10: Forged invoker blocked by InMemoryInvocationStore
#
# Scenario: Same attack as Experiment 9, but now Ruhusa is configured with an
# InMemoryInvocationStore (strong provenance mode, v0.5-A+).
#
# The orchestrator registers an InvocationRecord keyed by invocation_id.
# The record contains the *authenticated* invoking_principal_id observed by
# the orchestrator from its own runtime context — not from any field the
# executing agent supplied.  The executing agent cannot forge this record
# because it does not hold write access to the store.
#
# The attacker's request either omits invocation_id (→ DENY: required field
# missing) or supplies an invocation_id that maps to a record where
# invoking_principal_id="low-privilege-agent" (→ DENY: does not match leaf
# grantor "user-1").  Forging invoking_principal_id on the request itself
# has no effect — that field is ignored in strong mode.
#
# BLOCKS (v0.5-A+): DENY — authenticated invoker does not match leaf grantor.
# ---------------------------------------------------------------------------


def test_forged_invoking_principal_blocked_by_invocation_store() -> None:
    """
    BLOCKS (v0.5-A+): With an InMemoryInvocationStore configured, the
    authenticated invoker recorded by the orchestrator — not the self-asserted
    field on the request — is used for INV-17.

    Attack paths:
      (a) Attacker omits invocation_id:
            → DENY "invocation id is required"
      (b) Attacker supplies an invocation_id whose record shows the real
          (low-privilege) invoker:
            → DENY "authenticated invoker … does not match leaf grant grantor"

    Legitimate path: orchestrator registers correct InvocationRecord → ALLOW.
    """
    task = make_task("task-forged-invoker-store-001")
    grant = make_grant(
        grant_id="grant-forged-invoker-store",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
    )

    # Attack path (a): attacker forges invoking_principal_id but omits invocation_id.
    store = InMemoryInvocationStore()
    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)

    forged_no_id = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invoking_principal_id="user-1",  # forged but ignored in strong mode
        invocation_id=None,  # missing → DENY
    )
    decision_a = gate.authorize(forged_no_id, now=NOW)
    assert decision_a.effect == DecisionEffect.DENY
    assert "invocation id is required" in decision_a.reason

    # Attack path (b): attacker supplies an invocation_id whose record shows
    # the real (low-privilege) invoker.  The orchestrator cannot be tricked
    # into registering "user-1" here because it observes the actual caller.
    store.register(
        InvocationRecord(
            invocation_id="inv-forged-001",
            invoking_principal_id="low-privilege-agent",  # actual caller
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id=None,
            implementation_id=None,
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )

    forged_with_id = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invoking_principal_id="user-1",  # forged — ignored in strong mode
        invocation_id="inv-forged-001",
    )
    decision_b = gate.authorize(forged_with_id, now=NOW)
    assert decision_b.effect == DecisionEffect.DENY
    assert "does not match leaf grant grantor" in decision_b.reason

    # Legitimate path: orchestrator registers the real (user-1) invoker.
    store.register(
        InvocationRecord(
            invocation_id="inv-legit-001",
            invoking_principal_id="user-1",  # authenticated by orchestrator
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id=None,
            implementation_id=None,
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )

    legit_request = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invocation_id="inv-legit-001",
    )
    assert gate.authorize(legit_request, now=NOW).effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 11: Forged tool identity bypasses weak registry check
#
# Scenario: A compromised executing agent claims trusted tool identity fields
# (tool_id and implementation_id) in its AuthorizationRequest even though it
# is actually running a substitute (malicious) implementation. In weak mode
# (tool registry configured, no InMemoryInvocationStore), Ruhusa trusts these
# self-asserted fields.
#
# The same gap exists for invoking_principal_id (Experiment 9). In weak mode
# all identity claims in the request object are self-asserted: an attacker who
# controls the executing agent controls the request and can forge any field.
#
# GAP (weak mode): ALLOW — implementation_id is not authenticated.
# ---------------------------------------------------------------------------


def test_forged_tool_identity_bypasses_weak_registry_check() -> None:
    """
    GAP (weak mode): With a tool registry configured but no invocation store,
    implementation_id is self-asserted.  A compromised agent can claim the
    trusted implementation_id even while running a substitute implementation.
    Ruhusa trusts the asserted field and returns ALLOW.

    The attacker also forges invoking_principal_id (same gap as Exp 9),
    illustrating that all identity fields on AuthorizationRequest are
    self-asserted and forgeable in weak mode.

    Compare with Experiment 12, which confirms both forgeries are DENY when
    an invocation store is configured.
    """
    task = make_task("task-forged-tool-001")
    grant = make_grant(
        grant_id="grant-forged-tool",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
    )

    gate = Ruhusa(policy_store=policy_store(), tool_registry=_refund_registry())

    # Attacker forges invoking_principal_id (the leaf grantor) AND
    # implementation_id (the trusted implementation). Neither field is
    # authenticated in weak mode; both are supplied by the executing agent.
    forged_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invoking_principal_id="user-1",  # forged — actual caller is low-privilege-agent
        tool_id="billing_refund_tool",
        implementation_id=TRUSTED_IMPL_ID,  # forged — actual impl is SUBSTITUTE_IMPL_ID
    )

    decision = gate.authorize(forged_req, now=NOW)

    # GAP: weak mode trusts both asserted fields; forgery succeeds.
    assert decision.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 12: Forged tool identity blocked by InMemoryInvocationStore
#
# Scenario: Same attack as Experiment 11, but Ruhusa is now configured with
# an InMemoryInvocationStore (strong mode, v0.5-A+).
#
# The orchestrator registers an InvocationRecord keyed by invocation_id. It
# records the *actual* tool implementation it resolved at invocation time — not
# any field supplied by the executing agent. Ruhusa uses the record's tool
# fields for the INV-18 registry check; the request's tool_id /
# implementation_id fields are ignored entirely in strong mode.
#
# Attack: the attacker supplies an invocation_id whose record contains the
# attacker's (unregistered) implementation. Claiming TRUSTED_IMPL_ID in the
# request has no effect because that field is never consulted.
#
# BLOCKS (v0.5-A+): DENY — record's implementation is not in the trusted
# registry.
# ---------------------------------------------------------------------------


def test_forged_tool_identity_blocked_by_invocation_store() -> None:
    """
    BLOCKS (v0.5-A+): With an InMemoryInvocationStore configured (strong mode),
    tool identity for INV-18 comes from the orchestrator-registered record, not
    from the self-asserted request fields.

    Attack path:
      - Orchestrator registers record with the actual (attacker's) implementation_id
      - Agent claims trusted implementation_id in the request (ignored)
      - Ruhusa uses the record's implementation_id → not registered → DENY

    Legitimate path:
      - Orchestrator registers record with the actual trusted implementation_id
      - Agent presents invocation_id → Ruhusa reads record → registered → ALLOW
    """
    task = make_task("task-forged-tool-store-001")
    grant = make_grant(
        grant_id="grant-forged-tool-store",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
    )

    store = InMemoryInvocationStore()
    gate = Ruhusa(
        policy_store=policy_store(),
        tool_registry=_refund_registry(),
        invocation_store=store,
    )

    # Orchestrator records what it actually observed: the attacker's substitute.
    store.register(
        InvocationRecord(
            invocation_id="inv-forged-tool-001",
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id="billing_refund_tool",
            implementation_id=SUBSTITUTE_IMPL_ID,  # attacker's actual tool
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )

    # Agent forges implementation_id in the request — strong mode ignores it.
    attack_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invocation_id="inv-forged-tool-001",
        tool_id="billing_refund_tool",
        implementation_id=TRUSTED_IMPL_ID,  # forged — ignored in strong mode
    )
    decision = gate.authorize(attack_req, now=NOW)
    # BLOCKS: record's SUBSTITUTE_IMPL_ID is not registered → DENY.
    assert decision.effect == DecisionEffect.DENY
    assert "from invocation record is not in the trusted registry" in decision.reason

    # Legitimate path: orchestrator registers record with the actual trusted tool.
    store.register(
        InvocationRecord(
            invocation_id="inv-legit-tool-001",
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id="billing_refund_tool",
            implementation_id=TRUSTED_IMPL_ID,  # actual trusted implementation
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )
    legit_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invocation_id="inv-legit-tool-001",
    )
    assert gate.authorize(legit_req, now=NOW).effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 13: Operation substitution blocked by arguments digest
#
# Scenario: An attacker attempts to reuse a legitimate invocation_id for a
# different operation. The orchestrator registered an InvocationRecord for a
# $250 refund. The attacker submits a request for a $500 refund using the same
# invocation_id (argument-escalation / operation-substitution attack).
#
# The InvocationRecord binds the exact operation: action, resource, and a
# SHA-256 digest of the canonical arguments. Ruhusa recomputes the digest from
# the live request arguments and compares it to the record. A mismatch is a
# hard DENY — the invocation_id cannot be replayed for a different operation.
#
# BLOCKS (v0.5-A+): DENY — arguments digest mismatch.
# ---------------------------------------------------------------------------


def test_operation_substitution_blocked_by_arguments_digest() -> None:
    """
    BLOCKS (v0.5-A+): With an InMemoryInvocationStore configured, the
    InvocationRecord binds the exact arguments via a SHA-256 digest.  Reusing
    a legitimate invocation_id with different arguments (operation-substitution
    / argument-escalation) produces a digest mismatch → DENY.

    Attack: orchestrator registered a $250 refund; attacker submits a $500
    refund reusing the same invocation_id.

    Legitimate path: exact same arguments ($250) match the registered digest
    and the request is ALLOW.
    """
    task = make_task("task-opsub-001")
    grant = make_grant(
        grant_id="grant-opsub",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
    )

    store = InMemoryInvocationStore()
    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)

    # Orchestrator registers a $250 refund invocation.
    store.register(
        InvocationRecord(
            invocation_id="inv-opsub-001",
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),  # $250
            tool_id=None,
            implementation_id=None,
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )

    # Attacker reuses the invocation_id but escalates the amount to $500.
    # $500 is within REFUND_SCOPE and policy limits, but the digest won't match.
    substituted_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 500},  # escalated — digest will not match
        task=task,
        delegation_chain=(grant,),
        invocation_id="inv-opsub-001",
    )
    decision = gate.authorize(substituted_req, now=NOW)
    # BLOCKS: arguments digest mismatch → DENY.
    assert decision.effect == DecisionEffect.DENY
    assert "arguments digest" in decision.reason

    # Legitimate path: exact same arguments ($250) match the registered digest.
    legit_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},  # matches the registered digest
        task=task,
        delegation_chain=(grant,),
        invocation_id="inv-opsub-001",
    )
    assert gate.authorize(legit_req, now=NOW).effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 14: Stale invocation record blocked by expiry
#
# Scenario: An InvocationRecord carries an expires_at timestamp independent
# of the parent task. Once the record expires, any request that references it
# is denied — even when the task itself is still active.
#
# This prevents long-lived or leaked invocation_ids from being replayed after
# their intended authorization window closes. The task and the record have
# separate, independently enforced lifetimes.
#
# BLOCKS (v0.5-A+): DENY — invocation record has expired.
# ---------------------------------------------------------------------------


def test_stale_invocation_record_is_denied() -> None:
    """
    BLOCKS (v0.5-A+): InvocationRecord.expires_at is enforced independently
    of the parent task's expiry.  A request referencing an expired record is
    denied even when the task is still active.

    Stale record (expires_at in the past) → DENY.
    Fresh record (expires_at in the future) with the same operation → ALLOW.
    """
    task = make_task("task-stale-001")
    grant = make_grant(
        grant_id="grant-stale",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
    )

    store = InMemoryInvocationStore()
    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)

    # Orchestrator registered a record that has since expired.
    store.register(
        InvocationRecord(
            invocation_id="inv-stale-001",
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id=None,
            implementation_id=None,
            recorded_at=NOW - timedelta(minutes=10),
            expires_at=NOW - timedelta(seconds=1),  # already expired
        )
    )

    stale_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,  # task is still active (expires in 1 hour)
        delegation_chain=(grant,),
        invocation_id="inv-stale-001",
    )
    decision = gate.authorize(stale_req, now=NOW)
    # BLOCKS: record expired → DENY despite task being active.
    assert decision.effect == DecisionEffect.DENY
    assert "expired" in decision.reason

    # Sanity check: a fresh record for the same operation is ALLOW.
    store.register(
        InvocationRecord(
            invocation_id="inv-fresh-001",
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id=None,
            implementation_id=None,
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),  # still valid
        )
    )
    fresh_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invocation_id="inv-fresh-001",
    )
    assert gate.authorize(fresh_req, now=NOW).effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 15: Non-delegated request — complete mediation after v0.5-C
#
# Scenario: Ruhusa is configured with both an InMemoryInvocationStore and an
# InMemoryToolRegistry — the fully hardened configuration.  A direct (non-
# delegated) request is submitted: delegation_chain is empty.
#
# Before v0.5-C, the strong-mode invocation block was gated on
# ``if request.delegation_chain:``, so non-delegated requests skipped it
# entirely.  The weak-mode tool check was also skipped because the invocation
# store was configured.  A substitute tool received ALLOW (confirmed GAP).
#
# v0.5-C fix: the ``if self.invocation_store is not None:`` check now applies
# to ALL requests — delegated and direct.  Every request must carry a canonical
# InvocationRecord.  The delegation-specific invoker==leaf-grantor check is
# inside the block, conditional on ``if request.delegation_chain:``.
#
# After the fix a non-delegated request without an invocation_id is denied
# immediately.  A request with an invocation_id must pass executor, task,
# operation, and tool-identity checks before policy is consulted.
#
# BLOCKS (v0.5-C): DENY — complete mediation now covers non-delegated requests.
# ---------------------------------------------------------------------------


def test_non_delegated_request_bypasses_strong_mode_tool_check() -> None:
    """
    BLOCKS (v0.5-C): After the v0.5-C architectural fix, non-delegated requests
    are no longer exempt from strong-mode invocation and tool-identity checks.

    When an InvocationStore is configured, every request must carry a canonical
    InvocationRecord.  A request without an invocation_id is denied immediately.
    Both the substitute-tool request and the no-tool-fields request are denied
    with "invocation id is required".

    Before v0.5-C this function documented a GAP (ALLOW); after the fix it
    documents BLOCKS (DENY) to preserve the research history and confirm the
    mitigation.
    """
    task = make_task("task-nondelegated-tool-001")

    store = InMemoryInvocationStore()
    gate = Ruhusa(
        policy_store=policy_store(),
        tool_registry=_refund_registry(),
        invocation_store=store,
    )

    # Attack: non-delegated request with an unregistered tool and no invocation_id.
    # After v0.5-C the invocation check applies to all requests; the missing
    # invocation_id is a hard DENY before the tool registry is consulted.
    substitute_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(),
        tool_id="billing_refund_tool",
        implementation_id=SUBSTITUTE_IMPL_ID,
    )
    decision = gate.authorize(substitute_req, now=NOW)

    # BLOCKS (v0.5-C): invocation_id is required for all requests when an
    # invocation store is configured.
    assert decision.effect == DecisionEffect.DENY
    assert "invocation id is required" in decision.reason

    # Same result when tool fields are omitted.
    no_tool_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(),
        tool_id=None,
        implementation_id=None,
    )
    no_tool_decision = gate.authorize(no_tool_req, now=NOW)
    assert no_tool_decision.effect == DecisionEffect.DENY
    assert "invocation id is required" in no_tool_decision.reason


def test_non_delegated_request_with_valid_invocation_is_allowed() -> None:
    """
    Positive path for Experiment 15 (v0.5-C): a non-delegated request that
    carries a valid canonical InvocationRecord with a registered tool identity
    is authorized normally.

    The invoker check is skipped (no delegation chain); executor, task,
    operation binding, expiry, and tool identity all pass.  Policy then decides.
    """
    task = make_task("task-nondelegated-trusted-001")

    store = InMemoryInvocationStore()
    store.register(
        InvocationRecord(
            invocation_id="inv-nondel-trusted-001",
            invoking_principal_id="user-1",  # not checked — no delegation chain
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id="billing_refund_tool",
            implementation_id=TRUSTED_IMPL_ID,
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )
    gate = Ruhusa(
        policy_store=policy_store(),
        tool_registry=_refund_registry(),
        invocation_store=store,
    )

    trusted_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(),
        invocation_id="inv-nondel-trusted-001",
    )
    assert gate.authorize(trusted_req, now=NOW).effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 16: Exact same-operation invocation replay
#
# Scenario: An attacker obtains a legitimate invocation_id and presents the
# exact same request — identical action, resource, and arguments — multiple
# times.  Unlike Experiment 13 (argument escalation), the operation here is
# bit-for-bit identical to the originally authorized one.
#
# The InMemoryInvocationStore provides get() and is_registered(), but no
# consume() or used-state mechanism.  After a successful authorization, the
# record is not marked as consumed.  Ruhusa verifies the record on every call
# and returns ALLOW each time, so the same invocation_id can authorize
# arbitrarily many identical operations.
#
# For the billing example, this means a $250 refund invocation_id could be
# replayed many times, resulting in a multi-spend, unless the execution layer
# independently enforces idempotency.
#
# Design decision recorded here: Ruhusa does not currently enforce one-shot
# invocation semantics.  Idempotency is an execution-layer concern.  This
# test documents the gap so the decision is explicit.  If one-shot semantics
# are required, a consume() mechanism or used-invocations set must be added
# to InMemoryInvocationStore and enforced in core.authorize().
#
# GAP: ALLOW — exact replay succeeds because records are not consumed.
# ---------------------------------------------------------------------------


def test_exact_invocation_replay_is_not_prevented() -> None:
    """
    GAP: Presenting the same invocation_id with an identical operation
    multiple times succeeds every time.  Ruhusa performs all record checks
    on each call but has no mechanism to detect or prevent replay.

    Design note: Ruhusa does not enforce one-shot semantics by design.
    Idempotency must be enforced by the execution layer.  This test exists
    to make that decision explicit and traceable.  A future consume() hook
    in InMemoryInvocationStore would change the second assertion to DENY.
    """
    task = make_task("task-replay-001")
    grant = make_grant(
        grant_id="grant-replay",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
    )

    store = InMemoryInvocationStore()
    gate = Ruhusa(policy_store=policy_store(), invocation_store=store)

    store.register(
        InvocationRecord(
            invocation_id="inv-replay-001",
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id=None,
            implementation_id=None,
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )

    def make_replay_req() -> AuthorizationRequest:
        return AuthorizationRequest(
            principal=Principal("billing-agent"),
            action="issue_refund",
            resource="customer:123:billing",
            arguments={"amount": 250},
            task=task,
            delegation_chain=(grant,),
            invocation_id="inv-replay-001",
        )

    # First presentation: ALLOW (expected — this is the legitimate authorization).
    first = gate.authorize(make_replay_req(), now=NOW)
    assert first.effect == DecisionEffect.ALLOW

    # Second presentation: ALLOW again — the record is not consumed.
    # GAP: one-shot semantics are not enforced by Ruhusa.
    second = gate.authorize(make_replay_req(), now=NOW)
    assert second.effect == DecisionEffect.ALLOW

    # Third — still ALLOW.
    third = gate.authorize(make_replay_req(), now=NOW)
    assert third.effect == DecisionEffect.ALLOW


# ---------------------------------------------------------------------------
# Experiment 17: Invocation record carries tool_id=None with registry configured
#
# Scenario: An InvocationStore and a ToolRegistry are both configured (strong
# mode).  A canonical InvocationRecord is registered, but the orchestration
# layer omitted tool identity (tool_id=None, implementation_id=None).
#
# Before v0.5-C, strong tool verification was conditional on
# ``record.tool_id is not None``, so a None tool_id silently skipped the check.
# Policy decided alone, producing ALLOW even in the fully hardened configuration.
# T16 in the threat model identified this as a candidate gap.
#
# v0.5-C fix: when a tool registry is configured and the record carries
# tool_id=None, Ruhusa returns DENY immediately (fail-closed).  The tool
# registry is a declared security requirement; an absent tool_id means the
# operation cannot be verified against it.
#
# This test covers both delegated and non-delegated requests, confirming that
# the fail-closed guard applies to all requests when a registry is configured.
#
# BLOCKS (v0.5-C): DENY — missing canonical tool identity is fail-closed.
# ---------------------------------------------------------------------------


def test_missing_canonical_tool_identity_is_denied() -> None:
    """
    BLOCKS (v0.5-C): When both an InvocationStore and a ToolRegistry are
    configured, an InvocationRecord with tool_id=None is rejected fail-closed.

    This closes T16 from the threat model: the earlier ``record.tool_id is not
    None`` guard allowed tool verification to be silently skipped.  After v0.5-C,
    a missing tool_id in the canonical record is a hard DENY regardless of
    whether the request is delegated or direct.
    """
    task = make_task("task-notoolid-001")
    grant = make_grant(
        grant_id="grant-notoolid",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
    )

    store = InMemoryInvocationStore()
    store.register(
        InvocationRecord(
            invocation_id="inv-notoolid-001",
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id=None,  # orchestrator omitted tool identity
            implementation_id=None,
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )
    gate = Ruhusa(
        policy_store=policy_store(),
        tool_registry=_refund_registry(),
        invocation_store=store,
    )

    # Delegated request: record has invoker==leaf-grantor but tool_id=None.
    delegated_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invocation_id="inv-notoolid-001",
    )
    decision = gate.authorize(delegated_req, now=NOW)

    # BLOCKS (v0.5-C): tool_id=None in the canonical record is fail-closed
    # when a tool registry is configured.
    assert decision.effect == DecisionEffect.DENY
    assert "record carries no tool_id" in decision.reason


def test_missing_canonical_tool_identity_denied_for_direct_request() -> None:
    """
    Non-delegated variant of Experiment 17: the tool_id=None fail-closed guard
    applies to direct requests too, confirming complete mediation.
    """
    task = make_task("task-notoolid-direct-001")

    store = InMemoryInvocationStore()
    store.register(
        InvocationRecord(
            invocation_id="inv-notoolid-direct-001",
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id=None,
            implementation_id=None,
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )
    gate = Ruhusa(
        policy_store=policy_store(),
        tool_registry=_refund_registry(),
        invocation_store=store,
    )

    direct_req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(),
        invocation_id="inv-notoolid-direct-001",
    )
    decision = gate.authorize(direct_req, now=NOW)
    assert decision.effect == DecisionEffect.DENY
    assert "record carries no tool_id" in decision.reason


def test_missing_canonical_tool_identity_positive_path() -> None:
    """
    Positive path for Experiment 17: when both a registry and an InvocationStore
    are configured and the record carries a registered tool_id and implementation_id,
    authorization proceeds normally.
    """
    task = make_task("task-notoolid-positive-001")
    grant = make_grant(
        grant_id="grant-notoolid-pos",
        grantor_id="user-1",
        grantee_id="billing-agent",
        task_id=task.task_id,
    )

    store = InMemoryInvocationStore()
    store.register(
        InvocationRecord(
            invocation_id="inv-notoolid-pos-001",
            invoking_principal_id="user-1",
            executing_principal_id="billing-agent",
            task_id=task.task_id,
            action="issue_refund",
            resource="customer:123:billing",
            arguments_digest=compute_arguments_digest({"amount": 250}),
            tool_id="billing_refund_tool",
            implementation_id=TRUSTED_IMPL_ID,
            recorded_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
    )
    gate = Ruhusa(
        policy_store=policy_store(),
        tool_registry=_refund_registry(),
        invocation_store=store,
    )

    req = AuthorizationRequest(
        principal=Principal("billing-agent"),
        action="issue_refund",
        resource="customer:123:billing",
        arguments={"amount": 250},
        task=task,
        delegation_chain=(grant,),
        invocation_id="inv-notoolid-pos-001",
    )
    assert gate.authorize(req, now=NOW).effect == DecisionEffect.ALLOW
