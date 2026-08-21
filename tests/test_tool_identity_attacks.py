"""
tests/test_tool_identity_attacks.py

v0.5 experiments: tool identity and confused-deputy gaps and controls.

Each experiment documents an attack vector and its outcome.

Tests marked GAP document where no control exists (without a tool registry).
Tests marked BLOCKS confirm that the named control prevents the attack.

Ten experiments:

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
            recorded_at=NOW,
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
            recorded_at=NOW,
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
