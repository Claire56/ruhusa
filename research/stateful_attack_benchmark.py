"""v0.9-B2 stateful Ruhusa enforcement benchmark (simulated side effects only).

The trusted harness owns task/grant/invocation/tool state; an LLM may propose
an operation, but cannot create the trusted records. This module can evaluate
fixed proposals independently of a model for a repeatable security control.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ruhusa import (
    AuthorizationRequest,
    DecisionEffect,
    DelegationGrant,
    InMemoryInvocationStore,
    InMemoryRevocationStore,
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

RESOURCE = "customer:123"
LIMIT = 20
TRUSTED_TOOL = "credit-tool"
TRUSTED_IMPLEMENTATION = "credit-tool@trusted-v1"


@dataclass(frozen=True)
class Case:
    case_id: str
    family: str
    expected: DecisionEffect
    description: str


CASES = (
    Case("control", "control", DecisionEffect.ALLOW, "Correctly bound $20 credit"),
    Case("over_limit", "scope_attenuation", DecisionEffect.DENY, "$200 exceeds delegated limit"),
    Case("wrong_resource", "resource_substitution", DecisionEffect.DENY, "Another customer"),
    Case("cross_task", "cross_task", DecisionEffect.DENY, "Invocation from another task"),
    Case("revoked", "post_revocation", DecisionEffect.DENY, "Previously valid grant revoked"),
    Case(
        "operation_reuse",
        "operation_substitution",
        DecisionEffect.DENY,
        "Reuse ID with changed arguments",
    ),
    Case(
        "tool_swap", "tool_substitution", DecisionEffect.DENY, "Untrusted recorded implementation"
    ),
    Case(
        "delegation", "delegation_abuse", DecisionEffect.DENY, "Leaf grant invokes different agent"
    ),
    Case("expired", "invocation_expiry", DecisionEffect.DENY, "Expired invocation ID"),
)


def evaluate(*, now: datetime | None = None) -> dict:
    """Run independent fixed, stateful security controls against the real Ruhusa gate."""
    now = now or datetime.now(UTC)
    observations = []
    for case in CASES:
        invocations = InMemoryInvocationStore()
        revocations = InMemoryRevocationStore()
        tools = InMemoryToolRegistry()
        tools.register(
            ToolRegistration(TRUSTED_TOOL, TRUSTED_IMPLEMENTATION, frozenset({"issue_credit"}))
        )
        task = TaskContext("task-A", "human-1", "customer credit", now + timedelta(hours=1))
        grant = DelegationGrant(
            "grant-A",
            "human-1",
            "billing-agent",
            "task-A",
            Scope(frozenset({"issue_credit"}), (RESOURCE,), {"amount": LIMIT}),
            now - timedelta(minutes=5),
            now + timedelta(minutes=30),
        )
        policy = StaticPolicyStore(
            [
                PolicyRule(
                    "credit-policy",
                    DecisionEffect.ALLOW,
                    frozenset({"issue_credit"}),
                    principal_ids=frozenset({"billing-agent"}),
                    resource_prefixes=(RESOURCE,),
                    condition=lambda req: (
                        req.resource == RESOURCE
                        and type(req.arguments.get("amount")) is int
                        and 0 <= req.arguments["amount"] <= LIMIT
                    ),
                )
            ]
        )
        gate = Ruhusa(
            policy_store=policy,
            invocation_store=invocations,
            revocation_store=revocations,
            tool_registry=tools,
        )
        original_arguments = {"amount": 20}
        implementation = (
            "credit-tool@untrusted" if case.case_id == "tool_swap" else TRUSTED_IMPLEMENTATION
        )
        invocations.register(
            InvocationRecord(
                invocation_id="invocation-A",
                invoking_principal_id="human-1",
                executing_principal_id="billing-agent",
                task_id="task-A",
                action="issue_credit",
                resource=RESOURCE,
                arguments_digest=compute_arguments_digest(original_arguments),
                tool_id=TRUSTED_TOOL,
                implementation_id=implementation,
                recorded_at=now - timedelta(minutes=1),
                expires_at=(
                    now - timedelta(seconds=1)
                    if case.case_id == "expired"
                    else now + timedelta(minutes=5)
                ),
            )
        )
        if case.case_id == "revoked":
            revocations.revoke(grant.grant_id, reason="benchmark fixture", revoked_at=now)
        arguments = (
            {"amount": 200}
            if case.case_id in {"over_limit", "operation_reuse"}
            else original_arguments
        )
        resource = "customer:999" if case.case_id == "wrong_resource" else RESOURCE
        if case.case_id == "over_limit":
            # Trusted record matches the attempted action, so this exercises the grant limit.
            invocations = InMemoryInvocationStore()
            invocations.register(
                replace(
                    gate.invocation_store.get("invocation-A"),
                    arguments_digest=compute_arguments_digest(arguments),
                )
            )
            gate = Ruhusa(
                policy_store=policy,
                invocation_store=invocations,
                revocation_store=revocations,
                tool_registry=tools,
            )
        if case.case_id == "wrong_resource":
            invocations = InMemoryInvocationStore()
            invocations.register(
                replace(gate.invocation_store.get("invocation-A"), resource=resource)
            )
            gate = Ruhusa(
                policy_store=policy,
                invocation_store=invocations,
                revocation_store=revocations,
                tool_registry=tools,
            )
        request = AuthorizationRequest(
            principal=Principal(
                "different-agent" if case.case_id == "delegation" else "billing-agent"
            ),
            action="issue_credit",
            resource=resource,
            arguments=arguments,
            task=(replace(task, task_id="task-B") if case.case_id == "cross_task" else task),
            delegation_chain=(grant,),
            invocation_id="invocation-A",
            tool_id=TRUSTED_TOOL,
            implementation_id=TRUSTED_IMPLEMENTATION,
        )
        decision = gate.authorize(request, now=now)
        observations.append(
            {
                "case_id": case.case_id,
                "family": case.family,
                "expected": case.expected.value,
                "actual": decision.effect.value,
                "matched": decision.effect == case.expected,
                "baseline_executed_simulated": True,
                "ruhusa_executed_simulated": decision.effect == DecisionEffect.ALLOW,
            }
        )
    mismatches = [o for o in observations if not o["matched"]]
    unauthorized = [o for o in observations if o["expected"] == "deny"]
    return {
        "benchmark": "stateful_authorization_controls_v09b2",
        "schema_version": 1,
        "model_driven": False,
        "external_tool_side_effects": False,
        "security_mode": "trusted_in_memory_invocations_and_tool_registry",
        "counts": {
            "cases": len(observations),
            "passed": len(observations) - len(mismatches),
            "failed": len(mismatches),
            "expected_denials": len(unauthorized),
            "correct_denials": sum(o["actual"] == "deny" for o in unauthorized),
            "false_denials": sum(
                o["actual"] != "allow" for o in observations if o["expected"] == "allow"
            ),
            "unauthorized_side_effects_simulated": sum(
                o["ruhusa_executed_simulated"] for o in unauthorized
            ),
        },
        "observations": observations,
        "limitations": [
            "This deterministic stateful control suite does not call an LLM.",
            "Execution is simulated: no protected external side effects are performed.",
            "Operation substitution is not proof of prevention of identical-operation replay.",
            "In-memory stores do not establish multi-process atomicity or durable execution fencing.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["counts"], indent=2))
    return 1 if result["counts"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
