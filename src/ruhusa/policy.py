from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from .models import AuthorizationRequest, DecisionEffect


Condition = Callable[[AuthorizationRequest], bool]


@dataclass(frozen=True)
class PolicyRule:
    policy_id: str
    effect: DecisionEffect
    actions: frozenset[str]
    principal_ids: frozenset[str] = frozenset()
    principal_types: frozenset[str] = frozenset()
    resource_prefixes: tuple[str, ...] = ()
    condition: Condition | None = None
    reason: str = "policy matched"
    obligations: tuple[str, ...] = ()

    def matches(self, request: AuthorizationRequest) -> bool:
        if self.principal_ids and request.principal.principal_id not in self.principal_ids:
            return False
        if self.principal_types and request.principal.principal_type not in self.principal_types:
            return False
        if request.action not in self.actions:
            return False
        if self.resource_prefixes and not any(
            request.resource.startswith(prefix) for prefix in self.resource_prefixes
        ):
            return False
        if self.condition is not None and not self.condition(request):
            return False
        return True


class StaticPolicyStore:
    """Small deterministic policy store for the v0.1 research prototype.

    Rules are evaluated in order. No match means DENY. Later versions can add
    adapters for OPA/Rego, Cedar, AuthZEN-compatible PDPs, or cloud IAM.
    """

    def __init__(self, rules: Iterable[PolicyRule] = ()) -> None:
        self._rules = tuple(rules)

    def evaluate(self, request: AuthorizationRequest) -> PolicyRule | None:
        for rule in self._rules:
            if rule.matches(request):
                return rule
        return None
