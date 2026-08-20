from __future__ import annotations

from dataclasses import dataclass, field

from .models import DelegationGrant


@dataclass
class InMemoryGrantStore:
    """Trusted issuance boundary for delegation grants.

    Only grants explicitly registered through this store are accepted
    during authorization. Grants constructed outside of the store and
    presented directly in a delegation chain are rejected.

    This closes the gap where an attacker can fabricate a replacement
    grant after the original is revoked: the replacement grant_id is
    not in the store, so it is denied regardless of its contents.

    Note: the grant store tracks issuance, not revocation. A grant
    can be registered here and separately revoked in the revocation
    store. Both checks are applied independently during authorization.
    """

    _grants: dict[str, DelegationGrant] = field(default_factory=dict, init=False)

    def register(self, grant: DelegationGrant) -> DelegationGrant:
        """Record a grant as legitimately issued. Returns the grant unchanged."""
        self._grants[grant.grant_id] = grant
        return grant

    def get(self, grant_id: str) -> DelegationGrant | None:
        """Return the registered grant with this ID, or None if unknown."""
        return self._grants.get(grant_id)

    def contains(self, grant_id: str) -> bool:
        """Return True if this grant_id was registered through this store."""
        return grant_id in self._grants
