from __future__ import annotations

from dataclasses import dataclass, field

from .models import DelegationGrant


@dataclass
class InMemoryGrantStore:
    """Trusted issuance boundary for delegation grants.

    Only grants explicitly registered through this store are accepted
    during authorization. Two invariants are enforced:

    1. Content integrity: authorization checks that the presented grant
       exactly equals the canonical grant on record — same grant_id AND
       same contents. A grant with a known ID but modified fields
       (e.g. a wider scope) is denied.

    2. Immutable registry: once a grant_id is registered it cannot be
       overwritten. Re-registering the same ID raises ValueError. A
       legitimate re-issuance of authority must use a new grant_id.

    Note: this store tracks issuance, not revocation. A grant registered
    here can still be independently revoked in the revocation store. Both
    checks are applied during authorization.
    """

    _grants: dict[str, DelegationGrant] = field(default_factory=dict, init=False)

    def register(self, grant: DelegationGrant) -> DelegationGrant:
        """Record a grant as legitimately issued. Returns the grant unchanged.

        Raises ValueError if a grant with the same grant_id is already
        registered. Grant IDs are immutable once registered; re-issuance
        requires a new grant_id.
        """
        if grant.grant_id in self._grants:
            raise ValueError(
                f"grant {grant.grant_id!r} is already registered; "
                "grant IDs are immutable — use a new grant_id for re-issuance"
            )
        self._grants[grant.grant_id] = grant
        return grant

    def get(self, grant_id: str) -> DelegationGrant | None:
        """Return the registered grant with this ID, or None if unknown."""
        return self._grants.get(grant_id)

    def contains(self, grant_id: str) -> bool:
        """Return True if this grant_id was registered through this store."""
        return grant_id in self._grants

    def is_registered(self, grant: DelegationGrant) -> bool:
        """Return True if the presented grant exactly equals the canonical issued grant.

        Checks both that the grant_id is known and that every field of the
        presented grant matches the stored record. A grant with a recognized
        ID but modified contents (e.g. wider scope, different task) returns False.
        """
        stored = self._grants.get(grant.grant_id)
        return stored == grant
