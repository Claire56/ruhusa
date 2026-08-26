from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class RevocationRecord:
    """Immutable record describing when and why a delegation grant was revoked."""

    grant_id: str
    revoked_at: datetime
    reason: str

    def __post_init__(self) -> None:
        if not self.grant_id.strip():
            raise ValueError("grant_id must not be empty")

        if not self.reason.strip():
            raise ValueError("reason must not be empty")

        if self.revoked_at.tzinfo is None:
            object.__setattr__(
                self,
                "revoked_at",
                self.revoked_at.replace(tzinfo=UTC),
            )
        else:
            object.__setattr__(
                self,
                "revoked_at",
                self.revoked_at.astimezone(UTC),
            )


class InMemoryRevocationStore:
    """In-memory revocation state for delegation grants.

    This implementation is intended for development, tests, and the Ruhusa
    research prototype. Production deployments can replace it with a durable
    backend such as PostgreSQL, Redis, or an enterprise authorization service.
    """

    def __init__(self) -> None:
        self._records: dict[str, RevocationRecord] = {}

    def revoke(
        self,
        grant_id: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> RevocationRecord:
        """Revoke a grant.

        Revocation is monotonic toward earlier enforcement. A repeated
        revocation at the same or a later effective time preserves the
        existing record. An earlier revocation replaces a previously
        scheduled one so emergency revocation cannot be delayed.
        """
        candidate = RevocationRecord(
            grant_id=grant_id,
            revoked_at=revoked_at or datetime.now(UTC),
            reason=reason,
        )

        existing = self._records.get(grant_id)
        if existing is not None and existing.revoked_at <= candidate.revoked_at:
            return existing

        self._records[grant_id] = candidate
        return candidate

    def is_revoked(
        self,
        grant_id: str,
        *,
        at: datetime | None = None,
    ) -> bool:
        """Return whether a grant is revoked at the supplied point in time."""
        record = self._records.get(grant_id)
        if record is None:
            return False

        check_time = at or datetime.now(UTC)

        if check_time.tzinfo is None:
            check_time = check_time.replace(tzinfo=UTC)
        else:
            check_time = check_time.astimezone(UTC)

        return record.revoked_at <= check_time

    def get(self, grant_id: str) -> RevocationRecord | None:
        """Return the revocation record for a grant, if one exists."""
        return self._records.get(grant_id)

    def snapshot(self) -> tuple[RevocationRecord, ...]:
        """Return an immutable point-in-time view of revocations."""
        return tuple(self._records.values())

    def all(self) -> tuple[RevocationRecord, ...]:
        """Deprecated compatibility alias for snapshot()."""
        return self.snapshot()

    def __len__(self) -> int:
        return len(self._records)
