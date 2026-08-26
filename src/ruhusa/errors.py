from __future__ import annotations


class RuhusaError(Exception):
    """Base exception for stable Ruhusa framework errors."""


class ConfigurationError(RuhusaError, ValueError):
    """Invalid or incomplete framework configuration.

    ``ValueError`` remains a base class for backward compatibility.
    """


class StoreError(RuhusaError):
    """Base exception for infrastructure/storage dependency failures."""


class StoreUnavailableError(StoreError):
    """A configured backend cannot reliably satisfy an operation.

    Backend implementations should use this for timeouts, disconnections, or
    other conditions where authoritative state cannot be returned. Security
    decision paths must fail closed when this occurs.
    """


class InvalidStateTransitionError(RuhusaError):
    """An administrative/backend lifecycle transition is invalid.

    Existing boolean lifecycle methods retain their v0.6 behavior; this type is
    available for persistent backend and integration APIs.
    """


class ProvenanceError(RuhusaError):
    """Trusted provenance supplied to an administrative integration is invalid.

    Authorization-time provenance mismatches continue to produce DENY decisions.
    """
