"""Framework-neutral integration helpers for trusted orchestration boundaries."""

from .trusted import PreparedInvocation, TrustedInvocationFactory

__all__ = [
    "PreparedInvocation",
    "TrustedInvocationFactory",
]
