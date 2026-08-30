from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .errors import ConfigurationError


@dataclass(frozen=True)
class RuntimeConfig:
    """Validated production runtime configuration."""

    require_healthy_startup: bool = False
    fail_on_shutdown_error: bool = True

    def __post_init__(self) -> None:
        for name in ("require_healthy_startup", "fail_on_shutdown_error"):
            if type(getattr(self, name)) is not bool:
                raise ConfigurationError(f"{name} must be a boolean")

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> RuntimeConfig:
        allowed = {"require_healthy_startup", "fail_on_shutdown_error"}
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise ConfigurationError(
                "unknown runtime configuration option(s): " + ", ".join(unknown)
            )
        return cls(**dict(values))

    def as_dict(self) -> dict[str, bool]:
        return {
            "require_healthy_startup": self.require_healthy_startup,
            "fail_on_shutdown_error": self.fail_on_shutdown_error,
        }
