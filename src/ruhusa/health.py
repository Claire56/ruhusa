from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True)
class HealthCheckResult:
    name: str
    status: HealthStatus
    detail: str | None = None

    @property
    def healthy(self) -> bool:
        return self.status is HealthStatus.HEALTHY


@dataclass(frozen=True)
class HealthReport:
    generated_at: datetime
    checks: tuple[HealthCheckResult, ...]

    @property
    def healthy(self) -> bool:
        return bool(self.checks) and all(check.healthy for check in self.checks)

    def as_dict(self) -> dict[str, object]:
        return {
            "healthy": self.healthy,
            "generated_at": self.generated_at.isoformat(),
            "checks": [
                {"name": c.name, "status": c.status.value, "detail": c.detail} for c in self.checks
            ],
        }


HealthProbe = Callable[[], bool | HealthCheckResult]


class HealthRegistry:
    """Framework-neutral registry of read-only operational probes."""

    def __init__(self) -> None:
        self._probes: dict[str, HealthProbe] = {}

    def register(self, name: str, probe: HealthProbe) -> None:
        name = name.strip()
        if not name:
            raise ValueError("health probe name must not be empty")
        if name in self._probes:
            raise ValueError(f"health probe {name!r} is already registered")
        self._probes[name] = probe

    def check(self) -> HealthReport:
        results: list[HealthCheckResult] = []
        for name, probe in self._probes.items():
            try:
                value = probe()
            except Exception as exc:
                results.append(
                    HealthCheckResult(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        detail=f"probe raised {type(exc).__name__}",
                    )
                )
                continue

            if isinstance(value, HealthCheckResult):
                results.append(
                    HealthCheckResult(name=name, status=value.status, detail=value.detail)
                )
            else:
                results.append(
                    HealthCheckResult(
                        name=name,
                        status=HealthStatus.HEALTHY if value else HealthStatus.UNHEALTHY,
                    )
                )

        return HealthReport(datetime.now(UTC), tuple(results))
