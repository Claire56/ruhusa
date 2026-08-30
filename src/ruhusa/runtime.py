from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from threading import RLock

from .config import RuntimeConfig
from .errors import ConfigurationError, InvalidStateTransitionError, RuhusaError
from .health import HealthRegistry


class LifecycleError(RuhusaError):
    """Base class for explicit runtime lifecycle failures."""


class StartupError(LifecycleError):
    """Runtime startup failed and rollback was attempted."""

    def __init__(self, message: str, *, resource: str | None = None) -> None:
        super().__init__(message)
        self.resource = resource


class ShutdownError(LifecycleError):
    """One or more resources failed to close."""

    def __init__(self, resources: tuple[str, ...]) -> None:
        self.resources = resources
        super().__init__("runtime shutdown failed for resource(s): " + ", ".join(resources))


class ResourceClosedError(LifecycleError):
    """Operation requires a runtime that has already been closed."""


class RuntimeState(str, Enum):
    NEW = "new"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    CLOSED = "closed"


@dataclass(frozen=True)
class RuntimeResource:
    name: str
    start: Callable[[], None] | None = None
    close: Callable[[], None] | None = None

    def __post_init__(self) -> None:
        canonical_name = self.name.strip()
        if not canonical_name:
            raise ConfigurationError("runtime resource name must not be empty")
        object.__setattr__(self, "name", canonical_name)


class RuhusaRuntime:
    """Explicit lifecycle owner for application-managed resources."""

    def __init__(
        self,
        *,
        config: RuntimeConfig | None = None,
        health_registry: HealthRegistry | None = None,
    ) -> None:
        self.config = config if config is not None else RuntimeConfig()
        self.health_registry = health_registry

        if self.config.require_healthy_startup and self.health_registry is None:
            raise ConfigurationError("require_healthy_startup requires a health registry")

        self._resources: list[RuntimeResource] = []
        self._started_resources: list[RuntimeResource] = []
        self._state = RuntimeState.NEW
        self._lock = RLock()

    @property
    def state(self) -> RuntimeState:
        with self._lock:
            return self._state

    def register(
        self,
        name: str,
        *,
        start: Callable[[], None] | None = None,
        close: Callable[[], None] | None = None,
    ) -> None:
        resource = RuntimeResource(name=name, start=start, close=close)

        with self._lock:
            if self._state is RuntimeState.CLOSED:
                raise ResourceClosedError("cannot register a resource on a closed runtime")
            if self._state is not RuntimeState.NEW:
                raise InvalidStateTransitionError(
                    "runtime resources may only be registered before startup"
                )
            if any(existing.name == resource.name for existing in self._resources):
                raise ConfigurationError(
                    f"runtime resource {resource.name!r} is already registered"
                )
            self._resources.append(resource)

    def start(self) -> None:
        with self._lock:
            if self._state is RuntimeState.RUNNING:
                return
            if self._state is RuntimeState.CLOSED:
                raise ResourceClosedError("cannot start a closed runtime")
            if self._state is not RuntimeState.NEW:
                raise InvalidStateTransitionError(
                    f"cannot start runtime while state is {self._state.value}"
                )

            self._state = RuntimeState.STARTING

            try:
                for resource in tuple(self._resources):
                    self._started_resources.append(resource)
                    if resource.start is not None:
                        resource.start()

                if self.config.require_healthy_startup:
                    assert self.health_registry is not None
                    report = self.health_registry.check()
                    if not report.healthy:
                        raise StartupError(
                            "runtime startup health check failed",
                            resource="health",
                        )
            except Exception as exc:
                failing_resource = (
                    exc.resource
                    if isinstance(exc, StartupError)
                    else (self._started_resources[-1].name if self._started_resources else None)
                )
                self._rollback_started()
                self._state = RuntimeState.CLOSED

                if isinstance(exc, StartupError):
                    raise

                raise StartupError(
                    "runtime startup failed",
                    resource=failing_resource,
                ) from exc

            self._state = RuntimeState.RUNNING

    def close(self) -> None:
        with self._lock:
            if self._state is RuntimeState.CLOSED:
                return
            if self._state is RuntimeState.NEW:
                self._state = RuntimeState.CLOSED
                return
            if self._state is not RuntimeState.RUNNING:
                raise InvalidStateTransitionError(
                    f"cannot close runtime while state is {self._state.value}"
                )

            self._state = RuntimeState.STOPPING
            failures = self._close_started_resources()
            self._state = RuntimeState.CLOSED

            if failures and self.config.fail_on_shutdown_error:
                raise ShutdownError(tuple(failures))

    def ensure_running(self) -> None:
        with self._lock:
            if self._state is RuntimeState.CLOSED:
                raise ResourceClosedError("runtime is closed")
            if self._state is not RuntimeState.RUNNING:
                raise InvalidStateTransitionError(
                    f"runtime is not running; current state is {self._state.value}"
                )

    def _rollback_started(self) -> None:
        self._close_started_resources()

    def _close_started_resources(self) -> list[str]:
        failures: list[str] = []

        for resource in reversed(self._started_resources):
            if resource.close is None:
                continue
            try:
                resource.close()
            except Exception:
                failures.append(resource.name)

        self._started_resources.clear()
        return failures

    def __enter__(self) -> RuhusaRuntime:
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if exc is None:
            self.close()
            return False

        try:
            self.close()
        except ShutdownError:
            pass
        return False
