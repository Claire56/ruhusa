# Health and observability

## Health

`HealthRegistry` runs read-only probes and returns a `HealthReport`.

Probe exceptions are caught and reported as unhealthy. The exception message is
not included in the result so that DSNs, passwords, or other secrets in error
messages are not exposed through health endpoints.

PostgreSQL probes are available in `ruhusa.postgres_health`:

- `postgres.connectivity` — executes `SELECT 1`
- `postgres.schema` — verifies the schema version and migration history
- `postgres.audit_chain` — verifies the audit event hash chain

## Telemetry

`TelemetrySink` is a `Protocol`. Pass any object that implements `emit(event: TelemetryEvent)`.

`InMemoryTelemetrySink` is provided for testing.

### Separation of concerns

| Layer | Failure behavior |
|---|---|
| Audit | Re-raises. Mandatory security evidence. |
| Telemetry | Silently suppressed. Must not alter security results. |

`InstrumentedAuditLog` and `InstrumentedExecutionStore` decorate existing
implementations. They add low-cardinality, non-sensitive attributes only.
Sensitive values such as reasons, resource paths, and argument contents are
never included in telemetry events.

### Trace context

Use `telemetry_context()` as a context manager to attach `trace_id` and
`correlation_id` to events emitted within that scope. The context is propagated
through `ContextVar` and resets automatically on exit.
