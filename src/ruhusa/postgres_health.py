from __future__ import annotations

from psycopg_pool import ConnectionPool

from .health import HealthRegistry
from .postgres import SCHEMA_VERSION, PostgresAuditLog
from .postgres_migrations import validate_migration_history


def postgres_connectivity_probe(pool: ConnectionPool) -> bool:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            return cur.fetchone() == (1,)


def postgres_schema_probe(pool: ConnectionPool) -> bool:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT version FROM ruhusa_schema_metadata WHERE singleton = TRUE")
            row = cur.fetchone()
            if row is None or int(row[0]) != SCHEMA_VERSION:
                return False
            validate_migration_history(cur)
    return True


def postgres_audit_chain_probe(pool: ConnectionPool) -> bool:
    return PostgresAuditLog(pool).verify_chain()


def build_postgres_health_registry(
    pool: ConnectionPool, *, include_audit_chain: bool = True
) -> HealthRegistry:
    registry = HealthRegistry()
    registry.register("postgres.connectivity", lambda: postgres_connectivity_probe(pool))
    registry.register("postgres.schema", lambda: postgres_schema_probe(pool))
    if include_audit_chain:
        registry.register("postgres.audit_chain", lambda: postgres_audit_chain_probe(pool))
    return registry
