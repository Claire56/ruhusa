from __future__ import annotations

from pathlib import Path

POSTGRES = Path("src/ruhusa/postgres.py")


def require_once(text: str, needle: str, description: str) -> None:
    count = text.count(needle)
    if count != 1:
        raise SystemExit(
            f"expected exactly one {description}; found {count}. Refusing to patch automatically."
        )


def main() -> None:
    text = POSTGRES.read_text()

    if "SCHEMA_VERSION = 3" in text:
        print("postgres.py already appears patched for schema v3")
        return

    require_once(text, "SCHEMA_VERSION = 2", "SCHEMA_VERSION = 2")
    require_once(
        text,
        "from psycopg_pool import ConnectionPool\n",
        "psycopg_pool import anchor",
    )
    require_once(
        text,
        "\ndef create_postgres_pool(",
        "create_postgres_pool anchor",
    )

    text = text.replace("SCHEMA_VERSION = 2", "SCHEMA_VERSION = 3", 1)

    import_anchor = "from psycopg_pool import ConnectionPool\n"
    import_block = (
        "from psycopg_pool import ConnectionPool\n"
        "\n"
        "from .postgres_approvals import "
        "PostgresApprovalStore as PostgresApprovalStore\n"
        "from .postgres_migrations import "
        "APPROVAL_SCHEMA_DDL as _APPROVAL_SCHEMA_DDL\n"
    )
    text = text.replace(import_anchor, import_block, 1)

    schema_extension = (
        "\n# v0.9-A: fresh schema-v3 databases must contain the same durable\n"
        "# approval table created by the v2→v3 migration.\n"
        "_SCHEMA_STATEMENTS = (*_SCHEMA_STATEMENTS, _APPROVAL_SCHEMA_DDL)\n"
    )
    text = text.replace(
        "\ndef create_postgres_pool(",
        schema_extension + "\n\ndef create_postgres_pool(",
        1,
    )

    POSTGRES.write_text(text)
    print("Patched src/ruhusa/postgres.py for schema v3 + PostgresApprovalStore")


if __name__ == "__main__":
    main()
