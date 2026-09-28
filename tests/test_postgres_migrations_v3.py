from __future__ import annotations

import hashlib

from ruhusa.postgres_migrations import (
    _CHECKSUM_V1_TO_V2,
    _CHECKSUM_V2_TO_V3,
    _MIGRATION_STEPS,
    APPROVAL_SCHEMA_DDL,
)


def test_v1_v2_checksum_is_unchanged() -> None:
    assert _CHECKSUM_V1_TO_V2 == "48edbed3d9348b746c410ac89cc7a7d042f597a5871ad9810bfa6de0c1119e9f"


def test_v2_v3_checksum_is_frozen() -> None:
    assert hashlib.sha256(APPROVAL_SCHEMA_DDL.encode()).hexdigest() == (
        "be0a98f0642f61253c736d63261063c853a1bd998f0bac55ac470f0c210dc605"
    )
    assert _CHECKSUM_V2_TO_V3 == "be0a98f0642f61253c736d63261063c853a1bd998f0bac55ac470f0c210dc605"


def test_v2_v3_is_registered_without_rewriting_history() -> None:
    assert set(_MIGRATION_STEPS) == {(1, 2), (2, 3)}
    assert _MIGRATION_STEPS[(2, 3)] == (
        APPROVAL_SCHEMA_DDL,
        _CHECKSUM_V2_TO_V3,
    )


def test_schema_v3_enforces_one_active_approval_per_invocation() -> None:
    assert "active_invocation_id" in APPROVAL_SCHEMA_DDL
    assert "GENERATED ALWAYS AS" in APPROVAL_SCHEMA_DDL
    assert "STORED UNIQUE" in APPROVAL_SCHEMA_DDL
    assert "REFERENCES ruhusa_invocations(invocation_id)" in APPROVAL_SCHEMA_DDL
