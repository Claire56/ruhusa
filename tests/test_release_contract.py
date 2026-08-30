from __future__ import annotations

from importlib.metadata import version

import ruhusa


def test_distribution_version_is_v080() -> None:
    assert version("ruhusa") == "0.8.0"


def test_every_declared_root_export_resolves() -> None:
    assert len(ruhusa.__all__) == len(set(ruhusa.__all__))

    for name in ruhusa.__all__:
        assert getattr(ruhusa, name) is not None


def test_optional_integration_types_do_not_leak_into_root_api() -> None:
    assert "FastAPITrustedInvocationAdapter" not in ruhusa.__all__
    assert "PostgresGrantStore" not in ruhusa.__all__
    assert "PostgresExecutionStore" not in ruhusa.__all__


def test_framework_neutral_trusted_integration_stays_namespaced() -> None:
    from ruhusa.integrations import PreparedInvocation, TrustedInvocationFactory

    assert PreparedInvocation is not None
    assert TrustedInvocationFactory is not None
