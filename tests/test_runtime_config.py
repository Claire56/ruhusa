from __future__ import annotations

import pytest

from ruhusa.config import RuntimeConfig
from ruhusa.errors import ConfigurationError


def test_runtime_config_defaults_are_explicit() -> None:
    config = RuntimeConfig()
    assert config.require_healthy_startup is False
    assert config.fail_on_shutdown_error is True


def test_runtime_config_from_mapping_is_strict() -> None:
    config = RuntimeConfig.from_mapping(
        {
            "require_healthy_startup": True,
            "fail_on_shutdown_error": False,
        }
    )
    assert config.as_dict() == {
        "require_healthy_startup": True,
        "fail_on_shutdown_error": False,
    }


def test_runtime_config_rejects_unknown_keys() -> None:
    with pytest.raises(ConfigurationError, match="unknown runtime configuration"):
        RuntimeConfig.from_mapping({"unknown_option": True})


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("require_healthy_startup", "false"),
        ("require_healthy_startup", 1),
        ("fail_on_shutdown_error", "true"),
        ("fail_on_shutdown_error", 0),
    ],
)
def test_runtime_config_rejects_non_boolean_values(name: str, value) -> None:
    with pytest.raises(ConfigurationError, match="must be a boolean"):
        RuntimeConfig.from_mapping({name: value})
