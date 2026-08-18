"""E2E тест `truthgate validators list` — регистрация валидаторов SQLi/XSS/SSRF."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from orchestrator.cli import app
from tools import validators as _validators_pkg  # noqa: F401 — sideeffect
from tools.core.vulnerability_class import VulnerabilityClass
from tools.validators import registry
from tools.validators.sqli import SQLiValidator
from tools.validators.ssrf import SSRFValidator
from tools.validators.xss import XSSValidator

pytestmark = pytest.mark.integration


@pytest.fixture
def _register_all() -> None:
    registry.register(VulnerabilityClass.SQLI)(SQLiValidator)
    registry.register(VulnerabilityClass.XSS)(XSSValidator)
    registry.register(VulnerabilityClass.SSRF)(SSRFValidator)


def test_registry_returns_sqli_xss_ssrf(_register_all: None) -> None:
    assert isinstance(registry.get(VulnerabilityClass.SQLI), SQLiValidator)
    assert isinstance(registry.get(VulnerabilityClass.XSS), XSSValidator)
    assert isinstance(registry.get(VulnerabilityClass.SSRF), SSRFValidator)


def test_cli_validators_list_prints_sqli_xss_ssrf(_register_all: None) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["validators", "list"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "sqli" in out
    assert "xss" in out
    assert "ssrf" in out
    assert "sqli_boolean_v1" in out
    assert "xss_reflection_v1" in out
    assert "ssrf_oob_v1" in out
