from __future__ import annotations

from typer.testing import CliRunner

from orchestrator.cli import app


def test_version() -> None:
    r = CliRunner().invoke(app, ["version"])
    assert r.exit_code == 0
    assert "truthgate" in r.stdout


def test_classes_empty_in_m0() -> None:
    r = CliRunner().invoke(app, ["classes"])
    assert r.exit_code == 0


def test_run_smoke() -> None:
    r = CliRunner().invoke(app, ["run", "--target", "https://example.com", "--dry-run"])
    assert r.exit_code == 0
    assert "findings" in r.stdout
