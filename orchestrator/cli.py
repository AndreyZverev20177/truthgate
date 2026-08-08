"""CLI Truthgate. `uv run truthgate --help`."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from orchestrator import __version__, registry
from orchestrator.config import Config
from orchestrator.oob import StubOOB
from orchestrator.pipeline import run_pipeline
from orchestrator.scope import load_from_dict
from orchestrator.types import Candidate, ValidatorContext
from orchestrator.worker import StaticWorker

app = typer.Typer(
    name="truthgate",
    help="Truthgate — autonomous offsec AI with a deterministic proof gate.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


@app.command()
def version() -> None:
    """Печатает версию."""
    console.print(f"truthgate {__version__}")


@app.command()
def classes() -> None:
    """Список зарегистрированных валидаторов (пусто в M0)."""
    t = Table("bug_class", "known aliases")
    for cls in registry.known_classes():
        aliases = [k for k, v in registry.ALIASES.items() if v == cls]
        t.add_row(cls, ", ".join(aliases) or "—")
    if not registry.known_classes():
        t.add_row("—", "(валидаторы подключаются в M1)")
    console.print(t)


@app.command()
def run(
    target: str = typer.Option(..., "--target", "-t", help="Base URL цели"),
    scope_file: Path | None = typer.Option(None, "--scope", help="YAML/JSON с scope"),
    candidates_file: Path | None = typer.Option(
        None, "--candidates", help="JSON-список кандидатов от внешнего сканера"
    ),
    dry_run: bool = typer.Option(True, "--dry-run/--allow-destructive"),
    replays: int = typer.Option(3, "--replays"),
) -> None:
    """M0: запускает pipeline на статическом наборе кандидатов."""
    cfg = Config.load()
    _setup_logging(cfg.runtime.log_level)

    scope = None
    if scope_file and scope_file.exists():
        import yaml
        scope = load_from_dict(yaml.safe_load(scope_file.read_text()))

    cands: list[Candidate] = []
    if candidates_file and candidates_file.exists():
        for row in json.loads(candidates_file.read_text()):
            cands.append(Candidate(**row))

    ctx = ValidatorContext(
        target=target,
        replays=replays,
        dry_run=dry_run,
        program_headers={"User-Agent": cfg.runtime.user_agent},
        oob=StubOOB(),
    )

    workers = [StaticWorker(cands)]
    try:
        findings = run_pipeline(workers, ctx, scope=scope)
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]pipeline error:[/] {e}")
        raise typer.Exit(1) from e

    console.print_json(data={"findings": [f.to_dict() for f in findings]})
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    app()
