import shutil
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from cli import config as cfg
from core.detectors.engine import RuleEngine, load_rules_from_file


@click.group()
def rules() -> None:
    """Inspect and extend the active detector rule set."""


@rules.command("list")
def list_rules() -> None:
    """Show every active detector rule and where it came from."""
    try:
        engine = RuleEngine.with_defaults(cfg.RULES_DIR)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    table = Table(title="Active detector rules")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Applies to")
    table.add_column("Source")
    for rule in engine.rules:
        table.add_row(rule.id, rule.name, rule.severity.value, rule.applies_to, rule.source)
    Console().print(table)


@rules.command("add")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def add_rule(file: Path) -> None:
    """Register a custom YAML rule pack under .agentguard/rules/."""
    cfg.RULES_DIR.mkdir(parents=True, exist_ok=True)
    dest = cfg.RULES_DIR / file.name
    shutil.copyfile(file, dest)

    # Validate immediately -- a broken rule pack should fail loudly here,
    # not silently sit in .agentguard/rules/ until it trips up a later scan.
    try:
        load_rules_from_file(dest)
    except ValueError as exc:
        dest.unlink()
        raise click.ClickException(f"rule pack rejected, not installed: {exc}") from exc

    click.echo(f"Added rule pack: {dest}")
