import json

import click

from cli import config as cfg
from core import baseline as baseline_mod
from core.models import ServerSnapshot


@click.group()
def baseline() -> None:
    """Manage the trusted baseline snapshot."""


@baseline.command("save")
def save() -> None:
    """Snapshot the most recent `agentguard scan` result as the trusted baseline."""
    if not cfg.LAST_SCAN_FILE.exists():
        raise click.ClickException("No scan found. Run `agentguard scan <target>` first.")

    data = json.loads(cfg.LAST_SCAN_FILE.read_text(encoding="utf-8"))
    snapshots = [ServerSnapshot.from_dict(d) for d in data]
    baseline_mod.save_baseline(snapshots, cfg.BASELINE_FILE)

    tool_count = sum(len(s.tools) for s in snapshots)
    click.echo(f"Baseline saved to {cfg.BASELINE_FILE} ({tool_count} tool(s) across {len(snapshots)} server(s)).")
