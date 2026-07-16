import json
from pathlib import Path

import click

from cli import config as cfg
from cli import output
from core import baseline as baseline_mod
from core.models import ServerSnapshot


@click.command()
@click.option("--against", type=click.Path(path_type=Path), default=None, help="Baseline file to diff against (default: .agentguard/baseline.json).")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--fail-on", default="", help="Comma-separated severities on *newly introduced* flags that cause a non-zero exit.")
def diff(against: Path | None, fmt: str, fail_on: str) -> None:
    """Compare the latest scan against the trusted baseline and show drift."""
    baseline_path = against or cfg.BASELINE_FILE
    if not baseline_path.exists():
        raise click.ClickException(f"No baseline found at {baseline_path}. Run `agentguard baseline save` first.")
    if not cfg.LAST_SCAN_FILE.exists():
        raise click.ClickException("No scan found. Run `agentguard scan <target>` first.")

    before = baseline_mod.load_baseline(baseline_path)
    after_data = json.loads(cfg.LAST_SCAN_FILE.read_text(encoding="utf-8"))
    after = [ServerSnapshot.from_dict(d) for d in after_data]

    report = baseline_mod.diff_snapshots(before, after)
    output.render_diff(report, fmt)

    if fail_on.strip():
        fail_severities = {s.strip() for s in fail_on.split(",") if s.strip()}
        for _server, _tool, flag in report.new_risk_flags():
            if flag.severity.value in fail_severities:
                raise SystemExit(1)
