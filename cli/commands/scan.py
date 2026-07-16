import json
from pathlib import Path

import click

from cli import config as cfg
from cli import output
from core import introspect, manifest
from core.detectors.engine import RuleEngine
from core.models import ServerSnapshot


def _run_scan(target: str, live: bool) -> list[ServerSnapshot]:
    overrides = cfg.capability_overrides()

    try:
        if live or introspect.is_url(target):
            if not introspect.is_url(target):
                raise click.ClickException(f"--live requires a http(s) URL, got: {target}")
            snapshots = [introspect.snapshot_from_live(target, overrides)]
        else:
            path = Path(target)
            if not path.exists():
                raise click.ClickException(f"No such file or directory: {target}")
            snapshots = manifest.parse_manifest_path(path, overrides)

        engine = RuleEngine.with_defaults(cfg.RULES_DIR)
        for snap in snapshots:
            for tool in snap.tools:
                tool.risk_flags = engine.run(tool)
    except (introspect.IntrospectionError, ValueError, json.JSONDecodeError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc

    return snapshots


@click.command()
@click.argument("target")
@click.option("--live", is_flag=True, help="Connect directly to TARGET as a live MCP endpoint (tools/list over SSE/HTTP).")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table", help="Output format.")
@click.option(
    "--severity-min",
    type=click.Choice(["info", "low", "high", "critical"]),
    default="info",
    help="Only display flags at or above this severity.",
)
@click.option(
    "--fail-on",
    default="",
    help="Comma-separated severities that cause a non-zero exit code, e.g. critical,high",
)
def scan(target: str, live: bool, fmt: str, severity_min: str, fail_on: str) -> None:
    """Scan a config file, directory, or live MCP endpoint for risky tool declarations."""
    snapshots = _run_scan(target, live)

    cfg.AGENTGUARD_DIR.mkdir(exist_ok=True)
    cfg.LAST_SCAN_FILE.write_text(json.dumps([s.to_dict() for s in snapshots], indent=2), encoding="utf-8")

    output.render_scan(snapshots, fmt, severity_min)

    if fail_on.strip():
        fail_severities = {s.strip() for s in fail_on.split(",") if s.strip()}
        for snap in snapshots:
            for tool in snap.tools:
                for flag in tool.risk_flags:
                    if flag.severity.value in fail_severities:
                        raise SystemExit(1)
