"""Table/JSON rendering for scan and diff results."""
from __future__ import annotations

import json
import re

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from core.baseline import DriftReport
from core.models import ServerSnapshot, Severity

_SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "yellow",
    Severity.HIGH: "bold orange3",
    Severity.CRITICAL: "bold red",
}

# Tool names (and server names derived from them) come straight from
# whatever MCP server is being scanned -- fully attacker-controlled. Two
# separate risks if rendered as raw markup strings:
#   1. Rich markup injection: "[bold red]FAKE CRITICAL[/]" in a tool name
#      would be *styled*, letting a malicious server spoof or bury findings.
#   2. Raw ANSI/control-character injection: Rich does not strip literal
#      control bytes (e.g. ESC) from plain text, so they pass straight to
#      the terminal -- which can hide/rewrite prior output or, on terminals
#      that support OSC 8, render an invisible phishing hyperlink.
# _safe_text() neutralizes both: strip control chars, then wrap in Text()
# so Rich renders it as literal content instead of parsing it as markup.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _safe_text(value: str) -> Text:
    return Text(_CONTROL_CHARS_RE.sub("", value))


def _flag_text(flags, min_rank: int) -> Text:
    shown = [f for f in flags if f.severity.rank >= min_rank]
    if not shown:
        return Text("-")
    out = Text()
    for i, f in enumerate(shown):
        if i:
            out.append("\n")
        style = _SEVERITY_STYLE[f.severity]
        # rule_id/message come from rule *definitions* (built-in or a rule
        # pack the user explicitly installed), never from the scanned
        # target, so these are trusted enough to render as markup.
        out.append_text(Text.from_markup(f"[{style}]{f.severity.value.upper():<8}[/] {f.rule_id} {f.message}"))
    return out


def render_scan(snapshots: list[ServerSnapshot], fmt: str, severity_min: str) -> None:
    if fmt == "json":
        click.echo(json.dumps([s.to_dict() for s in snapshots], indent=2))
        return

    min_rank = Severity(severity_min).rank
    console = Console()
    for snap in snapshots:
        title = Text()
        title.append_text(_safe_text(snap.server_name))
        title.append_text(Text.from_markup(f"  [dim]({snap.transport})[/]"))
        table = Table(title=title, show_lines=True)
        table.add_column("Tool", style="bold")
        table.add_column("Capabilities")
        table.add_column("Risk flags")
        for tool in snap.tools:
            caps = ", ".join(c.value for c in tool.inferred_capabilities) or "-"
            table.add_row(_safe_text(tool.name), caps, _flag_text(tool.risk_flags, min_rank))
        console.print(table)


def _joined_safe_text(values: list[str]) -> Text:
    out = Text()
    for i, v in enumerate(values):
        if i:
            out.append(", ")
        out.append_text(_safe_text(v))
    return out


def render_diff(report: DriftReport, fmt: str) -> None:
    if fmt == "json":
        click.echo(json.dumps(report.to_dict(), indent=2))
        return

    console = Console()
    if not report.has_drift:
        console.print("[green]No drift detected against baseline.[/]")
        return

    if report.servers_added:
        line = Text.from_markup("[bold green]+ servers added:[/] ")
        line.append_text(_joined_safe_text(report.servers_added))
        console.print(line)
    if report.servers_removed:
        line = Text.from_markup("[bold red]- servers removed:[/] ")
        line.append_text(_joined_safe_text(report.servers_removed))
        console.print(line)

    for drift in report.server_drifts:
        if not drift.has_drift:
            continue
        table = Table(title=_safe_text(drift.server_name), show_lines=True)
        table.add_column("Change")
        table.add_column("Tool")
        table.add_column("Detail")

        for name in drift.added_tools:
            table.add_row(Text.from_markup("[green]+ added[/]"), _safe_text(name), "-")
        for name in drift.removed_tools:
            table.add_row(Text.from_markup("[red]- removed[/]"), _safe_text(name), "-")
        for change in drift.changed_tools:
            lines: list[Text] = []
            if change.capabilities_added:
                lines.append(Text(f"+capabilities: {', '.join(change.capabilities_added)}"))
            if change.capabilities_removed:
                lines.append(Text(f"-capabilities: {', '.join(change.capabilities_removed)}"))
            for f in change.risk_flags_added:
                style = _SEVERITY_STYLE[f.severity]
                lines.append(Text.from_markup(f"[{style}]+flag {f.rule_id}[/] {f.message}"))
            for f in change.risk_flags_removed:
                lines.append(Text(f"-flag {f.rule_id} {f.message}"))
            if change.schema_changed:
                lines.append(Text("input_schema changed"))

            details = Text("-") if not lines else Text("\n").join(lines)
            table.add_row(Text.from_markup("[yellow]~ changed[/]"), _safe_text(change.name), details)

        console.print(table)
        if drift.unchanged_tool_count:
            console.print(f"[dim]{drift.unchanged_tool_count} unchanged tool(s) omitted[/]")
