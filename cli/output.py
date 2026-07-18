"""Table/JSON rendering for scan and diff results."""
from __future__ import annotations

import json
import re

import click
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from core.baseline import DriftReport
from core.models import Capability, ServerSnapshot, Severity

_SEVERITY_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "yellow",
    Severity.HIGH: "bold orange3",
    Severity.CRITICAL: "bold red",
}

_CAPABILITY_STYLE = {
    Capability.READ: "green",
    Capability.WRITE: "yellow",
    Capability.DELETE: "bold red",
    Capability.EXECUTE: "bold magenta",
    Capability.NETWORK_EGRESS: "cyan",
    Capability.FINANCIAL: "bold red",
    Capability.AUTH: "bold blue",
}

_TABLE_BOX = box.ROUNDED

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


def _capability_badges(capabilities: list[Capability]) -> Text:
    if not capabilities:
        return Text("-", style="dim")
    out = Text()
    for i, cap in enumerate(capabilities):
        if i:
            out.append(" ")
        out.append(f" {cap.value} ", style=f"{_CAPABILITY_STYLE[cap]} reverse")
    return out


def render_scan(snapshots: list[ServerSnapshot], fmt: str, severity_min: str) -> None:
    if fmt == "json":
        click.echo(json.dumps([s.to_dict() for s in snapshots], indent=2))
        return

    from cli.banner import print_banner

    min_rank = Severity(severity_min).rank
    console = Console()
    print_banner(console)

    severity_counts: dict[Severity, int] = {s: 0 for s in Severity}
    tool_count = 0

    for snap in snapshots:
        title = Text()
        title.append_text(_safe_text(snap.server_name))
        title.append_text(Text.from_markup(f"  [dim]({snap.transport})[/]"))
        table = Table(title=title, show_lines=True, box=_TABLE_BOX, header_style="bold cyan", title_style="bold")
        table.add_column("Tool", style="bold")
        table.add_column("Capabilities")
        table.add_column("Risk flags")
        for tool in snap.tools:
            tool_count += 1
            for flag in tool.risk_flags:
                severity_counts[flag.severity] += 1
            table.add_row(_safe_text(tool.name), _capability_badges(tool.inferred_capabilities), _flag_text(tool.risk_flags, min_rank))
        console.print(table)

    _print_summary(console, severity_counts, tool_count)


def _print_summary(console: Console, severity_counts: dict[Severity, int], tool_count: int) -> None:
    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.LOW, Severity.INFO):
        count = severity_counts.get(sev, 0)
        if count:
            parts.append(f"[{_SEVERITY_STYLE[sev]}]{count} {sev.value}[/]")
    summary = ", ".join(parts) if parts else "[bold green]0 flags[/]"
    console.print(Text.from_markup(f"\n  {tool_count} tool(s) scanned -- {summary}\n"))


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
        table = Table(title=_safe_text(drift.server_name), show_lines=True, box=_TABLE_BOX, header_style="bold cyan", title_style="bold")
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
