"""A malicious MCP server fully controls tool names/descriptions returned by
tools/list. Table rendering must not let that content control the terminal:
neither via Rich markup injection (spoofing/hiding findings) nor via raw
ANSI/control-byte injection (which Rich does not sanitize on its own).
"""
from datetime import datetime, timezone

from rich.console import Console

from cli import output
from core.models import Capability, RiskFlag, ServerSnapshot, Severity, ToolDeclaration


def _snapshot_with_tool_name(name: str) -> ServerSnapshot:
    tool = ToolDeclaration(name=name, description="benign", inferred_capabilities=[Capability.READ])
    return ServerSnapshot(
        server_name="attacker_server",
        transport="static",
        scanned_at=datetime.now(timezone.utc).isoformat(),
        tools=[tool],
    )


def _rendered_text(snapshots) -> str:
    console = Console(record=True, width=120, force_terminal=True)
    # render_scan builds its own Console internally for the real CLI path;
    # here we exercise the same cell-construction helpers directly against
    # a recording console so we can inspect exactly what would hit stdout.
    from rich.table import Table

    for snap in snapshots:
        table = Table(title=output._safe_text(snap.server_name), show_lines=True)
        table.add_column("Tool")
        for tool in snap.tools:
            table.add_row(output._safe_text(tool.name))
        console.print(table)
    return console.export_text(styles=False)


def test_rich_markup_in_tool_name_is_not_interpreted():
    payload = "[bold green]totally_safe[/] [dim]nothing to see here[/]"
    rendered = _rendered_text([_snapshot_with_tool_name(payload)])
    # The literal brackets must survive -- if markup were interpreted, they
    # (and the text "nothing to see here") would vanish from the output.
    assert "[bold green]" in rendered
    assert "totally_safe" in rendered


def test_raw_ansi_escape_in_tool_name_is_stripped():
    payload = "evil\x1b[31mFAKE_CRITICAL\x1b[0m_tool"
    rendered = _rendered_text([_snapshot_with_tool_name(payload)])
    assert "\x1b" not in rendered
    assert "FAKE_CRITICAL" in rendered  # text itself is preserved, just not the escape bytes


def test_osc8_hyperlink_payload_in_tool_name_is_neutralized():
    # OSC 8 ... ST is how terminals render clickable hyperlinks; a malicious
    # server could disguise a phishing link as an innocuous tool name.
    payload = "\x1b]8;;https://evil.example/phish\x1b\\click_here\x1b]8;;\x1b\\"
    rendered = _rendered_text([_snapshot_with_tool_name(payload)])
    assert "\x1b" not in rendered
    assert "evil.example" not in rendered or "click_here" in rendered


def test_diff_table_sanitizes_added_tool_names():
    import contextlib
    import io

    from core.baseline import DriftReport, ServerDrift

    payload = "[bold red]FAKE CRITICAL[/] \x1b[31minjected\x1b[0m_tool"
    report = DriftReport(servers_added=[], server_drifts=[ServerDrift(server_name="attacker_server", added_tools=[payload])])

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        output.render_diff(report, fmt="table")
    rendered = buf.getvalue()

    assert "\x1b" not in rendered
    assert "[bold red]" in rendered
    # ESC byte is stripped but the surrounding literal text survives --
    # what's left ("[31m"/"[0m") is inert, not a live escape sequence.
    assert "injected" in rendered and "_tool" in rendered


def test_diff_table_sanitizes_added_server_names():
    import contextlib
    import io

    from core.baseline import DriftReport

    payload = "[bold red]spoofed[/] \x1b[31mserver\x1b[0m"
    report = DriftReport(servers_added=[payload])

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        output.render_diff(report, fmt="table")
    rendered = buf.getvalue()

    assert "\x1b" not in rendered
    assert "[bold red]" in rendered
