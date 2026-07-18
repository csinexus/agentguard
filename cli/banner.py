"""A small visual identity for `agentguard scan`'s table output.

Kept deliberately simple (a styled Panel, not hand-drawn ASCII-art
letters) -- multi-line letter art is easy to misalign across terminal
fonts/widths, where a Panel's border is drawn by Rich itself and always
lines up correctly.
"""
from __future__ import annotations

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


def print_banner(console: Console) -> None:
    body = Text("risk scanning for MCP tool manifests", style="dim italic")
    console.print(
        Panel(
            Align.center(body),
            title="[bold bright_cyan]AGENTGUARD[/]",
            border_style="bright_cyan",
            padding=(0, 2),
        )
    )
