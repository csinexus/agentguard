import click

from cli.commands.baseline import baseline
from cli.commands.diff import diff
from cli.commands.init import init
from cli.commands.rules import rules
from cli.commands.scan import scan

SCOPE_NOTE = """
AgentGuard v1 scope

  In scope:
    - Static scanning of MCP server tool manifests
    - Live introspection of running MCP servers (tools/list)
    - Rule-based detection of scope creep, destructive-action risk,
      and known injection patterns
    - Baseline snapshotting + drift detection between scans

  Explicitly NOT in scope (research-grade, not solved by better code):
    - Live behavioral/traffic monitoring for exfiltration
    - ML-based classification of novel prompt injection
    - A community threat-intel database of known-bad servers

  AgentGuard catches the checkable cases against declared tool metadata.
  It is not a claim to catch every attack.

  Trust boundary: scanning an mcpServers-shaped config (e.g.
  claude_desktop_config.json) EXECUTES the command it declares, on this
  machine, unsandboxed, before AgentGuard analyzes anything. Only scan
  configs from sources you'd already trust enough to run directly. See
  SECURITY.md for details.
"""


@click.group(help=f"AgentGuard -- risk scanning for MCP tool manifests.\n\n{SCOPE_NOTE}")
@click.version_option(package_name="agentguard")
def cli() -> None:
    pass


cli.add_command(init)
cli.add_command(scan)
cli.add_command(baseline)
cli.add_command(diff)
cli.add_command(rules)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
