import click

from cli import config as cfg


@click.command()
def init() -> None:
    """Create .agentguard/ config + rules dir in the current directory."""
    cfg.AGENTGUARD_DIR.mkdir(exist_ok=True)
    cfg.RULES_DIR.mkdir(exist_ok=True)
    if cfg.CONFIG_FILE.exists():
        click.echo(f"{cfg.CONFIG_FILE} already exists, leaving it alone.")
    else:
        cfg.CONFIG_FILE.write_text(cfg.DEFAULT_CONFIG_YAML, encoding="utf-8")
        click.echo(f"Created {cfg.CONFIG_FILE}")
    click.echo(f"Created {cfg.RULES_DIR}/ for custom rule packs (see `agentguard rules add`).")
