"""Project-local .agentguard/ config: overrides, custom rules, scan cache."""
from __future__ import annotations

from pathlib import Path

import yaml

AGENTGUARD_DIR = Path(".agentguard")
CONFIG_FILE = AGENTGUARD_DIR / "config.yaml"
RULES_DIR = AGENTGUARD_DIR / "rules"
LAST_SCAN_FILE = AGENTGUARD_DIR / "last_scan.json"
BASELINE_FILE = AGENTGUARD_DIR / "baseline.json"

DEFAULT_CONFIG_YAML = """\
# AgentGuard project config.
# capability_overrides lets you correct the heuristic capability tagger
# (core/capabilities.py) for specific tools it gets wrong.
capability_overrides: {}
"""


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    return yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8")) or {}


def capability_overrides() -> dict[str, list[str]]:
    return load_config().get("capability_overrides", {}) or {}
