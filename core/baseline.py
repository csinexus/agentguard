"""Baseline snapshotting + drift detection (spec section 1, "in scope").

A baseline is just a stored list of ServerSnapshots. `diff_snapshots` compares
a baseline against a fresh scan and reports what changed: servers/tools
added or removed, and for tools present in both, capability and risk-flag
deltas plus whether the raw schema changed at all (via content_hash).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from core.models import RiskFlag, ServerSnapshot, ToolDeclaration


def save_baseline(snapshots: list[ServerSnapshot], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([s.to_dict() for s in snapshots], indent=2), encoding="utf-8")


def load_baseline(path: Path) -> list[ServerSnapshot]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [ServerSnapshot.from_dict(d) for d in data]


@dataclass
class ToolChange:
    name: str
    capabilities_added: list[str] = field(default_factory=list)
    capabilities_removed: list[str] = field(default_factory=list)
    risk_flags_added: list[RiskFlag] = field(default_factory=list)
    risk_flags_removed: list[RiskFlag] = field(default_factory=list)
    schema_changed: bool = False

    @property
    def is_meaningful(self) -> bool:
        return bool(
            self.capabilities_added
            or self.capabilities_removed
            or self.risk_flags_added
            or self.risk_flags_removed
            or self.schema_changed
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "capabilities_added": self.capabilities_added,
            "capabilities_removed": self.capabilities_removed,
            "risk_flags_added": [f.to_dict() for f in self.risk_flags_added],
            "risk_flags_removed": [f.to_dict() for f in self.risk_flags_removed],
            "schema_changed": self.schema_changed,
        }


@dataclass
class ServerDrift:
    server_name: str
    added_tools: list[str] = field(default_factory=list)
    removed_tools: list[str] = field(default_factory=list)
    changed_tools: list[ToolChange] = field(default_factory=list)
    unchanged_tool_count: int = 0

    @property
    def has_drift(self) -> bool:
        return bool(self.added_tools or self.removed_tools or self.changed_tools)

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "added_tools": self.added_tools,
            "removed_tools": self.removed_tools,
            "changed_tools": [c.to_dict() for c in self.changed_tools],
            "unchanged_tool_count": self.unchanged_tool_count,
        }


@dataclass
class DriftReport:
    servers_added: list[str] = field(default_factory=list)
    servers_removed: list[str] = field(default_factory=list)
    server_drifts: list[ServerDrift] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.servers_added or self.servers_removed or any(d.has_drift for d in self.server_drifts))

    def new_risk_flags(self) -> list[tuple[str, str, RiskFlag]]:
        """(server_name, tool_name, flag) for every risk flag newly present vs. baseline."""
        out = []
        for drift in self.server_drifts:
            for change in drift.changed_tools:
                for flag in change.risk_flags_added:
                    out.append((drift.server_name, change.name, flag))
        return out

    def to_dict(self) -> dict:
        return {
            "servers_added": self.servers_added,
            "servers_removed": self.servers_removed,
            "server_drifts": [d.to_dict() for d in self.server_drifts],
            "has_drift": self.has_drift,
        }


def _tool_by_name(tools: list[ToolDeclaration]) -> dict[str, ToolDeclaration]:
    return {t.name: t for t in tools}


def _diff_tool(before: ToolDeclaration, after: ToolDeclaration) -> ToolChange:
    before_caps = {c.value for c in before.inferred_capabilities}
    after_caps = {c.value for c in after.inferred_capabilities}
    before_flags = {(f.rule_id, f.message) for f in before.risk_flags}
    after_flags = {(f.rule_id, f.message) for f in after.risk_flags}

    return ToolChange(
        name=after.name,
        capabilities_added=sorted(after_caps - before_caps),
        capabilities_removed=sorted(before_caps - after_caps),
        risk_flags_added=[f for f in after.risk_flags if (f.rule_id, f.message) not in before_flags],
        risk_flags_removed=[f for f in before.risk_flags if (f.rule_id, f.message) not in after_flags],
        schema_changed=json.dumps(before.input_schema, sort_keys=True) != json.dumps(after.input_schema, sort_keys=True),
    )


def _diff_server(before: ServerSnapshot, after: ServerSnapshot) -> ServerDrift:
    before_tools = _tool_by_name(before.tools)
    after_tools = _tool_by_name(after.tools)

    added = sorted(set(after_tools) - set(before_tools))
    removed = sorted(set(before_tools) - set(after_tools))
    common = sorted(set(after_tools) & set(before_tools))

    changed = []
    unchanged = 0
    for name in common:
        change = _diff_tool(before_tools[name], after_tools[name])
        if change.is_meaningful:
            changed.append(change)
        else:
            unchanged += 1

    return ServerDrift(
        server_name=after.server_name,
        added_tools=added,
        removed_tools=removed,
        changed_tools=changed,
        unchanged_tool_count=unchanged,
    )


def diff_snapshots(baseline: list[ServerSnapshot], current: list[ServerSnapshot]) -> DriftReport:
    before_by_name = {s.server_name: s for s in baseline}
    after_by_name = {s.server_name: s for s in current}

    servers_added = sorted(set(after_by_name) - set(before_by_name))
    servers_removed = sorted(set(before_by_name) - set(after_by_name))
    common_servers = sorted(set(after_by_name) & set(before_by_name))

    drifts = []
    for name in common_servers:
        # content_hash lets us skip a full tool-by-tool diff when nothing changed at all.
        if before_by_name[name].content_hash == after_by_name[name].content_hash:
            continue
        drifts.append(_diff_server(before_by_name[name], after_by_name[name]))

    return DriftReport(servers_added=servers_added, servers_removed=servers_removed, server_drifts=drifts)
