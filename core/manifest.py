"""Static scanning of MCP server tool manifests (spec section 1, "in scope").

Two static input shapes are recognized:

1. A raw `tools/list` JSON dump -- either `{"tools": [...]}` or a bare list.
   This is the purely static case: no process is spawned, we just read the
   file.
2. A `claude_desktop_config.json`-style `{"mcpServers": {name: {command,
   args, env}}}` file. These configs never embed tool schemas themselves, so
   turning them into a ServerSnapshot means briefly launching each declared
   server over stdio and calling tools/list -- still "static" in the sense
   that the driving input is a local config file, not `--live <url>`.

A directory is scanned by globbing `*.json` manifests inside it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import capabilities
from core.models import ServerSnapshot, ToolDeclaration


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Real MCP tool names/descriptions are short (a few sentences at most).
# Neither the introspection timeout nor the depth-bounded schema serializer
# cover this: a hostile server can respond well within the RPC timeout with
# a *large* payload (e.g. a multi-MB description), and every downstream
# heuristic (capabilities.py alone runs ~60 regex searches per tool over the
# full description) then pays for that size on every tool, unbounded and
# untimed. Truncating at ingestion -- the one place both the static and
# live/stdio paths funnel through -- bounds worst-case per-tool cost
# regardless of how many oversized tools a server returns.
_MAX_NAME_LENGTH = 500
_MAX_DESCRIPTION_LENGTH = 20_000


def _truncate(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return value[:max_length] + f"...(truncated, {len(value)} chars total)"


def tool_from_raw(raw: dict[str, Any]) -> ToolDeclaration:
    return ToolDeclaration(
        name=_truncate(raw.get("name", "<unnamed>"), _MAX_NAME_LENGTH),
        description=_truncate(raw.get("description", "") or "", _MAX_DESCRIPTION_LENGTH),
        input_schema=raw.get("inputSchema") or raw.get("input_schema") or {},
    )


def _as_raw_tool_list(data: Any) -> list[dict] | None:
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("tools"), list):
        return data["tools"]
    return None


def _as_mcp_servers_config(data: Any) -> dict[str, dict] | None:
    if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
        return data["mcpServers"]
    return None


def _tag_all(tools: list[ToolDeclaration], overrides: dict[str, list[str]] | None) -> None:
    for tool in tools:
        capabilities.tag_tool(tool, overrides)


def parse_manifest_file(path: Path, overrides: dict[str, list[str]] | None = None) -> list[ServerSnapshot]:
    data = json.loads(path.read_text(encoding="utf-8"))

    raw_tools = _as_raw_tool_list(data)
    if raw_tools is not None:
        tools = [tool_from_raw(t) for t in raw_tools]
        _tag_all(tools, overrides)
        return [ServerSnapshot(server_name=path.stem, transport="static", scanned_at=_now_iso(), tools=tools)]

    servers = _as_mcp_servers_config(data)
    if servers is not None:
        from core.introspect import introspect_stdio_sync

        snapshots = []
        for name, server_conf in servers.items():
            command = server_conf.get("command")
            if not command:
                continue
            args = server_conf.get("args", []) or []
            env = server_conf.get("env")
            raw = introspect_stdio_sync(command, args, env)
            tools = [tool_from_raw(t) for t in raw]
            _tag_all(tools, overrides)
            snapshots.append(ServerSnapshot(server_name=name, transport="stdio", scanned_at=_now_iso(), tools=tools))
        return snapshots

    raise ValueError(
        f"{path}: unrecognized manifest format -- expected a raw tools/list JSON dump "
        "({'tools': [...]} or a bare list) or an mcpServers config ({'mcpServers': {...}})"
    )


def parse_manifest_path(path: Path, overrides: dict[str, list[str]] | None = None) -> list[ServerSnapshot]:
    if path.is_dir():
        snapshots: list[ServerSnapshot] = []
        for f in sorted(path.glob("*.json")):
            snapshots.extend(parse_manifest_file(f, overrides))
        return snapshots
    return parse_manifest_file(path, overrides)
