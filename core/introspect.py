"""Live introspection of running MCP servers (spec section 1, "in scope").

Connects to an MCP server -- either by spawning it over stdio (used both for
`--live` stdio configs and for the mcpServers-config case in manifest.py) or
by connecting to an already-running SSE/streamable-HTTP endpoint -- and calls
`tools/list` directly. This is the one place AgentGuard talks MCP protocol;
everything else works on plain ToolDeclaration/ServerSnapshot data.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from core import capabilities
from core.manifest import tool_from_raw  # reuse the same raw-tool -> ToolDeclaration mapping
from core.models import ServerSnapshot, ToolDeclaration

# A misbehaving or nonexistent MCP server should fail a scan quickly and
# legibly rather than hanging it indefinitely.
DEFAULT_TIMEOUT_SECONDS = 15


class IntrospectionError(RuntimeError):
    """Raised when a live/stdio MCP server can't be reached or doesn't speak MCP."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tool_to_raw(tool: Any) -> dict[str, Any]:
    """Convert an mcp.types.Tool into the raw dict shape manifest.py expects."""
    return {
        "name": tool.name,
        "description": tool.description or "",
        "inputSchema": tool.inputSchema or {},
    }


async def _list_tools_via_session(session: ClientSession) -> list[dict[str, Any]]:
    await session.initialize()
    result = await session.list_tools()
    return [_tool_to_raw(t) for t in result.tools]


async def _introspect_stdio(command: str, args: list[str], env: dict[str, str] | None) -> list[dict[str, Any]]:
    params = StdioServerParameters(command=command, args=args, env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            return await _list_tools_via_session(session)


async def _introspect_http_like(url: str) -> list[dict[str, Any]]:
    """Try streamable-HTTP first (the current MCP transport), fall back to SSE."""
    try:
        from mcp.client.streamable_http import streamable_http_client

        async with streamable_http_client(url) as (read, write, _get_session_id):
            async with ClientSession(read, write) as session:
                return await _list_tools_via_session(session)
    except Exception as streamable_exc:
        from mcp.client.sse import sse_client

        try:
            async with sse_client(url) as (read, write):
                async with ClientSession(read, write) as session:
                    return await _list_tools_via_session(session)
        except Exception as sse_exc:
            raise IntrospectionError(
                f"could not reach '{url}' as either streamable-HTTP ({streamable_exc}) "
                f"or SSE ({sse_exc})"
            ) from sse_exc


def introspect_stdio_sync(command: str, args: list[str], env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    try:
        return asyncio.run(asyncio.wait_for(_introspect_stdio(command, args, env), timeout=DEFAULT_TIMEOUT_SECONDS))
    except IntrospectionError:
        raise
    except TimeoutError as exc:
        raise IntrospectionError(
            f"MCP server '{command}' did not respond to tools/list within {DEFAULT_TIMEOUT_SECONDS}s"
        ) from exc
    except OSError as exc:
        raise IntrospectionError(f"could not launch MCP server command '{command}': {exc}") from exc
    except Exception as exc:
        raise IntrospectionError(f"failed to introspect MCP server '{command}': {exc}") from exc


def introspect_live_sync(url: str) -> list[dict[str, Any]]:
    try:
        return asyncio.run(asyncio.wait_for(_introspect_http_like(url), timeout=DEFAULT_TIMEOUT_SECONDS))
    except IntrospectionError:
        raise
    except TimeoutError as exc:
        raise IntrospectionError(f"'{url}' did not respond to tools/list within {DEFAULT_TIMEOUT_SECONDS}s") from exc
    except Exception as exc:
        raise IntrospectionError(f"failed to introspect live MCP endpoint '{url}': {exc}") from exc


def is_url(candidate: str) -> bool:
    return urlparse(candidate).scheme in ("http", "https")


def snapshot_from_live(url: str, overrides: dict[str, list[str]] | None = None) -> ServerSnapshot:
    raw = introspect_live_sync(url)
    tools: list[ToolDeclaration] = [tool_from_raw(t) for t in raw]
    for t in tools:
        capabilities.tag_tool(t, overrides)
    transport = "sse" if not url.rstrip("/").endswith("mcp") else "http"
    return ServerSnapshot(server_name=url, transport=transport, scanned_at=_now_iso(), tools=tools)
