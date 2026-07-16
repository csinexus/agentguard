"""An intentionally hostile MCP server over stdio, used to stress-test
AgentGuard's introspection + detector + rendering pipeline against a
malicious/misbehaving target: huge payloads, control-character-laden
names, deeply nested schemas, markup-injection attempts, and a large
tool count -- all returned directly from tools/list with no need for
real backing functions (hence the low-level Server API, not FastMCP).
"""
import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.lowlevel import NotificationOptions

server: Server = Server("hostile-test-server")


def _deeply_nested_schema(depth: int) -> dict:
    schema: dict = {"type": "object"}
    cur = schema
    for _ in range(depth):
        cur["properties"] = {"x": {"type": "object"}}
        cur = cur["properties"]["x"]
    return schema


_HOSTILE_TOOLS = [
    types.Tool(
        name="huge_description_tool",
        description="benign prefix " + ("A" * 2_000_000),  # ~2MB description
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="deeply_nested_schema_tool",
        description="Looks normal.",
        # The mcp SDK's own pydantic-based Tool serializer refuses to
        # serialize schemas nested much beyond ~20-49 levels ("Circular
        # reference detected (depth exceeded)") -- so a genuinely
        # SDK-compliant server can't transmit anything deeper than this
        # regardless of what AgentGuard does. AgentGuard's own defense
        # against pathologically deep schemas (core/detectors/engine.py's
        # _MAX_SCHEMA_DEPTH) is exercised directly in
        # tests/test_detectors.py, bypassing this SDK-side ceiling.
        inputSchema=_deeply_nested_schema(15),
    ),
    types.Tool(
        name="control_char_name_\x1b[31mFAKE_CRITICAL\x1b[0m_tool",
        description="Name contains raw ANSI escape bytes.",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="markup_injection_tool",
        description="[bold red]FAKE FINDING[/] injected via description markup",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="unicode_tool_\U0001f600​‮",
        description="Name contains emoji, zero-width space, and a bidi override char.",
        inputSchema={"type": "object", "properties": {}},
    ),
]

_HOSTILE_TOOLS.extend(
    types.Tool(name=f"filler_tool_{i}", description="filler", inputSchema={"type": "object", "properties": {}})
    for i in range(3000)
)


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return _HOSTILE_TOOLS


async def _main() -> None:
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="hostile-test-server",
                server_version="0.0.1",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    anyio.run(_main)
