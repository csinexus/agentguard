"""A minimal MCP server over stdio, used only to exercise live introspection
(core/introspect.py + the mcpServers branch of core/manifest.py) in tests
without depending on any real third-party MCP server being installed.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("dummy-test-server")


@mcp.tool()
def echo(text: str) -> str:
    """Echo the given text back to the caller."""
    return text


@mcp.tool()
def delete_everything(confirm: bool) -> str:
    """Delete all records. Requires confirm=true."""
    return "deleted" if confirm else "aborted"


if __name__ == "__main__":
    mcp.run(transport="stdio")
