"""Dual-era MCP target for protocol detection tests.

Requires the MCP Python SDK v2 (`pip install "mcp>=2"`). Serves legacy
`initialize` and modern `server/discover` on the same endpoint.

Run: python testdata/mcp_modern_era_server.py [port]
Endpoint: http://127.0.0.1:7799/mcp
"""
import sys

from mcp.server.mcpserver import MCPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7799

mcp = MCPServer("ModernEraTarget", version="0.0.1")


@mcp.tool()
def echo(text: str) -> str:
    """Echo the supplied text back."""
    return f"Echo: {text}"


@mcp.resource("spike://notes")
def notes() -> str:
    """A readable resource, so discovery has a capability to report."""
    return "modern era target"


@mcp.prompt()
def greet(name: str) -> str:
    """A prompt template, so discovery has a capability to report."""
    return f"Hello, {name}"


if __name__ == "__main__":
    import uvicorn

    print(f"Starting MCP modern-era target on http://127.0.0.1:{PORT}/mcp")
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
    )
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
