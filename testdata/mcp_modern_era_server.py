"""
Batesian MCP era-detection target: a server that speaks the 2026-07-28 revision.

Unlike every other server in this directory, this one is NOT deliberately
vulnerable and no rule fires against it. It exists so era detection
(internal/attack/mcp/era.go) can be checked against a real modern-era server
rather than against the specification alone.

The MCP Python SDK v2 implements 2026-07-28 and still serves every 2025-era
client from the same MCPServer, so this one process answers both a modern
server/discover and a legacy initialize. That is what a real deployment looks
like: the SDK gives you both eras unless you go out of your way, which is why
the legacy rules keep working against current servers.

Requires the MCP Python SDK v2 (`pip install "mcp>=2"`).

Run:
    python testdata/mcp_modern_era_server.py [port]

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
