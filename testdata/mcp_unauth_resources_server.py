"""
Batesian MCP validation target: unauthenticated resource access (mcp-resources-unauth-001).

This server exposes MCP resources without any authentication, including one that
returns a simulated database connection string containing credentials.

Requires the MCP Python SDK v2 (`pip install "mcp>=2"`), which is what
`pip install mcp` now gives you. v2 renamed FastMCP to MCPServer with no
compatibility alias, so this file does not run on the 1.x line.

Run:
    python testdata/mcp_unauth_resources_server.py

Endpoint: http://localhost:7787/mcp
"""
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("UnauthResourcesTarget")


@mcp.resource("config://database")
def db_config() -> str:
    """Database connection string (should be protected)."""
    return "postgresql://admin:password123@db.internal:5432/prod"


@mcp.resource("config://secrets")
def secrets_config() -> str:
    """Application secrets (should be protected)."""
    return (
        "STRIPE_SECRET_KEY=sk-live-abc123xyz456def789\n"
        "SENDGRID_API_KEY=SG.test_api_key_value_here\n"
        "DATABASE_URL=postgresql://admin:hunter2@db.internal/prod\n"
    )


@mcp.resource("config://app")
def app_config() -> str:
    """General application configuration (less sensitive)."""
    return (
        '{"debug": false, "log_level": "info", '
        '"allowed_origins": ["https://app.example.com"]}'
    )


@mcp.tool()
def ping() -> str:
    """Health check tool."""
    return "pong"


if __name__ == "__main__":
    import uvicorn
    print("Starting MCP unauthenticated resources server on http://localhost:7787/mcp")
    # v2 moved stateless_http and json_response off the constructor and onto the
    # app factory. Both matter here: stateless keeps every probe independent of a
    # session, and JSON responses keep the fixture readable with curl.
    app = mcp.streamable_http_app(json_response=True, stateless_http=True)
    uvicorn.run(app, host="127.0.0.1", port=7787)
