"""
Batesian MCP validation target: unauthenticated resource access (mcp-resources-unauth-001).

This server exposes MCP resources without any authentication, including one that
returns a simulated database connection string containing credentials.

Run:
    python testdata/mcp_unauth_resources_server.py

Endpoint: http://localhost:8766/mcp
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("UnauthResourcesTarget", stateless_http=True, json_response=True)


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
    print("Starting MCP unauthenticated resources server on http://localhost:8766/mcp")
    uvicorn.run(mcp.streamable_http_app(), host="127.0.0.1", port=8766)
