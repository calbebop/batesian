"""
Batesian MCP validation target: OAuth DCR scope escalation (mcp-oauth-dcr-001).

This server implements a deliberately vulnerable OAuth 2.1 Dynamic Client
Registration endpoint (RFC 7591) that:
  - Accepts registrations without an Initial Access Token (no auth required)
  - Echoes back whatever scopes were requested without validation
  - Accepts any redirect URI including localhost and open-redirect targets

Run:
    python testdata/mcp_oauth_dcr_server.py

Endpoints:
    GET  http://localhost:8767/.well-known/oauth-authorization-server
    POST http://localhost:8767/register
"""
import json
import secrets
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


async def oauth_metadata(request: Request) -> JSONResponse:
    base = "http://localhost:8767"
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "scopes_supported": ["tools:read", "resources:read"],
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
    })


async def register_client(request: Request) -> JSONResponse:
    body = await request.json()

    client_id = "batesian-test-" + secrets.token_hex(8)
    client_secret = secrets.token_hex(16)

    requested_scope = body.get("scope", "tools:read")

    return JSONResponse({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": body.get("client_name", "unnamed"),
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "scope": requested_scope,
        "token_endpoint_auth_method": "client_secret_basic",
    }, status_code=201)


routes = [
    Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
    Route("/register", register_client, methods=["POST"]),
]

app = Starlette(routes=routes)

if __name__ == "__main__":
    print("Starting vulnerable OAuth DCR server on http://localhost:8767")
    print("  GET  /.well-known/oauth-authorization-server")
    print("  POST /register  (no auth, accepts any scopes and redirect URIs)")
    uvicorn.run(app, host="127.0.0.1", port=8767)
