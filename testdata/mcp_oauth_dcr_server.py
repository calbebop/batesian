"""
Batesian MCP validation target: OAuth DCR scope escalation (mcp-oauth-dcr-001).

This server implements a deliberately vulnerable OAuth 2.1 Dynamic Client
Registration endpoint (RFC 7591) that:
  - Accepts registrations without an Initial Access Token (no auth required)
  - Echoes back whatever scopes were requested without validation
  - Accepts any redirect URI including localhost and open-redirect targets

Two postures, selected by the first argument, differing only in whether the server
implements RFC 7592 client management:

    managed     (default) returns registration_client_uri and
                registration_access_token, so a scan can delete the client it
                registered. After a scan, GET /__clients must report 0.
    unmanaged   returns neither, so the client cannot be removed. The scan must
                report that it left one behind rather than staying silent.

Testing what DCR accepts means asking it to accept something, so a scan
necessarily creates clients here. Registrations are tracked (and exposed at
/__clients, which is a validation helper and no part of any OAuth spec) so the
cleanup can be observed rather than assumed.

Run:
    python testdata/mcp_oauth_dcr_server.py managed
    python testdata/mcp_oauth_dcr_server.py unmanaged

Endpoints:
    GET    http://localhost:7788/.well-known/oauth-authorization-server
    POST   http://localhost:7788/register
    DELETE http://localhost:7788/register/{client_id}   (managed posture only)
    GET    http://localhost:7788/__clients              (validation helper)
"""
import json
import secrets
import sys
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route


POSTURES = ("managed", "unmanaged")
POSTURE = sys.argv[1] if len(sys.argv) > 1 else "managed"
# Optional second argument lets the CI harness run the two postures on separate
# ports, so a leaked process from one posture cannot hold the other's port.
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 7788

# client_id -> {client_name, scope, token}. Registrations this server currently holds.
CLIENTS: dict = {}


async def oauth_metadata(request: Request) -> JSONResponse:
    base = f"http://localhost:{PORT}"
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

    # Registrations are tracked so a validator can see whether the scan cleaned up
    # after itself. Testing what DCR accepts means asking it to accept something, so
    # a scan necessarily creates clients here; leaving them would be a scanner
    # changing the state of the system it was pointed at and not changing it back.
    CLIENTS[client_id] = {
        "client_name": body.get("client_name", "unnamed"),
        "scope": requested_scope,
        "token": secrets.token_hex(8),
    }

    result = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": body.get("client_name", "unnamed"),
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "scope": requested_scope,
        "token_endpoint_auth_method": "client_secret_basic",
    }
    if POSTURE == "managed":
        # RFC 7592 client management, which is what lets a client be deleted again.
        base = str(request.base_url).rstrip("/")
        result["registration_client_uri"] = f"{base}/register/{client_id}"
        result["registration_access_token"] = CLIENTS[client_id]["token"]
    return JSONResponse(result, status_code=201)


async def manage_client(request: Request) -> Response:
    """RFC 7592 DELETE. Present only under the `managed` posture."""
    client_id = request.path_params["client_id"]
    record = CLIENTS.get(client_id)
    if record is None:
        return Response(status_code=404)
    if request.headers.get("authorization", "") != f"Bearer {record['token']}":
        # A delete must be authenticated with the registration access token.
        return Response(status_code=401)
    del CLIENTS[client_id]
    return Response(status_code=204)


async def list_clients(request: Request) -> JSONResponse:
    """Validation helper: what is still registered. Not part of any OAuth spec.

    Count this after a scan. Under `managed` it must be empty; under `unmanaged` the
    clients remain, which is the case the scan reports as left behind.
    """
    return JSONResponse({
        "count": len(CLIENTS),
        "clients": [c["client_name"] for c in CLIENTS.values()],
    })


routes = [
    Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
    Route("/register", register_client, methods=["POST"]),
    Route("/register/{client_id}", manage_client, methods=["DELETE"]),
    Route("/__clients", list_clients, methods=["GET"]),
]

app = Starlette(routes=routes)

if __name__ == "__main__":
    if POSTURE not in POSTURES:
        sys.exit(f"unknown posture {POSTURE!r}; expected one of {', '.join(POSTURES)}")
    print(f"Starting vulnerable OAuth DCR server ({POSTURE}) on http://localhost:{PORT}")
    print("  GET  /.well-known/oauth-authorization-server")
    print("  POST /register  (no auth, accepts any scopes and redirect URIs)")
    if POSTURE == "managed":
        print("  DELETE /register/{client_id}  (RFC 7592, needs the registration access token)")
        print("  -> a scan must leave 0 clients behind; check GET /__clients")
    else:
        print("  no RFC 7592 management: a scan CANNOT clean up, and must report that")
    print("  GET  /__clients  (validation helper: what is still registered)")
    uvicorn.run(app, host="127.0.0.1", port=PORT)
