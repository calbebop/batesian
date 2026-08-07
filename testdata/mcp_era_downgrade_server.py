"""
Batesian MCP validation target: era downgrade auth bypass (mcp-era-downgrade-001).

Two postures, selected by the first argument.

`vulnerable` (the default) serves BOTH protocol eras on one endpoint and enforces
its bearer check on the handshake era only. The stateless 2026-07-28 path was
added later and nobody put the gate on it, which is the mistake this rule looks
for and the shape a real deployment reaches by bolting authorization onto one
request path.

`discovery-only` serves ONE era and gates nothing. It still answers
`server/discover`, which every server must implement whatever era it serves, and
its reply names only handshake-era versions. Any 2026-07-28 request gets a
plain-text HTTP 400 saying the version is not served here. This is the posture a
server built on the Go SDK has when StreamableHTTPOptions.Stateless is left
false, and it is the negative control: taking the discovery answer as a modern
wire made that 400 look like the refused half of an asymmetry, and the rule
reported a critical authorization bypass against a server with no authorization
at all.

This is hand-rolled rather than built on the MCP SDK on purpose: the Python SDK
serves both eras correctly and applies no authorization, so it cannot exhibit the
asymmetry the `vulnerable` posture needs.

Run:
    python testdata/mcp_era_downgrade_server.py [vulnerable|discovery-only]

Endpoint: http://127.0.0.1:7800/mcp

Expect, `vulnerable`: mcp-era-downgrade-001 confirms, and the unauth rules stay
silent on the legacy wire while reporting the modern one.

Expect, `discovery-only`: mcp-era-downgrade-001 stays silent, and the unauth
rules report the one wire that is there, unlabelled.
"""
import json
import sys

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

PORT = 7800
MODERN = "2026-07-28"
VALID_TOKEN = "Bearer letmein"

POSTURES = ("vulnerable", "discovery-only")
POSTURE = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"

TOOLS = [{"name": "echo", "description": "Echoes input"}]

# The versions a handshake-only server names in its DiscoverResult. The modern
# revision is deliberately absent: the server does not serve it.
HANDSHAKE_VERSIONS = ["2025-11-25", "2025-06-18", "2024-11-05"]


def rpc_error(req_id, code, message):
    return JSONResponse(
        {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}},
        status_code=401 if code == -32001 else 400,
    )


async def mcp(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return rpc_error(None, -32700, "Parse error")

    method = body.get("method")
    req_id = body.get("id")
    modern = request.headers.get("mcp-protocol-version") == MODERN
    authorized = request.headers.get("authorization") == VALID_TOKEN

    if POSTURE == "discovery-only":
        # Discovery is answered on every version, and names only what is served.
        if method == "server/discover":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
                "resultType": "complete",
                "supportedVersions": HANDSHAKE_VERSIONS,
                "capabilities": {"tools": {"listChanged": False}},
            }})
        if modern:
            # Not JSON-RPC and not an authorization refusal: the version simply
            # is not served here. This is the Go SDK's wording.
            return PlainTextResponse(
                f'Bad Request: protocol version "{MODERN}" is only supported on '
                "stateless HTTP servers (set StreamableHTTPOptions.Stateless = true)",
                status_code=400,
            )
        return legacy_wire(method, req_id, authorized=True)

    # --- 2026-07-28: stateless, no handshake. The gate was never added here. ---
    if modern:
        if request.headers.get("mcp-method") != method:
            return rpc_error(req_id, -32020, "mcp-method header does not match the body's method")
        params = body.get("params") or {}
        if not isinstance(params.get("_meta"), dict):
            return rpc_error(req_id, -32602, "params._meta is required")

        envelope = {"cacheScope": "private", "resultType": "complete", "ttlMs": 0, "_meta": {}}
        if method == "server/discover":
            envelope["supportedVersions"] = [MODERN]
            envelope["capabilities"] = {"tools": {"listChanged": False}}
        elif method == "tools/list":
            # VULNERABILITY: no authorization check on this wire.
            envelope["tools"] = TOOLS
        else:
            return rpc_error(req_id, -32601, "Method not found")
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": envelope})

    # --- handshake era: the bearer check lives here, and only here. ---
    return legacy_wire(method, req_id, authorized)


def legacy_wire(method, req_id, authorized):
    """The handshake wire. authorized is passed in so the discovery-only posture
    can serve the same wire with nothing gated."""
    if method == "initialize":
        return JSONResponse(
            {"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "era-downgrade-target", "version": "1.0"},
                "capabilities": {"tools": {"listChanged": False}},
            }},
            headers={"Mcp-Session-Id": "era-downgrade-session"},
        )
    if method == "notifications/initialized":
        return JSONResponse({}, status_code=202)
    if method == "tools/list":
        if not authorized:
            return rpc_error(req_id, -32001, "Unauthorized")
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
    return rpc_error(req_id, -32601, "Method not found")


app = Starlette(routes=[Route("/mcp", mcp, methods=["POST"])])

if __name__ == "__main__":
    if POSTURE not in POSTURES:
        sys.exit(f"unknown posture {POSTURE!r}; expected one of {', '.join(POSTURES)}")
    print(f"Starting MCP era-downgrade target ({POSTURE}) on http://127.0.0.1:{PORT}/mcp")
    if POSTURE == "vulnerable":
        print(json.dumps({"gated": "2025-06-18 wire", "open": f"{MODERN} wire"}))
    else:
        print(json.dumps({"served": "2025-06-18 wire", "gated": None,
                          "discovery": HANDSHAKE_VERSIONS}))
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
