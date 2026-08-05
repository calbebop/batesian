"""
Batesian MCP validation target: era downgrade auth bypass (mcp-era-downgrade-001).

Serves BOTH protocol eras on one endpoint, and enforces its bearer check on the
handshake era only. The stateless 2026-07-28 path was added later and nobody put
the gate on it, which is the mistake this rule looks for and the shape a real
deployment reaches by bolting authorization onto one request path.

This is hand-rolled rather than built on the MCP SDK on purpose: the SDK serves
both eras correctly and applies no authorization at all, so it cannot exhibit the
asymmetry. That also means this rule has no reference implementation to be
validated against, only this fixture.

Run:
    python testdata/mcp_era_downgrade_server.py

Endpoint: http://127.0.0.1:7800/mcp

Expect: mcp-era-downgrade-001 confirms, and the unauth rules stay silent on the
legacy wire while reporting the modern one.
"""
import json

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

PORT = 7800
MODERN = "2026-07-28"
VALID_TOKEN = "Bearer letmein"

TOOLS = [{"name": "echo", "description": "Echoes input"}]


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
    print(f"Starting MCP era-downgrade target on http://127.0.0.1:{PORT}/mcp")
    print(json.dumps({"gated": "2025-06-18 wire", "open": f"{MODERN} wire"}))
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
