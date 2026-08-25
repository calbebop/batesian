"""
Deliberately vulnerable MCP test server for validating:

  mcp-shadow-surface-001: an MCP surface the operator did not aim at. This
  fixture binds TWO listeners:

    port 7807 - the "named target". Serves nothing but 404s, so the scan has
                no protocol surface where it was pointed.
    port 6277 - the shadow listener, an inspector-style proxy that answers an
                unauthenticated initialize and (in the default posture)
                accepts a foreign Origin as well.

Postures:
  shadow-open (default) - 6277 answers initialize without credentials AND
                          accepts the foreign-Origin twin.
                          The rule MUST fire confirmed/high.
  shadow-hardened       - 6277 still answers anonymously, but refuses any
                          request carrying a foreign Origin with 403.
                          The rule MUST fire confirmed/medium.
  none                  - no shadow listener at all; only 7807 runs.
                          The rule MUST stay silent.

The shadow page fingerprints as "MCP Inspector" so the evidence names the
product class. Nothing beyond initialize is ever served: no tool executes,
no session state matters.

Validate against it:
  python testdata/mcp_shadow_surface_server.py                   # shadow-open
  python testdata/mcp_shadow_surface_server.py shadow-hardened   # medium
  python testdata/mcp_shadow_surface_server.py none              # silent

Run: python testdata/mcp_shadow_surface_server.py [posture]
Scan: batesian scan --target http://127.0.0.1:7807 --rule-ids mcp-shadow-surface-001 -v
"""
import json
import sys
import threading

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

MAIN_PORT = 7807
SHADOW_PORT = 6277

FOREIGN_ORIGIN = "dns-rebind.batesian.invalid"


async def main_404(request: Request) -> JSONResponse:
    return JSONResponse({"error": "not found"}, status_code=404)


def handshake_result(rid):
    return {
        "jsonrpc": "2.0", "id": rid,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "inspector-proxy", "version": "1.0"},
        },
    }


async def shadow_endpoint(request: Request) -> JSONResponse:
    if request.app.state.posture == "shadow-hardened":
        origin = request.headers.get("origin", "")
        if origin and FOREIGN_ORIGIN in origin:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": 1,
                 "error": {"code": -32000, "message": "forbidden origin"}},
                status_code=403,
            )
    try:
        rid = (await request.json()).get("id", 1)
    except Exception:
        rid = 1
    return JSONResponse(handshake_result(rid))


async def shadow_page(request: Request) -> HTMLResponse:
    # Fingerprint on purpose: the evidence should name the product class.
    return HTMLResponse("<html><head><title>MCP Inspector</title></head>"
                        "<body>proxy ready</body></html>")


shadow_app = Starlette(routes=[
    Route("/{path:path}", shadow_endpoint, methods=["POST"]),
    Route("/", shadow_page, methods=["GET"]),
])
main_app = Starlette(routes=[Route("/{path:path}", main_404, methods=["GET", "POST"])])


def serve(app, port):
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    posture = sys.argv[1] if len(sys.argv) > 1 else "shadow-open"
    print(f"[*] shadow-surface fixture ({posture}): named target on {MAIN_PORT}, "
          f"shadow listener on {SHADOW_PORT}", flush=True)

    if posture == "none":
        print("[*] shadow listener intentionally not started", flush=True)
    else:
        shadow_app.state.posture = posture
        t = threading.Thread(target=serve, args=(shadow_app, SHADOW_PORT), daemon=True)
        t.start()

    serve(main_app, MAIN_PORT)
