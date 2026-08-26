"""
Deliberately vulnerable MCP test server for validating:

  mcp-origin-prefix-bypass-001: an Origin validator implemented as a string
  prefix match. It rejects a fully foreign origin - so a plain DNS-rebinding
  probe reads it as clean - while accepting any origin whose string starts
  with its own, which is exactly what the rule's crafted twins exploit.

Postures:
  prefix (default) - HasPrefix(origin, own-origin) validation. The subdomain
                     craft MUST fire confirmed/high.
  hardened         - parsed scheme+host equality. Every craft MUST be
                     rejected; the rule MUST stay silent.
  open             - no validation at all. The control twin is accepted too,
                     so the rule suppresses itself: that surface belongs to
                     mcp-dns-rebind-origin-001.

Only initialize and notifications are served; this rule is about header
handling, not tool surface.

Validate against it:
  python testdata/mcp_origin_prefix_bypass_server.py prefix    # fires
  python testdata/mcp_origin_prefix_bypass_server.py hardened  # silent
  python testdata/mcp_origin_prefix_bypass_server.py open      # silent

Run: python testdata/mcp_origin_prefix_bypass_server.py [posture]
Scan: batesian scan --target http://127.0.0.1:7811 --rule-ids mcp-origin-prefix-bypass-001 -v
"""
import sys

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

PORT = 7811


async def jsonrpc(request: Request) -> JSONResponse:
    body = await request.json()
    method = body.get("method")
    rid = body.get("id", 1)

    if method == "initialize":
        origin = request.headers.get("origin", "")
        if not request.app.state.origin_allowed(origin):
            return JSONResponse(status_code=403, content={"error": "forbidden origin"})
        return JSONResponse({
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "originpfx-fixture", "version": "1.0"},
            },
        })
    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {}})

    return JSONResponse({"jsonrpc": "2.0", "id": rid,
                         "error": {"code": -32601, "message": "Method not found"}})


def make_allowed(posture):
    def allowed(origin: str) -> bool:
        if posture == "open" or origin == "":
            return True
        # The server's own wire origin as a caller would see it in scripts.
        own = f"http://127.0.0.1:{PORT}"
        if posture == "prefix":
            # VULNERABLE: literal string comparison.
            return origin.startswith(own)
        # hardened: parse and compare components individually.
        from urllib.parse import urlsplit
        parts = urlsplit(origin)
        mine = urlsplit(own)
        return parts.scheme == mine.scheme and parts.netloc.lower() == mine.netloc.lower()
    return allowed


app = Starlette(routes=[Route("/", jsonrpc, methods=["POST"]), Route("/mcp", jsonrpc, methods=["POST"])])
app.state.posture = "prefix"
app.state.origin_allowed = make_allowed("prefix")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        app.state.posture = sys.argv[1]
    app.state.origin_allowed = make_allowed(app.state.posture)
    print(f"[*] MCP origin-prefix-bypass fixture ({app.state.posture}) on port {PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
