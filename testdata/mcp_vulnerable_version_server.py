"""
Deliberately vulnerable MCP test server for validating:

  mcp-vulnerable-version-001: a handshake whose serverInfo names a component
  with published advisories, reporting a version inside the affected range.

Postures:
  vulnerable (default) - identifies as mcp-server-git 2025.12.17, one patch
                         before the fixed release. The rule MUST fire a high
                         indicator citing CVE-2025-68143.
  patched              - same product at 2025.12.18. The rule MUST stay
                         silent: the range is exclusive of the fix.
  unknown              - an unrelated custom identity. Nothing in the table
                         matches; the rule MUST stay silent.

The server serves nothing beyond initialize - this rule reads identity only,
so there is no other surface to exercise.

Validate against it:
  python testdata/mcp_vulnerable_version_server.py vulnerable  # fires
  python testdata/mcp_vulnerable_version_server.py patched     # silent
  python testdata/mcp_vulnerable_version_server.py unknown     # silent

Run: python testdata/mcp_vulnerable_version_server.py [posture]
Scan: batesian scan --target http://127.0.0.1:7809 --rule-ids mcp-vulnerable-version-001 -v
"""
import sys

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

PORT = 7809

SERVER_INFO = {
    "vulnerable": {"name": "mcp-server-git", "version": "2025.12.17"},
    "patched": {"name": "mcp-server-git", "version": "2025.12.18"},
    "unknown": {"name": "acme-custom-mcp", "version": "1.0.0"},
}


async def jsonrpc(request: Request) -> JSONResponse:
    body = await request.json()
    method = body.get("method")
    rid = body.get("id", 1)

    if method == "initialize":
        info = SERVER_INFO[request.app.state.posture]
        return JSONResponse({
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": info,
            },
        })
    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {}})

    return JSONResponse({"jsonrpc": "2.0", "id": rid,
                         "error": {"code": -32601, "message": "Method not found"}})


app = Starlette(routes=[Route("/", jsonrpc, methods=["POST"]), Route("/mcp", jsonrpc, methods=["POST"])])
app.state.posture = "vulnerable"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        app.state.posture = sys.argv[1]
    print(f"[*] MCP vulnerable-version fixture ({app.state.posture}) on port {PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
