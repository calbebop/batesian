"""
Deliberately vulnerable MCP test server for validating:

  mcp-vulnerable-version-001: a handshake whose serverInfo names a component
  with published advisories, reporting a version inside the affected range.

Postures:
  vulnerable (default) - identifies as mcp-git 2026.10.19. The rule fires
                         indicators for the older confinement and command
                         execution advisories.
  intermediate         - same product at 2026.10.28. The rule still fires
                         for the November advisories.
  patched              - same product at 2026.11.11. The rule stays silent.
  unknown              - an unrelated custom identity. Nothing in the table
                         matches; the rule MUST stay silent.

The server serves nothing beyond initialize - this rule reads identity only,
so there is no other surface to exercise.

Validate against it:
  python testdata/mcp_vulnerable_version_server.py vulnerable  # fires
  python testdata/mcp_vulnerable_version_server.py intermediate  # fires
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
    "vulnerable": {"name": "mcp-git", "version": "2026.10.19"},
    "intermediate": {"name": "mcp-git", "version": "2026.10.28"},
    "patched": {"name": "mcp-git", "version": "2026.11.11"},
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
    if app.state.posture not in SERVER_INFO:
        sys.exit(f"unknown posture {app.state.posture!r}; expected one of {', '.join(SERVER_INFO)}")
    print(f"[*] MCP vulnerable-version fixture ({app.state.posture}) on port {PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
