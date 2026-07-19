"""
Deliberately vulnerable MCP test server for validating:
  - mcp-logging-unauth-001: answers logging/setLevel without authentication.

The server advertises the logging capability and dispatches logging/setLevel with
no auth check, so the rule fires its medium/confirmed finding. The probe sends an
invalid level, which this server rejects with -32602 (nothing is changed).

Run: python testdata/mcp_logging_unauth_server.py
"""
import json
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

PORT = 7797

VALID_LEVELS = {
    "debug", "info", "notice", "warning",
    "error", "critical", "alert", "emergency",
}

sessions = {}


async def mcp_endpoint(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})

    def result(res):
        return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}),
                        media_type="application/json")

    def error(code, msg):
        return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}}),
                        media_type="application/json")

    if method == "initialize":
        sid = str(uuid.uuid4())
        sessions[sid] = True
        res = {
            "protocolVersion": params.get("protocolVersion", "2025-03-26"),
            "serverInfo": {"name": "mcp-logging-vuln-server", "version": "1.0"},
            "capabilities": {"logging": {}},
        }
        return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}),
                        media_type="application/json",
                        headers={"Content-Type": "application/json", "Mcp-Session-Id": sid})

    if method == "notifications/initialized":
        return Response(status_code=202)

    # No auth check on logging/setLevel (vulnerable). An invalid level is rejected
    # with -32602 per the spec; a valid level would be accepted with an empty result.
    if method == "logging/setLevel":
        level = params.get("level", "")
        if level not in VALID_LEVELS:
            return error(-32602, f"Invalid params: unknown log level {level!r}")
        return result({})

    return error(-32601, "Method not found")


app = Starlette(routes=[
    Route("/mcp", mcp_endpoint, methods=["POST"]),
    Route("/", mcp_endpoint, methods=["POST"]),
])

if __name__ == "__main__":
    print(f"[*] MCP logging-unauth vulnerable server on port {PORT}", flush=True)
    print("[*] Vulnerability: logging/setLevel answers without authentication", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
