"""
Deliberately vulnerable MCP server for validating:
  - mcp-session-fixation-001: the server ADOPTS a client-supplied Mcp-Session-Id
    at initialize instead of minting one server-side (session fixation, CWE-384).

The server DOES enforce sessions (an unrecognized Mcp-Session-Id is rejected with
HTTP 404, per the Streamable HTTP spec) - which is exactly what separates this
from a server that tracks no sessions at all. The bug is that it trusts a session
id the client dictated at initialize.

Validate against it:
  python testdata/mcp_session_fixation_server.py
  batesian scan --target http://127.0.0.1:7786 \\
      --rule-ids mcp-session-fixation-001 -v

Run: python testdata/mcp_session_fixation_server.py

Endpoint: http://127.0.0.1:7786/mcp
"""
import json
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7786

VALID_SESSIONS: set = set()


def _result(req_id, result, session_id=None):
    headers = {"Mcp-Session-Id": session_id} if session_id else None
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result}, headers=headers)


async def mcp_endpoint(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    supplied = request.headers.get("mcp-session-id", "")

    if method == "initialize":
        # VULNERABLE: adopt the client-supplied session id instead of minting one.
        session_id = supplied or uuid.uuid4().hex
        VALID_SESSIONS.add(session_id)
        return _result(req_id, {
            "protocolVersion": "2025-03-26",
            "serverInfo": {"name": "session-fixation-target", "version": "1.0"},
            "capabilities": {"tools": {}},
        }, session_id=session_id)

    if method == "notifications/initialized":
        return Response(status_code=202)

    # Every other method requires a session the server recognizes.
    if supplied not in VALID_SESSIONS:
        return Response("Unknown session", status_code=404)  # spec-compliant rejection

    if method == "tools/list":
        return _result(req_id, {"tools": [{"name": "echo", "description": "Echo input"}]})

    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "Method not found"}})


app = Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["POST"])])

if __name__ == "__main__":
    print(f"[*] MCP session-fixation vulnerable server on http://127.0.0.1:{PORT}/mcp", flush=True)
    print("[*] Vulnerability: adopts client-supplied Mcp-Session-Id (CWE-384)", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
