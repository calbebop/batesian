"""
Deliberately vulnerable MCP server for validating:
  - mcp-secret-canary-001: the server reflects the caller's bearer credential
    verbatim into a JSON-RPC error response. Any sink that records responses
    (logs, traces, error trackers, shared SSE, client console) then exposes the
    secret (CWE-522 / CWE-532 / CWE-200).

A safe server returns a generic auth error that never echoes the presented token.

Validate against it:
  python testdata/mcp_secret_canary_server.py
  batesian scan --target http://127.0.0.1:7792 --rule-ids mcp-secret-canary-001 -v

Run: python testdata/mcp_secret_canary_server.py
"""
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7792


async def mcp(request: Request) -> Response:
    body = await request.json()
    req_id = body.get("id")
    auth = request.headers.get("authorization", "")
    token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
    # VULNERABLE: echo the presented credential straight back into the response.
    return JSONResponse({
        "jsonrpc": "2.0", "id": req_id,
        "error": {"code": -32000, "message": f"authentication failed for token: {token}"},
    })


app = Starlette(routes=[Route("/mcp", mcp, methods=["POST"]), Route("/", mcp, methods=["POST"])])

if __name__ == "__main__":
    print(f"[*] MCP secret-canary vulnerable server on port {PORT}", flush=True)
    print("[*] Vulnerability: reflects the presented bearer token into error responses", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
