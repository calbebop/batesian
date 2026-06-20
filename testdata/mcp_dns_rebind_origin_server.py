"""
Deliberately vulnerable MCP Streamable HTTP test server for validating:
  - mcp-dns-rebind-origin-001: the server does NOT validate the Origin header, so
    it processes a request carrying a foreign Origin instead of rejecting it with
    HTTP 403. A local/private-bound server is then reachable from a victim's
    browser via DNS rebinding (CWE-350 / CWE-346; the class behind CVE-2025-49596).

Flow the scanner drives:
  - POST {/, /mcp} initialize with no Origin -> 200 + JSON-RPC result (baseline)
  - POST initialize with Origin: https://...invalid -> 200 + result (VULNERABLE;
    a compliant server returns HTTP 403 Forbidden for a present, invalid Origin)

Validate against it:
  python testdata/mcp_dns_rebind_origin_server.py
  batesian scan --target http://127.0.0.1:7794 --rule-ids mcp-dns-rebind-origin-001 -v

Run: python testdata/mcp_dns_rebind_origin_server.py
"""
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7794


async def mcp(request: Request) -> Response:
    body = await request.json()
    req_id = body.get("id")
    method = body.get("method", "")
    # VULNERABLE: the Origin header is never checked; the request is processed
    # regardless of its value (a compliant server returns HTTP 403 for a present,
    # invalid Origin).
    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "rebind-fixture", "version": "1.0"},
            "capabilities": {},
        }})
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})


app = Starlette(routes=[
    Route("/mcp", mcp, methods=["POST"]),
    Route("/", mcp, methods=["POST"]),
])

if __name__ == "__main__":
    print(f"[*] MCP DNS-rebinding (no Origin validation) vulnerable server on port {PORT}", flush=True)
    print("[*] Vulnerability: processes any Origin instead of returning HTTP 403", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
