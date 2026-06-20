"""
Deliberately vulnerable MCP Streamable HTTP test server for validating:
  - mcp-header-body-split-001: the server ENFORCES the presence of the SEP-2243
    Mcp-Method routing header (so it looks SEP-2243-aware), but does NOT validate
    that the header value matches the JSON-RPC body method. A request with
    Mcp-Method: tools/call and body method tools/list is still executed as
    tools/list - a header/body "split-brain" (CWE-444).

A compliant server MUST reject a mismatch with 400 + JSON-RPC error -32020
(-32001 in the original SEP-2243 draft).

Validate against it:
  python testdata/mcp_header_body_split_server.py
  batesian scan --target http://127.0.0.1:7789 --rule-ids mcp-header-body-split-001 -v

Run: python testdata/mcp_header_body_split_server.py
"""
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7789


async def mcp(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    mcp_method = request.headers.get("mcp-method", "")

    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "split-fixture", "version": "1.0"},
            "capabilities": {"tools": {}},
        }})
    if method == "notifications/initialized":
        return Response(status_code=202)
    if method == "tools/list":
        # VULNERABLE: require the header to be PRESENT but ignore its VALUE.
        if not mcp_method:
            return JSONResponse(status_code=400, content={
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32020, "message": "HeaderMismatch: missing Mcp-Method"}})
        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "result": {"tools": [{"name": "echo", "description": "echo"}]}})
    return JSONResponse(status_code=400, content={"jsonrpc": "2.0", "id": req_id,
                        "error": {"code": -32601, "message": "method not found"}})


app = Starlette(routes=[Route("/mcp", mcp, methods=["POST"]), Route("/", mcp, methods=["POST"])])

if __name__ == "__main__":
    print(f"[*] MCP header/body split-brain vulnerable server on port {PORT}", flush=True)
    print("[*] Vulnerability: enforces Mcp-Method presence, ignores its value (SEP-2243)", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
