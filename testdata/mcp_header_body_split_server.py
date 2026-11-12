"""MCP 2026-07-28 fixture that accepts a mismatched Mcp-Method header.

Run with ``python testdata/mcp_header_body_split_server.py``, then scan
``http://127.0.0.1:7789`` with rule ``mcp-header-body-split-001``. The expected
result is a medium protocol indicator. No gateway policy is modeled here.
"""

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7789
VERSION = "2026-07-28"


async def mcp(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")

    def error(code: int, message: str) -> JSONResponse:
        return JSONResponse(status_code=400, content={
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message},
        })

    if method == "initialize":
        return error(-32022, "UnsupportedProtocolVersion")

    params = body.get("params") or {}
    body_version = (params.get("_meta") or {}).get(
        "io.modelcontextprotocol/protocolVersion"
    )
    if request.headers.get("mcp-protocol-version") != body_version:
        return error(-32020, "HeaderMismatch: MCP-Protocol-Version")
    if body_version != VERSION:
        return error(-32022, "UnsupportedProtocolVersion")
    if not request.headers.get("mcp-method"):
        return error(-32020, "HeaderMismatch: missing Mcp-Method")

    if method == "server/discover":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "supportedVersions": [VERSION],
            "capabilities": {"tools": {}},
        }})
    if method == "tools/list":
        # Deliberately accept Mcp-Method: tools/call with a tools/list body.
        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "result": {"tools": [{"name": "echo", "description": "echo"}]}})
    return JSONResponse(status_code=200, content={
        "jsonrpc": "2.0", "id": req_id,
        "error": {"code": -32601, "message": "Method not found"},
    })


app = Starlette(routes=[Route("/mcp", mcp, methods=["POST"]),
                        Route("/", mcp, methods=["POST"])])

if __name__ == "__main__":
    print(f"MCP header mismatch fixture on port {PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
