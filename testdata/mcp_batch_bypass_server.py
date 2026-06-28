"""
Deliberately vulnerable MCP server for validating:
  - mcp-jsonrpc-batch-bypass-001: authentication is enforced on a single JSON-RPC
    request object but BYPASSED when the same request is wrapped in a one-element
    JSON-RPC batch array (CWE-288, auth bypass via an alternate channel).

initialize is open (capability discovery). tools/list requires a bearer token for
a single request (HTTP 401 without one), but a batch [tools/list] is processed
without any token: the auth gate keys on the top-level method, and a JSON-RPC
batch array has none, so the gate is skipped and every element runs.

JSON-RPC batching was removed in MCP revision 2025-06-18; this fixture emulates a
legacy / non-compliant server that still processes batches.

Validate against it:
  python testdata/mcp_batch_bypass_server.py
  batesian scan --target http://127.0.0.1:7795 \\
      --rule-ids mcp-jsonrpc-batch-bypass-001 -v

Endpoint: http://127.0.0.1:7795/mcp
"""
import json
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7795


def _init_result(req_id):
    return {
        "jsonrpc": "2.0", "id": req_id,
        "result": {
            "protocolVersion": "2025-03-26",
            "serverInfo": {"name": "batch-bypass-lab", "version": "1.0"},
            "capabilities": {"tools": {"listChanged": False}},
        },
    }


def _tools_result(req_id):
    return {
        "jsonrpc": "2.0", "id": req_id,
        "result": {"tools": [
            {"name": "run_query", "description": "Run a database query"},
            {"name": "read_file", "description": "Read a file from disk"},
        ]},
    }


def _dispatch(obj):
    """Dispatch a single request object with no auth check (used for batch
    elements, which is exactly where this server fails to re-apply the gate)."""
    method = obj.get("method", "")
    req_id = obj.get("id")
    if method == "initialize":
        return _init_result(req_id)
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _tools_result(req_id)
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": "method not found"}}


async def mcp_endpoint(request: Request) -> Response:
    raw = await request.body()
    try:
        payload = json.loads(raw)
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
            status_code=400,
        )
    authed = request.headers.get("authorization") is not None

    # VULNERABILITY: the gate below runs only for single objects. A batch array is
    # dispatched element-by-element with no auth check at all.
    if isinstance(payload, list):
        responses = [r for r in (_dispatch(obj) for obj in payload) if r is not None]
        return JSONResponse(responses)

    method = payload.get("method", "")
    req_id = payload.get("id")

    if method == "initialize":
        # Open for capability discovery; mint a session id server-side.
        return JSONResponse(_init_result(req_id), headers={"Mcp-Session-Id": uuid.uuid4().hex})
    if method == "notifications/initialized":
        return Response(status_code=202)
    if method == "tools/list" and not authed:
        # The gate that the batch path fails to apply.
        return JSONResponse(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32001, "message": "Unauthorized"}},
            status_code=401,
        )
    result = _dispatch(payload)
    if result is None:
        return Response(status_code=202)
    return JSONResponse(result)


app = Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["POST"])])

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
