"""
Deliberately vulnerable A2A server for validating:
  - a2a-jsonrpc-batch-bypass-001: authentication is enforced at the HTTP layer for
    a single JSON-RPC request (HTTP 401) but BYPASSED when the same request is
    wrapped in a one-element JSON-RPC batch array (CWE-288).

A single unauthenticated JSON-RPC request is rejected with HTTP 401. A batch array
is dispatched without any auth check: the gate keys on the top-level request, and
a JSON-RPC batch array has none. A2A does not define batching, so a correct server
should reject the array rather than dispatch it unauthenticated.

The dispatched GetTask / tasks/get returns a TaskNotFound (-32001) application
error for the probe's non-existent id, which is what proves the dispatcher ran
past the auth gate.

Validate against it:
  python testdata/a2a_batch_bypass_server.py
  batesian scan --target http://127.0.0.1:3108 \\
      --rule-ids a2a-jsonrpc-batch-bypass-001 -v

Endpoint: http://127.0.0.1:3108/
"""
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 3108


def _task_not_found(req_id):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32001, "message": "Task not found"}}


async def rpc_endpoint(request: Request) -> Response:
    raw = await request.body()
    try:
        payload = json.loads(raw)
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
            status_code=400,
        )
    authed = request.headers.get("authorization") is not None

    # VULNERABILITY: the HTTP auth gate is enforced only for single request
    # objects. A JSON-RPC batch array is dispatched element-by-element with no
    # auth check at all.
    if isinstance(payload, list):
        return JSONResponse([_task_not_found(obj.get("id")) for obj in payload])

    if not authed:
        return Response(status_code=401)
    return JSONResponse(_task_not_found(payload.get("id")))


app = Starlette(routes=[Route("/", rpc_endpoint, methods=["POST"])])

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
