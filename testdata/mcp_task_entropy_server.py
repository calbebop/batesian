"""
Deliberately vulnerable MCP test server for validating:

  mcp-task-id-entropy-001: task handles minted with a counter instead of a
  random source. The tasks extension lets servers treat handles as bearer
  tokens for stored state, provided they are unguessable - this fixture
  breaks that MUST on purpose.

Postures:
  weak (default) - handles are sequential integers ("100007", "100014", ...).
                   The rule MUST fire the high sequential finding.
  clean          - handles are uuid-shaped hex. The rule MUST stay silent.

Only initialize and a read-only annotated wait tool that returns one handle
per task-augmented call are served. The arguments it receives are never used;
nothing executes.

Validate against it:
  python testdata/mcp_task_entropy_server.py weak    # high finding
  python testdata/mcp_task_entropy_server.py clean   # silent

Run: python testdata/mcp_task_entropy_server.py [posture]
Scan: batesian scan --target http://127.0.0.1:7812 --rule-ids mcp-task-id-entropy-001 -v
"""
import sys
import uuid

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

PORT = 7812

COUNTER = {"n": 100007}


async def jsonrpc(request: Request) -> JSONResponse:
    body = await request.json()
    method = body.get("method")
    rid = body.get("id", 1)

    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "entropy-fixture", "version": "1.0"},
            },
        })
    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {}})
    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
            "name": "wait_a_moment",
            "description": "Waits briefly; safe to run.",
            "annotations": {"readOnlyHint": True},
            "execution": {"taskSupport": "optional"},
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        }]}})
    if method == "tools/call":
        if request.app.state.posture == "weak":
            COUNTER["n"] += 7
            handle = str(COUNTER["n"])
        else:
            handle = str(uuid.uuid4())
        return JSONResponse({
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "task": {"taskId": handle,
                         "status": {"state": "TASK_STATE_WORKING"}},
                "isError": False,
            },
        })

    return JSONResponse({"jsonrpc": "2.0", "id": rid,
                         "error": {"code": -32601, "message": "Method not found"}})


app = Starlette(routes=[Route("/", jsonrpc, methods=["POST"]), Route("/mcp", jsonrpc, methods=["POST"])])
app.state.posture = "weak"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        app.state.posture = sys.argv[1]
    print(f"[*] MCP task-entropy fixture ({app.state.posture}) on port {PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
