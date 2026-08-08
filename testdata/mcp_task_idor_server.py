"""
Deliberately vulnerable MCP test server for validating:
  - mcp-task-idor-001: MCP 2025-11-25 tasks are not bound to the authorization
    context that created them.

Postures:
  - "vulnerable" (default): authentication is enforced on task creation, but no
    scoping is applied to tasks/get, tasks/result or tasks/list, so any
    authenticated session can read another session's task and its result.
  - "create-open": task creation needs no credentials, while the read methods
    still require a Bearer token and are still unscoped. Authentication is
    enforced on the surface the rule tests, so the cross-context read is still
    an authorization failure and must still be reported.

Run: python testdata/mcp_task_idor_server.py [posture]
"""
import json
import sys
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

PORT = 7798

POSTURES = ("vulnerable", "create-open")
POSTURE = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"

# taskId -> {"owner": session_id, "topic": str}
TASKS = {}

TOOL = {
    "name": "research",
    "description": "Long running research query",
    # Task augmentation is required for this tool.
    "execution": {"taskSupport": "required"},
    # Declared non-destructive, so the scanner is willing to invoke it.
    "annotations": {"readOnlyHint": False, "destructiveHint": False},
    "inputSchema": {
        "type": "object",
        "properties": {"topic": {"type": "string", "description": "Research topic"}},
    },
}


async def mcp_endpoint(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})
    sid = request.headers.get("mcp-session-id", "")
    authed = request.headers.get("authorization", "").startswith("Bearer ")

    def result(res, headers=None):
        return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}),
                        media_type="application/json", headers=headers or {})

    def error(code, msg):
        return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}}),
                        media_type="application/json")

    if method == "initialize":
        new_sid = str(uuid.uuid4())
        return result({
            "protocolVersion": "2025-11-25",
            "serverInfo": {"name": "mcp-task-idor-vuln-server", "version": "1.0"},
            "capabilities": {
                "tools": {},
                "tasks": {
                    "list": {},
                    "cancel": {},
                    "requests": {"tools": {"call": {}}},
                },
            },
        }, headers={"Content-Type": "application/json", "Mcp-Session-Id": new_sid})

    if method == "notifications/initialized":
        return Response(status_code=202)

    if method == "tools/list":
        return result({"tools": [TOOL]})

    if method == "tools/call":
        if "task" not in params:
            return error(-32600, "Task augmentation required for this tool")
        # Under the default posture authentication is enforced here. Under
        # create-open it is not, and the read methods below carry the boundary.
        if POSTURE != "create-open" and not authed:
            return Response(status_code=401)
        tid = uuid.uuid4().hex
        TASKS[tid] = {"owner": sid, "topic": params.get("arguments", {}).get("topic", "")}
        return result({"task": {
            "taskId": tid, "status": "working", "statusMessage": "Gathering sources...",
            "createdAt": "2026-07-20T07:00:00Z", "lastUpdatedAt": "2026-07-20T07:00:00Z",
            "ttl": 60000, "pollInterval": 500,
        }})

    # Under create-open the read methods are the only authenticated surface, so
    # an anonymous caller must be refused here even though creation was open.
    if POSTURE == "create-open" and method in ("tasks/get", "tasks/result", "tasks/list") and not authed:
        return error(-32001, "Unauthorized")

    # Vulnerable: neither of the following checks the requesting session against
    # the task's owner, so any caller holding a task id can read it.
    if method == "tasks/get":
        tid = params.get("taskId", "")
        if tid not in TASKS:
            return error(-32602, "Failed to retrieve task: Task not found")
        return result({
            "taskId": tid, "status": "completed", "statusMessage": "Research complete",
            "createdAt": "2026-07-20T07:00:00Z", "lastUpdatedAt": "2026-07-20T07:00:04Z", "ttl": 60000,
        })

    if method == "tasks/result":
        tid = params.get("taskId", "")
        if tid not in TASKS:
            return error(-32602, "Task not found: " + tid)
        topic = TASKS[tid]["topic"]
        return result({
            "content": [{"type": "text", "text": f"CONFIDENTIAL research report on {topic!r}: internal findings."}],
            "isError": False,
            "_meta": {"io.modelcontextprotocol/related-task": {"taskId": tid}},
        })

    # Vulnerable: the list is not filtered to the requesting session either, so a
    # caller can enumerate every task on the server without knowing any task id.
    if method == "tasks/list":
        return result({"tasks": [
            {"taskId": t, "status": "completed", "createdAt": "2026-07-20T07:00:00Z"}
            for t in TASKS
        ]})

    return error(-32601, "Method not found")


app = Starlette(routes=[
    Route("/mcp", mcp_endpoint, methods=["POST"]),
    Route("/", mcp_endpoint, methods=["POST"]),
])

if __name__ == "__main__":
    if POSTURE not in POSTURES:
        sys.exit(f"unknown posture {POSTURE!r}; expected one of {', '.join(POSTURES)}")
    print(f"[*] MCP task-IDOR vulnerable server ({POSTURE}) on port {PORT}", flush=True)
    print("[*] Vulnerability: tasks/get and tasks/result are not scoped to the creating session", flush=True)
    if POSTURE == "create-open":
        print("[*] Task creation is open; the read methods require a Bearer token", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
