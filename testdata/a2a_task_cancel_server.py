"""
Deliberately vulnerable A2A server for validating:
  - a2a-task-cancel-idor-001: task cancellation is NOT bound to the task owner.

An unauthenticated cancel is rejected (HTTP 401), but ANY authenticated principal
may cancel ANY task, so principal B can cancel principal A's task (CWE-639). Tasks
stay in a cancelable state until canceled, so the cancel surface is exercisable.

Run with two principals:
  python testdata/a2a_task_cancel_server.py
  batesian scan --target http://127.0.0.1:3109 \\
      --rule-ids a2a-task-cancel-idor-001 \\
      --principal name=a,token=tok-a --principal name=b,token=tok-b -v

Endpoint: http://127.0.0.1:3109/
"""
import itertools
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 3109
TASKS = {}  # task id -> {"state": ..., "owner": <token>}
_counter = itertools.count(1)


def _bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    return auth[len("Bearer "):] if auth.startswith("Bearer ") else ""


async def rpc(request: Request) -> Response:
    raw = await request.body()
    try:
        req = json.loads(raw)
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
            status_code=400,
        )
    method = req.get("method", "")
    rid = req.get("id")
    params = req.get("params") or {}
    tok = _bearer(request)

    def result(res):
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": res})

    def rpc_err(code, msg):
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}})

    if method in ("SendMessage", "message/send"):
        if not tok:
            return Response(status_code=401)
        tid = f"task-{next(_counter)}"
        TASKS[tid] = {"state": "submitted", "owner": tok}
        return result({"id": tid, "contextId": f"ctx-{tid}", "status": {"state": "submitted"}})

    if method in ("CancelTask", "tasks/cancel"):
        if not tok:
            return Response(status_code=401)  # unauthenticated cancel is rejected
        tid = params.get("id", "")
        task = TASKS.get(tid)
        if task is None:
            return rpc_err(-32001, "Task not found")
        # VULNERABILITY: any authenticated principal may cancel any task; the
        # cancel handler does not check that the caller owns the task.
        task["state"] = "canceled"
        return result({"id": tid, "status": {"state": "canceled"}})

    if method in ("GetTask", "tasks/get"):
        tid = params.get("id", "")
        task = TASKS.get(tid)
        if task is None:
            return rpc_err(-32001, "Task not found")
        return result({"id": tid, "contextId": f"ctx-{tid}", "status": {"state": task["state"]}})

    return rpc_err(-32601, "method not found")


app = Starlette(routes=[Route("/", rpc, methods=["POST"])])

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
