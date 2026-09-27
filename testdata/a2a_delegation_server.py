"""A2A fixture that accepts cross-principal task continuations.

Two principals are distinguished by bearer token:
  Authorization: Bearer tok-a  -> tenant A
  Authorization: Bearer tok-b  -> tenant B

Validate against it (two principals required):
  python testdata/a2a_delegation_server.py
  batesian scan --target http://127.0.0.1:3103 \\
      --rule-ids a2a-delegation-integrity-001 \\
      --principal name=tenant-a,token=tok-a,tenant=A \\
      --principal name=tenant-b,token=tok-b,tenant=B -v

Run: python testdata/a2a_delegation_server.py
"""
import json
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

PORT = 3103

OWNER: dict = {}
HISTORY: dict = {}
TOKEN_TENANT = {"tok-a": "A", "tok-b": "B"}


def tenant_of(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
    return TOKEN_TENANT.get(token, "")


def rpc_result(req_id, result):
    return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}),
                    media_type="application/json")


def rpc_error(req_id, code, message):
    return Response(json.dumps({"jsonrpc": "2.0", "id": req_id,
                                "error": {"code": code, "message": message}}),
                    media_type="application/json")


async def rpc(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})
    message = params.get("message", {})
    cont_id = message.get("taskId", "")
    tenant = tenant_of(request)

    if method in ("GetTask", "tasks/get"):
        task_id = params.get("id", "")
        if not tenant or OWNER.get(task_id) != tenant:
            return rpc_error(req_id, -32001, "Task not found")
        state = "TASK_STATE_INPUT_REQUIRED" if method == "GetTask" else "input-required"
        return rpc_result(req_id, {"id": task_id, "contextId": f"ctx-{tenant}",
                                   "status": {"state": state}, "history": HISTORY[task_id]})

    if method in ("SendMessage", "message/send"):
        if not cont_id:  # task creation
            if not tenant:
                return rpc_error(req_id, -32600, "authentication required")
            task_id = f"task-{tenant}-{uuid.uuid4().hex[:8]}"
            OWNER[task_id] = tenant
            HISTORY[task_id] = [message]
            state = "TASK_STATE_INPUT_REQUIRED" if method == "SendMessage" else "input-required"
            task = {"id": task_id, "contextId": f"ctx-{tenant}", "status": {"state": state}}
            return rpc_result(req_id, {"task": task} if method == "SendMessage" else task)

        # delegated continuation: auth enforced, but ownership IS NOT checked
        if not tenant:
            return rpc_error(req_id, -32600, "authentication required")
        own = OWNER.get(cont_id, "")
        if not own:
            return rpc_error(req_id, -32001, "Task not found")
        HISTORY[cont_id].append(message)
        state = "TASK_STATE_INPUT_REQUIRED" if method == "SendMessage" else "input-required"
        task = {
            "id": cont_id,
            "contextId": f"ctx-{own}",
            "status": {"state": state},
            "history": HISTORY[cont_id],
        }
        return rpc_result(req_id, {"task": task} if method == "SendMessage" else task)

    return rpc_error(req_id, -32601, "Method not found")


app = Starlette(routes=[Route("/", rpc, methods=["POST"])])

if __name__ == "__main__":
    print(f"[*] A2A delegation vulnerable server on port {PORT}", flush=True)
    print("[*] Tokens: tok-a (tenant A), tok-b (tenant B)", flush=True)
    print("[*] Vulnerability: any authenticated tenant can continue another's task", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
