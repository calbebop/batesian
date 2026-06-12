"""
Deliberately vulnerable two-tenant A2A test server for validating:
  - a2a-multitenant-isolation-001: authenticated task lookup is NOT bound to the
    owning tenant, so a valid principal in tenant A can read tenant B's task.

Two tenants are distinguished purely by bearer token:
  Authorization: Bearer tok-a  -> tenant A
  Authorization: Bearer tok-b  -> tenant B

Task creation IS authenticated (an unauthenticated create / read is rejected),
which is what separates this from a fully-open server (a2a-task-idor-001). The
bug is that GetTask returns the task to ANY authenticated tenant, ignoring which
tenant created it.

Validate against it (two principals required):
  python testdata/a2a_multitenant_server.py
  batesian scan --target http://127.0.0.1:3102 \\
      --rule-ids a2a-multitenant-isolation-001 \\
      --principal name=tenant-a,token=tok-a,tenant=A \\
      --principal name=tenant-b,token=tok-b,tenant=B -v

Run: python testdata/a2a_multitenant_server.py
"""
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

PORT = 3102

# task_id -> {"owner": tenant, "history": [...]}
TASKS: dict = {}

TOKEN_TENANT = {"tok-a": "A", "tok-b": "B"}


def tenant_of(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
    return TOKEN_TENANT.get(token, "")


def rpc_result(req_id, result):
    return Response(
        json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}),
        media_type="application/json",
    )


def rpc_error(req_id, code, message):
    return Response(
        json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}),
        media_type="application/json",
    )


async def rpc(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})
    tenant = tenant_of(request)

    if method in ("SendMessage", "message/send"):
        # Creation is authenticated: reject anonymous callers.
        if not tenant:
            return rpc_error(req_id, -32600, "authentication required")
        task_id = f"task-{tenant}-{len([t for t in TASKS.values() if t['owner'] == tenant]) + 1}"
        ctx_id = f"ctx-{tenant}"
        message = params.get("message", {})
        parts = message.get("parts", [])
        text = parts[0].get("text", "") if parts else ""
        TASKS[task_id] = {
            "owner": tenant,
            "contextId": ctx_id,
            "history": [{"role": "user", "parts": [{"text": text}]}],
        }
        return rpc_result(req_id, {"id": task_id, "contextId": ctx_id, "status": "working"})

    if method in ("GetTask", "tasks/get"):
        # Reading is authenticated too -- but NOT bound to the owning tenant.
        if not tenant:
            return rpc_error(req_id, -32600, "authentication required")
        task_id = params.get("id", "")
        task = TASKS.get(task_id)
        if not task:
            return rpc_error(req_id, -32001, "Task not found")
        # VULNERABLE: no check that task["owner"] == tenant.
        return rpc_result(req_id, {
            "id": task_id,
            "contextId": task["contextId"],
            "history": task["history"],
        })

    return rpc_error(req_id, -32601, "Method not found")


app = Starlette(routes=[Route("/", rpc, methods=["POST"])])

if __name__ == "__main__":
    print(f"[*] A2A multi-tenant vulnerable server on port {PORT}", flush=True)
    print("[*] Tokens: tok-a (tenant A), tok-b (tenant B)", flush=True)
    print("[*] Vulnerability: GetTask ignores tenant ownership (cross-tenant read)", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
