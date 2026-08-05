"""
Deliberately vulnerable A2A test server for validating:
  - a2a-push-binding-001: push-notification config operations are authenticated
    but NOT bound to the task's owning principal, so any valid principal can SET
    (webhook hijack) or GET (callback-secret leak) another principal's task push
    config (CWE-639/862/441).

Two principals by bearer token:
  Authorization: Bearer tok-a -> tenant-a
  Authorization: Bearer tok-b -> tenant-b

Messaging and push-config ops require auth (unauthenticated => rejected), which
is what separates this from a no-auth control plane. The bug: set/get of a push
config never checks that the caller owns the task.

Validate (two principals required):
  python testdata/a2a_push_binding_server.py
  batesian scan --target http://127.0.0.1:3107 --rule-ids a2a-push-binding-001 \\
      --principal name=tenant-a,token=tok-a,tenant=A \\
      --principal name=tenant-b,token=tok-b,tenant=B -v

Run: python testdata/a2a_push_binding_server.py
"""
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

PORT = 3107
TOKEN_TENANT = {"tok-a": "tenant-a", "tok-b": "tenant-b"}
TASK_OWNER: dict = {}
PUSH_CFG: dict = {}  # taskId -> {"url", "token"}
_counter = 0


def tenant_of(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
    return TOKEN_TENANT.get(token, "")


def result(req_id, res):
    return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res}),
                    media_type="application/json")


def error(req_id, msg):
    return Response(json.dumps({"jsonrpc": "2.0", "id": req_id,
                                "error": {"code": -32600, "message": msg}}),
                    media_type="application/json")


def push_url(params):
    """Read the callback from the two shapes the protocol defines.

    v0.3 nests it under pushNotificationConfig. v1.0 params ARE a
    TaskPushNotificationConfig, so the callback is a flat `url` alongside taskId
    and token.

    A flat `pushNotificationUrl` used to be accepted here as well. No SDK defines
    that field, a2a-sdk rejects it with -32602, and accepting it meant this
    fixture agreed with the scanner instead of with the protocol.
    """
    cfg = params.get("pushNotificationConfig")
    if isinstance(cfg, dict) and cfg.get("url"):
        return cfg["url"]
    return params.get("url", "")


async def rpc(request: Request) -> Response:
    global _counter
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})
    who = tenant_of(request)

    if method in ("SendMessage", "message/send"):
        if not who:
            return error(req_id, "authentication required")
        _counter += 1
        tid = f"task-{who}-{_counter}"
        TASK_OWNER[tid] = who
        return result(req_id, {"id": tid, "contextId": f"ctx-{who}", "status": "working"})

    if method in ("CreateTaskPushNotificationConfig", "tasks/pushNotificationConfig/set"):
        if not who:
            return error(req_id, "authentication required")
        tid = params.get("taskId", "")
        # VULNERABLE: no check that `who` owns `tid`.
        PUSH_CFG[tid] = {"url": push_url(params), "token": params.get("token", "")}
        return result(req_id, {"taskId": tid, "pushNotificationConfig": PUSH_CFG[tid]})

    if method in ("GetTaskPushNotificationConfig", "tasks/pushNotificationConfig/get"):
        if not who:
            return error(req_id, "authentication required")
        tid = params.get("taskId", "")
        # VULNERABLE: returns another principal's callback URL/token.
        return result(req_id, {"taskId": tid, "pushNotificationConfig": PUSH_CFG.get(tid, {})})

    return error(req_id, "Method not found")


app = Starlette(routes=[Route("/", rpc, methods=["POST"])])

if __name__ == "__main__":
    print(f"[*] A2A push-binding vulnerable server on port {PORT}", flush=True)
    print("[*] Tokens: tok-a (tenant-a), tok-b (tenant-b)", flush=True)
    print("[*] Vulnerability: push config set/get not bound to task owner", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
