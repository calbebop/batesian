"""A2A push-config fixture with authentication but no task-owner binding.

Two principals by bearer token:
  Authorization: Bearer tok-a -> tenant-a
  Authorization: Bearer tok-b -> tenant-b

Validate (two principals required):
  python testdata/a2a_push_binding_server.py
  batesian scan --target http://127.0.0.1:3107 --rule-ids a2a-push-binding-001 \\
      --principal name=tenant-a,token=tok-a,tenant=A \\
      --principal name=tenant-b,token=tok-b,tenant=B -v

Run: python testdata/a2a_push_binding_server.py
"""
import json
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

PORT = 3107
TOKEN_TENANT = {"tok-a": "tenant-a", "tok-b": "tenant-b"}
TASK_OWNER: dict = {}
PUSH_CFG: dict = {}  # taskId -> configId -> config
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
        if tid not in TASK_OWNER:
            return error(req_id, "Task not found")
        v1 = method == "CreateTaskPushNotificationConfig"
        config = params if v1 else params.get("pushNotificationConfig") or {}
        config_id = config.get("id") or uuid.uuid4().hex
        stored = {"id": config_id, "url": config.get("url", ""),
                  "token": config.get("token", "")}
        PUSH_CFG.setdefault(tid, {})[config_id] = stored
        response = {"taskId": tid, **stored} if v1 else {
            "taskId": tid, "pushNotificationConfig": stored}
        return result(req_id, response)

    if method in ("GetTaskPushNotificationConfig", "tasks/pushNotificationConfig/get"):
        if not who:
            return error(req_id, "authentication required")
        v1 = method == "GetTaskPushNotificationConfig"
        tid = params.get("taskId" if v1 else "id", "")
        config_id = params.get("id" if v1 else "pushNotificationConfigId", "")
        config = PUSH_CFG.get(tid, {}).get(config_id)
        if config is None:
            return error(req_id, "Push config not found")
        response = {"taskId": tid, **config} if v1 else {
            "taskId": tid, "pushNotificationConfig": config}
        return result(req_id, response)

    return error(req_id, "Method not found")


app = Starlette(routes=[Route("/", rpc, methods=["POST"])])

if __name__ == "__main__":
    print(f"[*] A2A push-binding vulnerable server on port {PORT}", flush=True)
    print("[*] Tokens: tok-a (tenant-a), tok-b (tenant-b)", flush=True)
    print("[*] Vulnerability: push config set/get not bound to task owner", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
