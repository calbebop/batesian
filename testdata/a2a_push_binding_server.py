"""A2A push-config fixture with configurable task-owner binding.

Two principals by bearer token:
  Authorization: Bearer tok-a -> tenant-a
  Authorization: Bearer tok-b -> tenant-b

Validate (two principals required):
  Use --rule-ids a2a-push-lifecycle-001 for List/Delete checks.
  Use --rule-ids a2a-subscription-scope-001 for task subscription checks.
  python testdata/a2a_push_binding_server.py
  batesian scan --target http://127.0.0.1:3107 --rule-ids a2a-push-binding-001 \\
      --principal name=tenant-a,token=tok-a,tenant=A \\
      --principal name=tenant-b,token=tok-b,tenant=B -v

Run: python testdata/a2a_push_binding_server.py
Set BATESIAN_PUSH_POSTURE=bound for a protected control.
Set BATESIAN_A2A_BINDING=rest for the v1.0 HTTP+JSON subscription fixture.
"""
import json
import os
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

PORT = 3107
BOUND = os.getenv("BATESIAN_PUSH_POSTURE", "vulnerable") == "bound"
BINDING = os.getenv("BATESIAN_A2A_BINDING", "jsonrpc")
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
    if BINDING != "jsonrpc":
        return Response(status_code=404)
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
        return result(req_id, {"id": tid, "contextId": f"ctx-{who}",
                               "status": {"state": "working"}})

    if method in ("GetTask", "tasks/get"):
        tid = params.get("id", "")
        if not who or TASK_OWNER.get(tid) != who:
            return error(req_id, "not task owner")
        return result(req_id, {"id": tid, "contextId": f"ctx-{who}",
                               "status": {"state": "working"}})

    if method in ("SubscribeToTask", "tasks/resubscribe"):
        tid = params.get("id", "")
        owner = TASK_OWNER.get(tid)
        if not owner or not who or (BOUND and owner != who):
            return error(req_id, "Task not found")
        event = {"jsonrpc": "2.0", "id": req_id,
                 "result": {"id": tid, "contextId": f"ctx-{owner}",
                            "status": {"state": "working"}}}
        return Response("data: " + json.dumps(event) + "\n\n",
                        media_type="text/event-stream")

    if method in ("CreateTaskPushNotificationConfig", "tasks/pushNotificationConfig/set"):
        if not who:
            return error(req_id, "authentication required")
        tid = params.get("taskId", "")
        if tid not in TASK_OWNER:
            return error(req_id, "Task not found")
        if BOUND and TASK_OWNER[tid] != who:
            return error(req_id, "not task owner")
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
        if BOUND and TASK_OWNER.get(tid) != who:
            return error(req_id, "not task owner")
        config = PUSH_CFG.get(tid, {}).get(config_id)
        if config is None:
            return error(req_id, "Push config not found")
        response = {"taskId": tid, **config} if v1 else {
            "taskId": tid, "pushNotificationConfig": config}
        return result(req_id, response)

    if method in ("ListTaskPushNotificationConfigs", "tasks/pushNotificationConfig/list"):
        if not who:
            return error(req_id, "authentication required")
        v1 = method == "ListTaskPushNotificationConfigs"
        tid = params.get("taskId" if v1 else "id", "")
        if BOUND and TASK_OWNER.get(tid) != who:
            return error(req_id, "not task owner")
        configs = list(PUSH_CFG.get(tid, {}).values())
        entries = [{"taskId": tid, **config} if v1 else {
            "taskId": tid, "pushNotificationConfig": config} for config in configs]
        return result(req_id, {"configs": entries} if v1 else entries)

    if method in ("DeleteTaskPushNotificationConfig", "tasks/pushNotificationConfig/delete"):
        if not who:
            return error(req_id, "authentication required")
        v1 = method == "DeleteTaskPushNotificationConfig"
        tid = params.get("taskId" if v1 else "id", "")
        config_id = params.get("id" if v1 else "pushNotificationConfigId", "")
        if BOUND and TASK_OWNER.get(tid) != who:
            return error(req_id, "not task owner")
        configs = PUSH_CFG.get(tid, {})
        if config_id not in configs:
            return error(req_id, "Push config not found")
        del configs[config_id]
        return result(req_id, {} if v1 else None)

    return error(req_id, "Method not found")


async def rest_card(request: Request) -> Response:
    if BINDING != "rest":
        return Response(status_code=404)
    base = str(request.base_url).rstrip("/")
    return Response(json.dumps({"supportedInterfaces": [{
        "url": base + "/agent", "protocolBinding": "HTTP+JSON",
        "protocolVersion": "1.0",
    }]}), media_type="application/json")


async def rest_send(request: Request) -> Response:
    global _counter
    if BINDING != "rest":
        return Response(status_code=404)
    who = tenant_of(request)
    if not who:
        return Response(status_code=403)
    _counter += 1
    task_id = f"task-{who}-{_counter}"
    TASK_OWNER[task_id] = who
    task = {"id": task_id, "contextId": f"ctx-{who}",
            "status": {"state": "TASK_STATE_WORKING"}}
    return Response(json.dumps({"task": task}), media_type="application/a2a+json")


async def rest_task(request: Request) -> Response:
    if BINDING != "rest":
        return Response(status_code=404)
    task_id = request.path_params["task_id"]
    owner = TASK_OWNER.get(task_id)
    if not owner or tenant_of(request) != owner:
        return Response(status_code=404)
    task = {"id": task_id, "contextId": f"ctx-{owner}",
            "status": {"state": "TASK_STATE_WORKING"}}
    return Response(json.dumps(task), media_type="application/a2a+json")


async def rest_subscribe(request: Request) -> Response:
    if BINDING != "rest":
        return Response(status_code=404)
    task_id = request.path_params["task_id"]
    owner = TASK_OWNER.get(task_id)
    who = tenant_of(request)
    if not owner or not who or (BOUND and owner != who):
        return Response(status_code=404)
    task = {"id": task_id, "contextId": f"ctx-{owner}",
            "status": {"state": "TASK_STATE_WORKING"}}
    return Response("data: " + json.dumps({"task": task}) + "\n\n",
                    media_type="text/event-stream")


app = Starlette(routes=[
    Route("/", rpc, methods=["POST"]),
    Route("/.well-known/agent-card.json", rest_card, methods=["GET"]),
    Route("/agent/message:send", rest_send, methods=["POST"]),
    Route("/agent/tasks/{task_id}:subscribe", rest_subscribe, methods=["POST"]),
    Route("/agent/tasks/{task_id}", rest_task, methods=["GET"]),
])

if __name__ == "__main__":
    print(f"[*] A2A {BINDING} {os.getenv('BATESIAN_PUSH_POSTURE', 'vulnerable')} server on port {PORT}", flush=True)
    print("[*] Tokens: tok-a (tenant-a), tok-b (tenant-b)", flush=True)
    print("[*] Vulnerable posture leaves push config and subscription access unbound", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
