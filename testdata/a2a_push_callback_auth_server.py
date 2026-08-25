"""
Deliberately vulnerable A2A test server for validating:

  a2a-push-callback-auth-001: an agent that accepts the caller's integrity
  token at push-config registration and then drops it on the way out, so its
  notifications carry nothing receivers can authenticate.

Postures:
  unsigned (default) - the outbound callback POSTs the status JSON with NO
                       X-A2A-Notification-Token header and no token in the
                       body. The rule MUST fire confirmed/high.
  signed             - the callback presents the configured token in the
                       documented header. The rule MUST stay silent: the
                       transport is verifiable.
  nocallback         - registration accepted, no outbound call ever made.
                       The rule MUST report NOT TESTED.

Only the v1.0 two-step wire is served (SendMessage +
CreateTaskPushNotificationConfig). Nothing beyond a status update is ever
sent to the registered URL, and only URLs the scan itself supplied receive
traffic.

Validate against it (batesian starts its local OOB listener automatically):
  python testdata/a2a_push_callback_auth_server.py unsigned    # fires
  python testdata/a2a_push_callback_auth_server.py signed      # silent
  python testdata/a2a_push_callback_auth_server.py nocallback  # not tested

Run: python testdata/a2a_push_callback_auth_server.py [posture]
Scan: batesian scan --target http://127.0.0.1:7810 --rule-ids a2a-push-callback-auth-001 -v
"""
import threading
import time

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

PORT = 7810


async def jsonrpc(request: Request) -> JSONResponse:
    body = await request.json()
    method = body.get("method")
    rid = body.get("id", "1")

    if method == "SendMessage":
        return JSONResponse({
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "id": "task-cbauth-live",
                "contextId": "ctx-cbauth-live",
                "status": {"state": "TASK_STATE_WORKING"},
            },
        })

    if method == "CreateTaskPushNotificationConfig":
        url = body.get("params", {}).get("url", "")
        token = body.get("params", {}).get("token", "")
        posture = request.app.state.posture
        if posture != "nocallback" and url:
            def fire():
                time.sleep(0.5)
                headers = {}
                if posture == "signed":
                    headers["X-A2A-Notification-Token"] = token
                try:
                    httpx.post(url, json={
                        "kind": "status-update",
                        "taskId": "task-cbauth-live",
                        "status": {"state": "TASK_STATE_COMPLETED"},
                    }, headers=headers, timeout=5)
                except Exception:
                    pass
            threading.Thread(target=fire, daemon=True).start()
        return JSONResponse({
            "jsonrpc": "2.0", "id": rid,
            "result": {"taskId": "task-cbauth-live", "url": url, "token": token},
        })

    return JSONResponse({"jsonrpc": "2.0", "id": rid,
                         "error": {"code": -32601, "message": "Method not found"}})


app = Starlette(routes=[Route("/", jsonrpc, methods=["POST"]), Route("/a2a/jsonrpc", jsonrpc, methods=["POST"])])
app.state.posture = "unsigned"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        app.state.posture = sys.argv[1]
    print(f"[*] A2A push callback-auth fixture ({app.state.posture}) on port {PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
