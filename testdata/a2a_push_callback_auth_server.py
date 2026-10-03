"""A2A push-auth fixture: unsigned, signed, or nocallback."""
import sys
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
        config = body.get("params", {})
        url = config.get("url", "")
        auth = config.get("authentication", {})
        if auth.get("scheme") != "Bearer" or not auth.get("credentials"):
            return JSONResponse({"error": "missing Bearer authentication"}, status_code=400)
        posture = request.app.state.posture
        if posture != "nocallback" and url:
            def fire():
                time.sleep(0.5)
                headers = {}
                if posture == "signed":
                    headers["Authorization"] = f"Bearer {auth['credentials']}"
                try:
                    httpx.post(url, json={
                        "statusUpdate": {
                            "taskId": "task-cbauth-live",
                            "status": {"state": "TASK_STATE_COMPLETED"},
                        },
                    }, headers=headers, timeout=5)
                except Exception:
                    pass
            threading.Thread(target=fire, daemon=True).start()
        return JSONResponse({
            "jsonrpc": "2.0", "id": rid,
            "result": {"taskId": "task-cbauth-live", "url": url, "authentication": auth},
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
