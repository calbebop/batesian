"""
Deliberately vulnerable A2A test server for validating:
  - a2a-wellknown-hostinject-001: reflects X-Forwarded-Host into agent card url
  - a2a-artifact-tamper-001: allows task ID reuse / content overwrite

Run: python testdata/a2a_new_rules_server.py
"""
import json
import sys
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 3101

# Mutable task store — the artifact-tamper vulnerability
tasks: dict = {}


async def agent_card(request: Request) -> Response:
    """
    Reflects X-Forwarded-Host / X-Original-Host / Host into the agent card url.
    This is the host-header injection vulnerability.
    """
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("x-original-host")
        or request.headers.get("host", "localhost:3101")
    )
    card = {
        "name": "Vulnerable Test Agent",
        "description": "Deliberately vulnerable A2A agent for Batesian rule testing",
        "version": "1.0",
        # VULNERABLE: url is constructed from user-supplied headers
        "url": f"http://{host}/",
        "provider": {
            "organization": "Batesian Test",
            "url": f"http://{host}/provider",
        },
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "skills": [
            {"id": "echo", "name": "Echo", "description": "Echo input back"},
        ],
    }
    return Response(json.dumps(card), media_type="application/json")


async def rpc(request: Request) -> Response:
    """
    A2A JSON-RPC endpoint. Allows task ID reuse without checking immutability.
    """
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})

    if method == "tasks/send":
        task_id = params.get("id", f"task-{len(tasks)}")
        message = params.get("message", {})
        parts = message.get("parts", [])
        text = parts[0].get("text", "") if parts else ""

        # VULNERABLE: always overwrite — no immutability check
        tasks[task_id] = text

        result = {
            "id": task_id,
            "state": "completed",
            "message": {
                "role": "agent",
                "parts": [{"type": "text", "text": f"Processed: {text}"}],
            },
        }
        return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}),
                        media_type="application/json")

    if method == "tasks/get":
        task_id = params.get("id", "")
        if task_id not in tasks:
            return Response(json.dumps({"jsonrpc": "2.0", "id": req_id,
                                        "error": {"code": -32001, "message": "Task not found"}}),
                            media_type="application/json")
        text = tasks[task_id]
        result = {
            "id": task_id,
            "state": "completed",
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": text}],
            },
        }
        return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}),
                        media_type="application/json")

    return Response(json.dumps({"jsonrpc": "2.0", "id": req_id,
                                "error": {"code": -32601, "message": "Method not found"}}),
                    media_type="application/json")


app = Starlette(routes=[
    Route("/.well-known/agent-card.json", agent_card, methods=["GET"]),
    Route("/.well-known/agent.json", agent_card, methods=["GET"]),
    Route("/", rpc, methods=["POST"]),
])

if __name__ == "__main__":
    print(f"[*] A2A new-rules vulnerable server on port {PORT}", flush=True)
    print("[*] Vulnerabilities: host-header injection, mutable task artifacts", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
