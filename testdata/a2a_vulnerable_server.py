"""
Deliberately vulnerable A2A server for Batesian rule validation.

This server is intentionally misconfigured to be vulnerable to every A2A
attack rule in the scanner. DO NOT deploy this in production.

Vulnerabilities present:
  a2a-extcard-unauth-001   -- extended agent card served without authentication
  a2a-push-ssrf-001        -- push notification callbacks made without URL validation
  a2a-session-smuggle-001  -- role:agent accepted from unauthenticated clients
  a2a-task-idor-001        -- tasks returned to any caller who knows the ID
  a2a-context-orphan-001   -- cross-session context injection not checked
  a2a-peer-impersonation-001 -- bearer tokens accepted without signature validation
  a2a-delegation-escalation-001 -- privileged delegation metadata echoed back
  a2a-json-rpc-fuzz-001    -- unhandled exceptions on malformed input (500s)
  a2a-jws-algconf-001      -- agent card has no JWS signatures

Usage:
  pip install starlette uvicorn httpx
  python testdata/a2a_vulnerable_server.py
"""

import json
import threading
import uuid
import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

PORT = 9998
TASK_STORE: dict = {}


# ---------------------------------------------------------------------------
# Agent card -- no JWS signatures, extended card served without auth
# ---------------------------------------------------------------------------

PUBLIC_CARD = {
    "name": "Vulnerable Test Agent",
    "description": "Deliberately vulnerable A2A agent for Batesian testing",
    "version": "0.0.1",
    "capabilities": {
        "streaming": False,
        "pushNotifications": True,
        "extendedAgentCard": True,
    },
    "supportedInterfaces": [
        {"url": f"http://127.0.0.1:{PORT}", "protocolBinding": "JSONRPC"}
    ],
    "skills": [{"id": "echo", "name": "Echo", "description": "Echoes input", "tags": ["echo"]}],
}

EXTENDED_CARD = {
    **PUBLIC_CARD,
    "name": "Vulnerable Test Agent - Extended Edition",
    "description": "Full privileged card, authenticated users only (but no auth enforced)",
    "version": "0.0.2",
    "skills": PUBLIC_CARD["skills"] + [
        {
            "id": "admin_skill",
            "name": "Admin Skill",
            "description": "Privileged admin operations -- should require auth",
            "tags": ["admin", "privileged"],
        }
    ],
}


async def agent_card(request: Request) -> Response:
    return JSONResponse(PUBLIC_CARD)


async def extended_agent_card(request: Request) -> Response:
    # Vulnerability: serves extended card without checking Authorization header
    return JSONResponse(EXTENDED_CARD)


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------

async def jsonrpc(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        # Vulnerability: returns 500 on unparseable body instead of -32700
        return Response("Internal Server Error", status_code=500)

    method = body.get("method")
    req_id = body.get("id", 1)
    params = body.get("params", {})

    # Vulnerability: crashes on unexpected types instead of returning -32600
    if not isinstance(method, str):
        raise ValueError(f"method must be string, got {type(method)}")

    if method in ("SendMessage", "message/send"):
        return await handle_send_message(req_id, params)
    elif method in ("GetTask", "tasks/get"):
        return handle_get_task(req_id, params)
    elif method in ("CreateTaskPushNotificationConfig", "tasks/pushNotificationConfig/set"):
        return await handle_push_config(req_id, params)
    elif method == "initialize":
        return handle_initialize(req_id, params)
    elif method == "GetExtendedAgentCard":
        # Extended card also exposed via JSON-RPC -- no auth check
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": EXTENDED_CARD})
    else:
        return jsonrpc_error(req_id, -32601, "Method not found")


async def handle_send_message(req_id, params: dict) -> Response:
    message = params.get("message", {})
    configuration = params.get("configuration", {})

    task_id = str(uuid.uuid4())
    context_id = configuration.get("contextId", str(uuid.uuid4()))

    # Vulnerability: accepts role:agent (integer 2 or string "agent") from clients
    # A2A spec says clients MUST send role 1 (USER) only.
    role = message.get("role", 1)

    # Vulnerability: echoes back delegation metadata from configuration block
    delegation_note = ""
    if configuration.get("role") or configuration.get("permissions"):
        delegation_note = (
            f"Processed with delegation: role={configuration.get('role')}, "
            f"permissions={configuration.get('permissions')}, "
            f"delegatedBy={configuration.get('delegatedBy')}"
        )

    parts = message.get("parts", [])
    text_in = ""
    for p in parts:
        if isinstance(p, dict):
            text_in = p.get("text", "")

    task = {
        "id": task_id,
        "contextId": context_id,
        "status": {"state": "completed"},
        "role_accepted": role,
        "artifacts": [
            {
                "parts": [{"text": f"Echo: {text_in}" + (f"\n{delegation_note}" if delegation_note else "")}]
            }
        ],
    }
    TASK_STORE[task_id] = task

    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": task})


def handle_get_task(req_id, params: dict) -> Response:
    task_id = params.get("id", "")
    # Vulnerability: returns task to any caller, no session/ownership check
    task = TASK_STORE.get(task_id)
    if task is None:
        return jsonrpc_error(req_id, -32602, "Task not found")
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {**task, "history": [
        {"role": 1, "parts": [{"text": "original user message"}]},
        {"role": 2, "parts": [{"text": "agent response with sensitive context"}]},
    ]}})


async def handle_push_config(req_id, params: dict) -> Response:
    config = params.get("pushNotificationConfig", {})
    callback_url = config.get("url", "")

    # Vulnerability: makes outbound HTTP request to caller-supplied URL
    if callback_url:
        def fire_callback():
            try:
                httpx.post(callback_url, json={"event": "task_update", "token": config.get("token", "")}, timeout=5)
            except Exception:
                pass
        threading.Thread(target=fire_callback, daemon=True).start()

    task_id = str(uuid.uuid4())
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"taskId": task_id, "registered": True}})


def handle_initialize(req_id, params: dict) -> Response:
    return JSONResponse({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "vulnerable-test-agent", "version": "0.0.1"},
        },
    })


def jsonrpc_error(req_id, code: int, message: str) -> Response:
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


# ---------------------------------------------------------------------------
# Exception handler -- returns 500 with traceback (vulnerability for fuzz rule)
# ---------------------------------------------------------------------------

async def server_error_handler(request: Request, exc: Exception) -> Response:
    import traceback
    tb = traceback.format_exc()
    return Response(f"Internal Server Error\n{tb}", status_code=500, media_type="text/plain")


# ---------------------------------------------------------------------------
# App wiring
# ---------------------------------------------------------------------------

app = Starlette(
    routes=[
        Route("/.well-known/agent-card.json", agent_card),
        Route("/agent/authenticatedExtendedCard", extended_agent_card),
        Route("/extendedAgentCard", extended_agent_card),
        Route("/", jsonrpc, methods=["POST"]),
    ],
    exception_handlers={500: server_error_handler, Exception: server_error_handler},
)

if __name__ == "__main__":
    print(f"Starting vulnerable A2A server on http://127.0.0.1:{PORT}")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
