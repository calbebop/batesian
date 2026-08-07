"""
Deliberately vulnerable A2A test server for validating:
  - a2a-card-security-unenforced-001: the AgentCard declares that a Bearer token
    is required (securitySchemes + securityRequirements), but the JSON-RPC
    endpoint serves message/send and tasks/get with no authentication.

The card promises auth; the server does not enforce it, so the rule fires its
high/confirmed finding after an unauthenticated message/send returns a task.

Run: python testdata/a2a_card_security_unenforced_server.py
"""
import json
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 3110
BASE = f"http://127.0.0.1:{PORT}"

AGENT_CARD = {
    "name": "Insecure Research Agent",
    "description": "Declares Bearer auth but does not enforce it",
    "version": "1.0.0",
    "supportedInterfaces": [
        {"url": BASE + "/", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
    ],
    "capabilities": {"streaming": False},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [
        {"id": "research", "name": "Research", "description": "Answers questions", "tags": ["research"]},
    ],
    # The card advertises that callers MUST present a Bearer token...
    "securitySchemes": {
        "bearerAuth": {"httpAuthSecurityScheme": {"scheme": "Bearer", "bearerFormat": "JWT"}},
    },
    # SecurityRequirement is a proto message holding one map field, so a v1.0
    # card nests the scheme names under "schemes" and each maps to a StringList.
    # This fixture previously served [{"bearerAuth": []}], the v0.3 body shape
    # under the v1.0 field name, which no real implementation emits: it was
    # vouching for how the rule happened to parse rather than for the protocol,
    # and it hid the rule naming the proto field as the scheme.
    "securityRequirements": [{"schemes": {"bearerAuth": {"list": ["a2a:invoke"]}}}],
}

tasks = {}


async def agent_card(request: Request) -> Response:
    return JSONResponse(AGENT_CARD)


async def jsonrpc(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})

    def result(res):
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": res})

    def error(code, msg):
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}})

    # ...but no method below checks the Authorization header (vulnerable).
    if method in ("SendMessage", "message/send"):
        tid = "task-" + uuid.uuid4().hex[:8]
        tasks[tid] = {"id": tid, "contextId": "ctx-" + tid, "status": {"state": "submitted"}}
        return result(tasks[tid])

    if method in ("GetTask", "tasks/get"):
        tid = params.get("id", "")
        task = tasks.get(tid)
        if task is None:
            return error(-32001, "Task not found")
        return result(task)

    return error(-32601, "Method not found")


app = Starlette(routes=[
    Route("/.well-known/agent-card.json", agent_card, methods=["GET"]),
    Route("/", jsonrpc, methods=["POST"]),
])

if __name__ == "__main__":
    print(f"[*] A2A card-security-unenforced vulnerable server on port {PORT}", flush=True)
    print("[*] Vulnerability: card declares Bearer auth but message/send is served unauthenticated", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
