"""
Deliberately vulnerable A2A test server for:
  - a2a-security-headers-001: no HTTP security headers returned
  - a2a-registry-poison-001: unauthenticated agent registry registration
  - a2a-circular-delegation-001: accepts tasks/send with deep delegation chains

Run:
    pip install starlette uvicorn
    python testdata/a2a_remaining_rules_server.py

Validate:
    batesian scan --target http://127.0.0.1:7784 \\
        --rule-ids a2a-security-headers-001,a2a-registry-poison-001,a2a-circular-delegation-001
"""

import json
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

AGENT_CARD = {
    "name": "Remaining Rules Test Agent",
    "version": "1.0",
    "url": "http://127.0.0.1:7784/",
    "description": "Test agent for remaining rules validation.",
    "capabilities": {"streaming": False},
    "skills": [{"id": "ping", "name": "Ping", "description": "Responds to pings"}]
}

# In-memory agent registry (vulnerable: no auth)
_registry: list = [
    {"name": "legitimate-agent", "url": "https://agent.example.com", "version": "1.0"}
]


async def agent_card(request: Request) -> JSONResponse:
    # Deliberately omits all security headers (triggers a2a-security-headers-001)
    return JSONResponse(AGENT_CARD)


async def registry(request: Request) -> Response:
    """
    Unauthenticated registry endpoint (triggers a2a-registry-poison-001).
    GET: list registered agents
    POST: register a new agent (no auth required)
    """
    if request.method == "GET":
        return JSONResponse(_registry)

    if request.method == "POST":
        body = await request.body()
        try:
            card = json.loads(body)
        except Exception:
            return JSONResponse({"error": "bad json"}, status_code=400)

        # Accept without any authentication check (vulnerable)
        _registry.append(card)
        return JSONResponse(
            {"id": f"agent-{len(_registry)}", "status": "registered", "agent": card},
            status_code=201
        )

    return Response(status_code=405)


async def a2a_rpc(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})

    method = body.get("method", "")
    req_id = body.get("id")

    if method == "tasks/send":
        params = body.get("params", {})
        config = params.get("configuration", {})

        # Accepts any depth without limit (triggers a2a-circular-delegation-001 depth probe)
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "id": params.get("id", "task-1"),
                "status": {"state": "completed"},
                "acceptedConfig": config  # Echo the config back for visibility
            }
        })

    return JSONResponse({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"}
    })


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


app = Starlette(
    routes=[
        Route("/.well-known/agent.json", agent_card),
        Route("/.well-known/agent-card.json", agent_card),
        Route("/registry", registry, methods=["GET", "POST"]),
        Route("/agents", registry, methods=["GET", "POST"]),
        Route("/", a2a_rpc, methods=["POST", "GET"]),
        Route("/a2a", a2a_rpc, methods=["POST"]),
        Route("/health", health),
    ]
)

if __name__ == "__main__":
    print("Starting a2a_remaining_rules_server on http://127.0.0.1:7784")
    print("Expected rules to fire: a2a-security-headers-001, a2a-registry-poison-001, a2a-circular-delegation-001")
    uvicorn.run(app, host="127.0.0.1", port=7784, log_level="warning")
