"""
Deliberately vulnerable A2A test server for:
  - a2a-tls-downgrade-001: serves over plain HTTP (no redirect)
  - a2a-capability-inflation-001: accepts tasks/send with undeclared elevated configuration

Run:
    pip install starlette uvicorn
    python testdata/a2a_tls_capinflation_server.py

Validate:
    batesian scan --target http://127.0.0.1:7782 \\
        --rule-ids a2a-tls-downgrade-001,a2a-capability-inflation-001
"""

import json
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

AGENT_CARD = {
    "name": "TLS Downgrade Test Agent",
    "version": "1.0",
    "url": "http://127.0.0.1:7782/",
    "description": "Test agent for TLS and capability inflation rules.",
    "capabilities": {"streaming": False},
    "skills": [{"id": "ping", "name": "Ping", "description": "Responds to pings"}]
}


async def agent_card(request: Request) -> JSONResponse:
    return JSONResponse(AGENT_CARD)


async def a2a_rpc(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, status_code=400)

    method = body.get("method", "")
    req_id = body.get("id")

    if method == "tasks/send":
        params = body.get("params", {})
        config = params.get("configuration", {})

        # Vulnerable: accept ALL configuration without validation and echo back privilege claims
        response_data = {
            "id": params.get("id", "task-1"),
            "status": {"state": "completed"},
        }

        # Echo privilege claims back (confirms acceptance -- triggers capability inflation finding)
        if "permissions" in config:
            response_data["grantedPermissions"] = config["permissions"]
            response_data["note"] = "admin access acknowledged and processed"

        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": response_data})

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
        Route("/", a2a_rpc, methods=["POST", "GET"]),
        Route("/a2a", a2a_rpc, methods=["POST"]),
        Route("/health", health),
    ]
)

if __name__ == "__main__":
    print("Starting a2a_tls_capinflation_server on http://127.0.0.1:7782 (plain HTTP)")
    print("Expected rules to fire: a2a-tls-downgrade-001, a2a-capability-inflation-001")
    uvicorn.run(app, host="127.0.0.1", port=7782, log_level="warning")
