"""
Deliberately vulnerable A2A test server for validating:
  - a2a-extension-downgrade-001: the agent card declares an extension as
    REQUIRED, but the server processes SendMessage requests that OMIT the
    A2A-Extensions activation header (fail-open negotiation downgrade,
    CWE-636/757).

The card advertises capabilities.extensions[] with required=true for
  https://ext.example/required-policy/v1
yet messaging is accepted whether or not the client activates it. A fail-closed
server would reject the un-activated request.

This is a static-card + JSON-RPC server; no authentication is involved.

Validate against it:
  python testdata/a2a_extension_downgrade_server.py
  batesian scan --target http://127.0.0.1:3106 --rule-ids a2a-extension-downgrade-001 -v

Run: python testdata/a2a_extension_downgrade_server.py
"""
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 3106
REQUIRED_EXT = "https://ext.example/required-policy/v1"

CARD = {
    "name": "Vulnerable Extension Agent",
    "url": f"http://127.0.0.1:{PORT}/",
    "version": "1.0.0",
    "capabilities": {
        "extensions": [
            {"uri": REQUIRED_EXT, "required": True, "description": "Mandatory policy extension"}
        ]
    },
}


async def card(request: Request) -> JSONResponse:
    return JSONResponse(CARD)


async def rpc(request: Request) -> Response:
    body = await request.json()
    req_id = body.get("id")
    # VULNERABLE: never checks the A2A-Extensions header, so a request that
    # omits the required extension is processed exactly like one that activates it.
    result = {"id": "task-1", "contextId": "ctx-1", "status": "working"}
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})


app = Starlette(routes=[
    Route("/.well-known/agent-card.json", card, methods=["GET"]),
    Route("/", rpc, methods=["POST"]),
])

if __name__ == "__main__":
    print(f"[*] A2A extension-downgrade vulnerable server on port {PORT}", flush=True)
    print(f"[*] Required (but unenforced) extension: {REQUIRED_EXT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
