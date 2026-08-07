"""
Batesian MCP validation target: a failure that is not a refusal.

This server has NO authentication, so every unauth rule should fire against it.
What it varies is how its listing methods fail, selected by the second argument:

    ok    every listing returns a result   -> findings, as any open server
    401   every listing returns 401        -> clean, authorization is enforced
    502   every listing returns 502        -> INCONCLUSIVE, nothing was established

The 502 mode is the point. A gateway failure says nothing about authorization, but
the unauth rules gated on `if err != nil || !resp.IsSuccess() { return nil }`,
which lumped 502 in with 401 and reported the surfaces clean. The 401 and 502 runs
produced identical output, so an operator could not tell "this server enforces
auth" from "the scanner could not tell".

Run:
    python testdata/mcp_transient_failure_server.py [port] [ok|401|502]

Endpoint: http://127.0.0.1:7802/mcp

Expect: 502 reports the tools, prompts, resources and logging rules as not tested; 401
reports them clean; ok reports findings. The three must differ from each other.
"""


import sys

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7802
MODE = sys.argv[2] if len(sys.argv) > 2 else "502"
MODES = ("ok", "401", "502")

TOOLS = [{"name": "echo", "description": "Echoes input",
          "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]
PROMPTS = [{"name": "greet", "description": "A prompt template"}]
RESOURCES = [{"uri": "config://database", "name": "database", "mimeType": "text/plain"}]

# logging/setLevel is in here so mcp-logging-unauth-001 is exercised too. Left to
# fall through it answers -32601, which correctly reads as the method being absent,
# so the mode would never reach that rule's gate.
LISTING = {"tools/list": {"tools": TOOLS},
           "prompts/list": {"prompts": PROMPTS},
           "resources/list": {"resources": RESOURCES},
           "logging/setLevel": {}}


async def mcp(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "Parse error"}}, status_code=400)

    method = body.get("method")
    req_id = body.get("id")

    if method == "initialize":
        return JSONResponse(
            {"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "FlakyTarget", "version": "1.0"},
                "capabilities": {"tools": {}, "prompts": {}, "resources": {}, "logging": {}},
            }},
            headers={"Mcp-Session-Id": "flaky-session"},
        )
    if method == "notifications/initialized":
        return JSONResponse({}, status_code=202)

    if method in LISTING:
        if MODE == "502":
            # A gateway failure. Says nothing about authorization.
            return PlainTextResponse("Bad Gateway", status_code=502)
        if MODE == "401":
            # Auth genuinely enforced. Reporting clean here is correct.
            return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                                 "error": {"code": -32001, "message": "Unauthorized"}}, status_code=401)
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": LISTING[method]})

    if method == "resources/read":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "contents": [{"uri": "config://database", "mimeType": "text/plain",
                          "text": "postgresql://admin:hunter2@db.internal:5432/prod"}]}})
    if method == "prompts/get":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "messages": [{"role": "user", "content": {"type": "text", "text": "Hello"}}]}})
    if method == "tools/call":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "result": {"content": [{"type": "text", "text": "ok"}]}})

    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "Method not found"}}, status_code=400)


app = Starlette(routes=[Route("/mcp", mcp, methods=["POST"])])

if __name__ == "__main__":
    if MODE not in MODES:
        sys.exit(f"unknown mode {MODE!r}; expected one of {', '.join(MODES)}")
    print(f"Starting MCP transient-failure target ({MODE}) on http://127.0.0.1:{PORT}/mcp")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
