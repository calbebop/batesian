"""
Batesian MCP validation target: responses larger than the scanner's read limit.

This server is deliberately vulnerable in the ordinary way: it has NO
authentication, so every unauth rule should fire against it exactly as it would
against any other open server. The only unusual thing about it is response size.
Every listing and read is padded past the scanner's body read limit.

That size is the whole point. The limit used to be 1 MB and the read truncated
silently, so a truncated JSON-RPC result was unparseable, and rules that treat an
unparseable probe the same as a refused one reported those surfaces clean. A
server could hide every unauthenticated-access finding by being large.

Measured against this fixture at 1.33 MB responses: 1 finding before, 7 after.
The same server with small responses gives 7 either way, which is what makes size
the only variable.

1 MB is not a large response. A tools/list on a server with a few hundred tools,
or a resources/read of a config file, exceeds it without trying.

Run:
    python testdata/mcp_large_body_server.py [port] [size_kb]

Endpoint: http://127.0.0.1:7801/mcp

Expect: the same findings a small open server produces, notably
mcp-tools-unauth-001, mcp-prompt-unauth-001 and mcp-resources-unauth-001,
including the critical credential read. Any of those going silent means a body
was truncated somewhere.
"""
import json
import sys

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7801
# Default comfortably past the old 1 MB limit and well under the current one.
SIZE_KB = int(sys.argv[2]) if len(sys.argv) > 2 else 1200

# The padding carries a credential, so the credential-detection path is exercised
# at the same size as everything else.
PAD = "postgresql://admin:hunter2@db.internal:5432/prod " + ("x" * 1024)
FILLER = [{"name": f"pad_{i}", "description": PAD} for i in range(SIZE_KB)]

TOOLS = [{"name": "echo", "description": "Echoes input",
          "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]
PROMPTS = [{"name": "greet", "description": "A prompt template"}]
RESOURCES = [{"uri": "config://database", "name": "database", "mimeType": "text/plain"}]


async def mcp(request: Request) -> JSONResponse:
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
                "serverInfo": {"name": "LargeBodyTarget", "version": "1.0"},
                "capabilities": {"tools": {}, "prompts": {}, "resources": {}, "logging": {}},
            }},
            headers={"Mcp-Session-Id": "large-body-session"},
        )
    if method == "notifications/initialized":
        return JSONResponse({}, status_code=202)

    # No authorization check on any of these. The padding is the only trick.
    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "result": {"tools": TOOLS + FILLER}})
    if method == "prompts/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "result": {"prompts": PROMPTS + FILLER}})
    if method == "prompts/get":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "messages": [{"role": "user", "content": {"type": "text", "text": PAD}}] * SIZE_KB}})
    if method == "resources/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "result": {"resources": RESOURCES + FILLER}})
    if method == "resources/read":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "contents": [{"uri": "config://database", "mimeType": "text/plain",
                          "text": PAD * SIZE_KB}]}})
    if method == "tools/call":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "result": {"content": [{"type": "text", "text": PAD}]}})

    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "Method not found"}}, status_code=400)


app = Starlette(routes=[Route("/mcp", mcp, methods=["POST"])])

if __name__ == "__main__":
    sample = len(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS + FILLER}}))
    print(f"Starting MCP large-body target on http://127.0.0.1:{PORT}/mcp")
    print(json.dumps({"tools_list_bytes": sample,
                      "tools_list_mb": round(sample / (1 << 20), 2),
                      "auth": None}))
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
