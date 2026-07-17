"""
Deliberately vulnerable MCP test server for validating:
  - mcp-completion-unauth-001: answers completion/complete without auth and
    leaks valid suggestion values to an anonymous caller.

The server advertises the completions, prompts, and resources capabilities and
serves completion/complete for both a prompt argument (ref/prompt) and a
resource-template variable (ref/resource) with no authentication, so the rule
fires its medium reachability finding plus the high disclosure finding.

Run: python testdata/mcp_completion_unauth_server.py
"""
import json
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

PORT = 7796

PROMPTS = [
    {
        "name": "code_review",
        "description": "Review code in a given language",
        "arguments": [{"name": "language", "description": "Programming language", "required": True}],
    },
]

RESOURCE_TEMPLATES = [
    {"uriTemplate": "file:///project/{path}", "name": "project-file", "mimeType": "text/plain"},
]

# Completion suggestions the server leaks. These stand in for internal namespace
# contents an operator would not want an anonymous caller to enumerate.
LANGUAGE_VALUES = ["python", "pytorch", "pyside"]
PATH_VALUES = ["accounts/admin.py", "accounts/billing.py", "secrets/prod.env"]

sessions = {}


def rpc_result(req_id, result):
    return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}),
                    media_type="application/json")


def rpc_error(req_id, code, message):
    return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}),
                    media_type="application/json")


async def mcp_endpoint(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})

    if method == "initialize":
        sid = str(uuid.uuid4())
        sessions[sid] = True
        result = {
            "protocolVersion": params.get("protocolVersion", "2025-03-26"),
            "serverInfo": {"name": "mcp-completion-vuln-server", "version": "1.0"},
            "capabilities": {
                "completions": {},
                "prompts": {"listChanged": False},
                "resources": {"listChanged": False},
            },
        }
        return Response(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}),
                        media_type="application/json",
                        headers={"Content-Type": "application/json", "Mcp-Session-Id": sid})

    if method == "notifications/initialized":
        return Response(status_code=202)

    # No auth check on any of the methods below (vulnerable).
    if method == "prompts/list":
        return rpc_result(req_id, {"prompts": PROMPTS})

    if method == "resources/templates/list":
        return rpc_result(req_id, {"resourceTemplates": RESOURCE_TEMPLATES})

    if method == "completion/complete":
        ref = params.get("ref", {})
        ref_type = ref.get("type", "")
        if ref_type == "ref/prompt":
            if ref.get("name") == "code_review":
                values = LANGUAGE_VALUES
            else:
                # Unknown prompt name: dispatched, but invalid params per spec.
                return rpc_error(req_id, -32602, "Invalid params: unknown prompt")
        elif ref_type == "ref/resource":
            values = PATH_VALUES
        else:
            return rpc_error(req_id, -32602, "Invalid params: unknown reference type")
        return rpc_result(req_id, {"completion": {"values": values, "total": len(values), "hasMore": False}})

    return rpc_error(req_id, -32601, "Method not found")


app = Starlette(routes=[
    Route("/mcp", mcp_endpoint, methods=["POST"]),
    Route("/", mcp_endpoint, methods=["POST"]),
])

if __name__ == "__main__":
    print(f"[*] MCP completion-unauth vulnerable server on port {PORT}", flush=True)
    print("[*] Vulnerability: completion/complete answers without auth and leaks suggestion values", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
