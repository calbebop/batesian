"""
Deliberately vulnerable MCP test server for validating:

  mcp-scope-confusion-001: a server that authenticates every tools/call and
  then ignores what the credential is scoped to do. Both bearer tokens are
  valid; in the vulnerable posture the limited one reaches every tool the
  full one can.

Postures:
  vulnerable (default) - any accepted bearer authorizes everything. The rule
                         MUST fire confirmed/high on delete_item.
  patched              - tokens carry scopes (tok-a -> items:write+read,
                         tok-b -> items:read) and privileged tools check them
                         first, refusing with an insufficient_scope message
                         before argument validation. The rule MUST stay silent.
  open                 - no authentication anywhere. The anonymous control
                         dispatches, so scope enforcement is not the boundary
                         this rule can speak about, and it MUST stay silent
                         (the surface belongs to mcp-tools-unauth-001).

Tokens: tok-a is the full principal, tok-b the limited one. Pass
--token tok-a plus two --principal flags exactly as validate_secured_agent.py
does for the cross-principal rules.

Both postures serve list_items (readOnlyHint true) and delete_item (explicitly
non-read-only). Every probe call names an item_id that does not exist, so
nothing is ever deleted regardless of posture.

Validate against it:
  python testdata/mcp_scope_confusion_server.py              # vulnerable
  python testdata/mcp_scope_confusion_server.py patched      # silent
  python testdata/mcp_scope_confusion_server.py open         # silent

Run: python testdata/mcp_scope_confusion_server.py [posture]
"""
import sys
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

PORT = 7806

FULL_SCOPES = {"items:read", "items:write"}
LIMITED_SCOPES = {"items:read"}

TOOLS = [
    {
        "name": "list_items",
        "description": "List stored items.",
        "annotations": {"readOnlyHint": True},
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "delete_item",
        "description": "Delete a stored item.",
        "annotations": {"readOnlyHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {"item_id": {"type": "string"}},
            "required": ["item_id"],
        },
    },
]

ITEMS_STORE = {}  # empty on purpose: probes name ids that cannot exist


def token_scopes(token: str):
    if token == "tok-a":
        return FULL_SCOPES
    if token == "tok-b":
        return LIMITED_SCOPES
    return None


async def jsonrpc(request: Request) -> JSONResponse:
    body = await request.json()
    method = body.get("method")
    rid = body.get("id", 1)
    auth = request.headers.get("authorization", "")
    token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""

    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "scope-confusion-fixture", "version": "1.0"},
            },
        })
    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {}})

    posture = request.app.state.posture
    if posture == "open":
        scopes = FULL_SCOPES  # no gate at all: everyone reads as full
    else:
        scopes = token_scopes(token)
        if scopes is None:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": rid,
                 "error": {"code": -32000, "message": "unauthorized: missing or invalid bearer token"}},
                status_code=401,
            )

    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    if method == "tools/call":
        params = body.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {}) or {}

        if name == "list_items":
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"{len(ITEMS_STORE)} item(s)"}], "isError": False}})

        if name == "delete_item":
            item_id = args.get("item_id", "")
            if posture == "patched" and "items:write" not in scopes:
                # Refuse BEFORE validation, naming the missing scope the way an
                # OAuth resource server does.
                return JSONResponse({
                    "jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32000,
                              "message": f"insufficient_scope: items:write required (token has {sorted(scopes)})"},
                }, status_code=403)
            # VULNERABLE (and open): dispatch reached; validation runs after.
            if not item_id:
                return JSONResponse({
                    "jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32602, "message": "invalid params: item_id required"},
                })
            if item_id not in ITEMS_STORE:
                return JSONResponse({
                    "jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32602, "message": f"Item {item_id} not found"},
                })
            ITEMS_STORE.pop(item_id, None)
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": "deleted"}], "isError": False}})

    return JSONResponse({
        "jsonrpc": "2.0", "id": rid,
        "error": {"code": -32601, "message": "Method not found"},
    })


app = Starlette(routes=[Route("/", jsonrpc, methods=["POST"]), Route("/mcp", jsonrpc, methods=["POST"])])


if __name__ == "__main__":
    app.state.posture = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"
    print(f"[*] MCP scope-confusion fixture ({app.state.posture}) on port {PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
