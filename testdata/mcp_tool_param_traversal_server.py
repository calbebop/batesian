"""
Deliberately vulnerable MCP test server for validating:

  mcp-tool-param-traversal-001: a read-only annotated tool whose path argument
  is joined onto an internal root without containment checking. The error
  message discloses the resolved absolute lookup, which is exactly the
  resolution evidence the rule's oracle reads. No file content is ever
  returned; every probed filename exists nowhere.

Postures:
  vulnerable (default) - naive os.path.join + resolved-path leak.
                         The rule MUST fire confirmed/high on read_note.
  patched              - resolves the join and rejects anything outside the
                         root with a generic message that names no path.
                         The rule MUST stay silent.

An unannotated `admin_read` tool carries the same bug but declares no
annotations: the rule must never dispatch it, so it stays broken here by
design and its silence is part of the validation.

Validate against it:
  python testdata/mcp_tool_param_traversal_server.py            # vulnerable
  python testdata/mcp_tool_param_traversal_server.py patched    # silent

Run: python testdata/mcp_tool_param_traversal_server.py [posture]
"""
import json
import os
import sys
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

PORT = 7805
NOTES_ROOT = "/srv/notes"  # stand-in root; nothing here is ever read


def read_note_schema_tool():
    return {
        "name": "read_note",
        "description": "Read a note from the notes directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Note file name"}},
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": True},
    }


def admin_read_tool():
    # Same bug, no annotations: the safety gate must skip it entirely.
    return {
        "name": "admin_read",
        "description": "Read any file (unannotated on purpose).",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    }


TOOLS = [read_note_schema_tool(), admin_read_tool()]


def naive_join(root: str, p: str) -> str:
    # VULNERABLE: an absolute caller path discards the root entirely, and a
    # relative one is never checked for where it ends up.
    if p.startswith("/"):
        return os.path.normpath(p)
    return os.path.normpath(os.path.join(root, p))


async def jsonrpc(request: Request) -> JSONResponse:
    body = await request.json()
    method = body.get("method")
    rid = body.get("id", 1)

    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "traversal-fixture", "version": "1.0"},
            },
        })
    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {}})
    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    if method == "tools/call":
        params = body.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {})
        raw_path = args.get("path", "")

        if name == "read_note":
            posture = request.app.state.posture
            if posture == "patched":
                # PATCHED: resolve, verify containment, refuse generically.
                joined = os.path.normpath(os.path.join(NOTES_ROOT, raw_path))
                if not joined.startswith(NOTES_ROOT + os.sep):
                    return JSONResponse({
                        "jsonrpc": "2.0", "id": rid,
                        "result": {"content": [{"type": "text", "text":
                                  "rejected: path escapes the notes directory"}], "isError": True},
                    })
                return JSONResponse({
                    "jsonrpc": "2.0", "id": rid,
                    "result": {"content": [{"type": "text", "text": f"note not found: {joined}"}],
                               "isError": True},
                })

            # VULNERABLE: leak the resolution the way Node's ENOENT does.
            resolved = naive_join(NOTES_ROOT, raw_path)
            return JSONResponse({
                "jsonrpc": "2.0", "id": rid,
                "result": {"content": [{"type": "text", "text":
                          f"ENOENT: no such file or directory, open '{resolved}'"}],
                           "isError": True},
            })

        if name == "admin_read":
            # Same leak, but this tool must never be reached by the scanner.
            resolved = naive_join(NOTES_ROOT, raw_path)
            return JSONResponse({
                "jsonrpc": "2.0", "id": rid,
                "result": {"content": [{"type": "text", "text":
                          f"ENOENT: no such file or directory, open '{resolved}'"}],
                           "isError": True},
            })

    return JSONResponse({
        "jsonrpc": "2.0", "id": rid,
        "error": {"code": -32601, "message": "Method not found"},
    })


app = Starlette(routes=[Route("/", jsonrpc, methods=["POST"]), Route("/mcp", jsonrpc, methods=["POST"])])


if __name__ == "__main__":
    app.state.posture = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"
    print(f"[*] MCP tool-param traversal fixture ({app.state.posture}) on port {PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
