"""
Batesian MCP validation target: per-request log opt-in (mcp-log-optin-001).

MCP 2026-07-28 removed logging/setLevel and replaced it with a per-request opt-in.
The logging page is explicit: "To receive log messages for a specific request,
include io.modelcontextprotocol/logLevel in the request's _meta. The server MUST NOT
emit notifications/message for a request that does not include this field."

This server speaks the 2026-07-28 wire ONLY (it refuses the handshake), answers
server/discover, and streams its tools/list reply as SSE so notification frames are
possible at all.

Three postures, selected by the first argument:

    always    emits a notifications/message frame whether or not logLevel was
              requested. THE RULE MUST FIRE. This is the shape of a server carried
              over from the setLevel era, holding a connection-global level.
    on-optin  emits only when logLevel is present. The rule must report CLEAN, and
              that clean result is a real one: the control request proves the server
              logs here, and it withheld the frames when they were not asked for.
    never     emits nothing at all. The rule must report NOT OBSERVED, never clean:
              emitting is a MAY, so silence is indistinguishable from the gate
              working, and claiming otherwise would be a pass with no evidence.

The `never` posture is the one worth keeping. It is the reason the rule sends a
control request at all, and while writing that rule the control was briefly dead
logic: silent-control and silent-probe both fell through to clean, so removing the
control changed no output. This posture is what pins the difference.

Run:
    python testdata/mcp_log_optin_server.py always
    python testdata/mcp_log_optin_server.py on-optin
    python testdata/mcp_log_optin_server.py never

Scan:
    batesian scan --target http://127.0.0.1:7804/mcp \\
        --rule-ids mcp-log-optin-001 -v

Endpoint: http://127.0.0.1:7804/mcp
"""
import json
import sys
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
import uvicorn

PORT = 7804
MODERN_VERSION = "2026-07-28"
LOG_LEVEL_KEY = "io.modelcontextprotocol/logLevel"

POSTURES = ("always", "on-optin", "never")
POSTURE = sys.argv[1] if len(sys.argv) > 1 else "always"


def _rpc_error(req_id, code, message, status=200):
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": code, "message": message}},
                        status_code=status)


def _sse(frames):
    """One SSE data event per frame, in order."""
    def gen():
        for frame in frames:
            yield f"data: {json.dumps(frame)}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


async def mcp_endpoint(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        return _rpc_error(None, -32700, "Parse error")

    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params") or {}
    meta = params.get("_meta") or {}

    # Modern wire only: a handshake request is refused, so the scanner can only reach
    # this server through server/discover.
    if request.headers.get("mcp-protocol-version") != MODERN_VERSION:
        return _rpc_error(req_id, -32022, "UnsupportedProtocolVersion", status=400)

    if method == "server/discover":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "supportedVersions": [MODERN_VERSION],
            # Declared, because this server does emit log notifications. A server that
            # emits them without declaring the capability breaks a second requirement,
            # and the rule reports that in its evidence.
            "capabilities": {"tools": {}, "logging": {}},
            "serverInfo": {"name": "log-optin-target", "version": "1.0"},
        }})

    if method != "tools/list":
        return _rpc_error(req_id, -32601, "Method not found")

    opted_in = LOG_LEVEL_KEY in meta
    emit = POSTURE == "always" or (POSTURE == "on-optin" and opted_in)

    frames = []
    if emit:
        # Request-scoped, on the response stream, ahead of the response: where the
        # binding says notifications/message flows.
        frames.append({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {"level": "debug", "logger": "log-optin-target",
                       "data": {"msg": "listing tools", "optedIn": opted_in}},
        })
    frames.append({"jsonrpc": "2.0", "id": req_id,
                   "result": {"tools": [{"name": "echo", "description": "Echo input"}]}})
    return _sse(frames)


app = Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["POST"])])

if __name__ == "__main__":
    if POSTURE not in POSTURES:
        sys.exit(f"unknown posture {POSTURE!r}; expected one of {', '.join(POSTURES)}")
    print(f"[*] MCP per-request log opt-in target ({POSTURE}) on "
          f"http://127.0.0.1:{PORT}/mcp", flush=True)
    if POSTURE == "always":
        print("[*] Violation: emits notifications/message with no logLevel in _meta "
              "(MUST NOT). The rule must fire.", flush=True)
    elif POSTURE == "on-optin":
        print("[*] Expected: no finding. Logs only when asked, which is the gate "
              "working.", flush=True)
    else:
        print("[*] Expected: NOT OBSERVED. Never logs, so the gate cannot be "
              "established either way.", flush=True)
    print(f"[*] Wire: MCP {MODERN_VERSION} only; the handshake is refused", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
