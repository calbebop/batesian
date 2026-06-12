"""
Deliberately vulnerable MCP Streamable HTTP test server for validating:
  - mcp-sse-resume-replay-001: the SSE resumption buffer is NOT scoped to the
    originating session, so a client resuming with Last-Event-ID receives another
    session's buffered events (cross-session redelivery, CWE-488 / CWE-294).

Flow the scanner drives:
  - initialize (POST) -> server mints a distinct Mcp-Session-Id per session
  - GET (Accept: text/event-stream) with no Last-Event-ID -> emits one
    session-specific event (id + data) and records it in a GLOBAL log
  - GET with Last-Event-ID=N -> VULNERABLE: replays every logged event with
    id > N regardless of which session created it

A compliant server replays only the requesting session's own events.

Validate against it:
  python testdata/mcp_sse_resume_replay_server.py
  batesian scan --target http://127.0.0.1:7790 --rule-ids mcp-sse-resume-replay-001 -v

Run: python testdata/mcp_sse_resume_replay_server.py
"""
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
import uvicorn

PORT = 7790
_sessions = 0
_events = 0
LOG = []  # list of {"eid", "sid", "data"}


async def mcp_post(request: Request) -> Response:
    global _sessions
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    if method == "initialize":
        _sessions += 1
        sid = f"sess-{_sessions}"
        return JSONResponse(
            {"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "resume-fixture", "version": "1.0"},
                "capabilities": {"tools": {}},
            }},
            headers={"Mcp-Session-Id": sid},
        )
    return Response(status_code=202)


async def mcp_get(request: Request) -> Response:
    global _events
    sid = request.headers.get("mcp-session-id", "")
    leid = request.headers.get("last-event-id", "")

    if leid == "":
        _events += 1
        eid = _events
        data = json.dumps({"sid": sid, "secret": f"S-{sid}-{eid}"})
        LOG.append({"eid": eid, "sid": sid, "data": data})

        def gen_new():
            yield f"id: {eid}\ndata: {data}\n\n"
        return StreamingResponse(gen_new(), media_type="text/event-stream")

    try:
        last = int(leid)
    except ValueError:
        last = -1

    def gen_resume():
        # VULNERABLE: replay every buffered event after `last`, any session.
        for ev in list(LOG):
            if ev["eid"] > last:
                yield f"id: {ev['eid']}\ndata: {ev['data']}\n\n"
    return StreamingResponse(gen_resume(), media_type="text/event-stream")


async def handler(request: Request) -> Response:
    if request.method == "POST":
        return await mcp_post(request)
    return await mcp_get(request)


app = Starlette(routes=[Route("/mcp", handler, methods=["GET", "POST"]),
                        Route("/", handler, methods=["GET", "POST"])])

if __name__ == "__main__":
    print(f"[*] MCP SSE resume-replay vulnerable server on port {PORT}", flush=True)
    print("[*] Vulnerability: resumption buffer not scoped to session", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
