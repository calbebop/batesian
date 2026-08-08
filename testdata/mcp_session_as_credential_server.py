"""
MCP server for validating:
  - mcp-session-as-credential-001: the server accepts its own Mcp-Session-Id as
    proof of identity (CWE-287 / CWE-565).

The Security Best Practices are explicit: "MCP servers that implement
authorization MUST verify all inbound requests. MCP Servers MUST NOT use sessions
for authentication."

Four postures, selected by the first argument.

`vulnerable` requires a bearer token at initialize, mints a session id, and then
accepts that session id alone on every later request. Stripping the Authorization
header changes nothing as long as the session id is one it issued. That is a
bearer token in a plaintext header that no proxy log redacts.

`open-handshake` is the same failure on a server that leaves initialize ungated:
anyone may handshake, but the session remembers who opened it and that memory is
what authorizes later calls. It must fire. An open handshake is not the same thing
as no authorization, and reading it that way suppressed this case.

`patched` is the same server with the fix: every request is authenticated on its
own credential, and the session id only selects which conversation the request
belongs to. It must produce no finding.

`session-presence-auth` is the false-positive posture, and it is the reason step 3
of the rule exists. It has no authorization at all, but it demands a session id on
every non-initialize request, so a stripped request is refused for SESSION reasons
rather than credential ones. This is the shape of the official MCP C# SDK's
stateful sample, which the rule reported as vulnerable before the anonymous
handshake control was added. It must produce no finding.

Validate against it:
  python testdata/mcp_session_as_credential_server.py vulnerable
  batesian scan --target http://127.0.0.1:7803 --token tok-a \\
      --rule-ids mcp-session-as-credential-001 -v

The token matters: the rule asks whether a session id can stand in for a
credential, which it cannot ask without a credential to compare against. With no
--token it reports inconclusive rather than clean.

Endpoint: http://127.0.0.1:7803/mcp
"""
import sys
import uuid
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7803
TOKEN = "tok-a"

POSTURES = ("vulnerable", "open-handshake", "patched", "session-presence-auth")
POSTURE = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"

# Postures that let anyone handshake. session-presence-auth authenticates nothing
# at all; open-handshake authorizes later calls from the session's own memory of
# who opened it, which is the failure under test.
OPEN_HANDSHAKE = ("open-handshake", "session-presence-auth")

# session id -> the principal the session was opened by
SESSIONS: dict = {}


def _result(req_id, result, session_id=None):
    headers = {"Mcp-Session-Id": session_id} if session_id else None
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result}, headers=headers)


def _error(req_id, code, message):
    return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": code, "message": message}})


def _credentialed(request: Request) -> bool:
    return request.headers.get("authorization", "") == f"Bearer {TOKEN}"


async def mcp_endpoint(request: Request) -> Response:
    body = await request.json()
    method = body.get("method", "")
    req_id = body.get("id")
    supplied = request.headers.get("mcp-session-id", "")
    authed = _credentialed(request)

    if method == "initialize":
        if POSTURE not in OPEN_HANDSHAKE and not authed:
            return _error(req_id, -32000, "authentication required")
        session_id = uuid.uuid4().hex
        # The session remembers the principal that opened it. In the vulnerable
        # postures that memory is what later authorizes calls made without a
        # credential, which is the bug.
        SESSIONS[session_id] = "tenant-a" if authed else "anonymous"
        return _result(req_id, {
            "protocolVersion": "2025-11-25",
            "serverInfo": {"name": "session-as-credential-target", "version": "1.0"},
            "capabilities": {"tools": {}},
        }, session_id=session_id)

    if method == "notifications/initialized":
        return Response(status_code=202)

    # Every posture is stateful: an id the server never issued is rejected, per the
    # Streamable HTTP transport. Without this the rule cannot attribute a success to
    # the issued session id, and its never-issued-id control suppresses the finding.
    if supplied not in SESSIONS:
        return _error(req_id, -32000, "no valid session id provided")

    if POSTURE == "vulnerable":
        # VULNERABLE: the session id resolved a principal, so the request is
        # authorized. The Authorization header is never looked at again.
        pass
    elif POSTURE == "open-handshake":
        # VULNERABLE the same way, on a server that gates nothing at initialize.
        # A session opened anonymously carries no authority; one opened with the
        # credential authorizes calls that present no credential at all.
        if not authed and SESSIONS[supplied] == "anonymous":
            return _error(req_id, -32000, "authentication required")
    elif POSTURE == "patched":
        # FIXED: authenticate this request on its own credential.
        if not authed:
            return _error(req_id, -32000, "authentication required")
    # session-presence-auth: the session id was enough because nothing is
    # authenticated here at all. The refusal above was about session state.

    if method == "tools/list":
        return _result(req_id, {"tools": [{"name": "echo", "description": "Echo input"}]})

    return _error(req_id, -32601, "Method not found")


app = Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["POST"])])

if __name__ == "__main__":
    if POSTURE not in POSTURES:
        sys.exit(f"unknown posture {POSTURE!r}; expected one of {', '.join(POSTURES)}")
    print(f"[*] MCP session-as-credential target ({POSTURE}) on "
          f"http://127.0.0.1:{PORT}/mcp", flush=True)
    if POSTURE == "vulnerable":
        print("[*] Vulnerability: the issued Mcp-Session-Id authorizes requests "
              "on its own (CWE-287/CWE-565)", flush=True)
    else:
        print("[*] Expected: no finding", flush=True)
    print(f"[*] Credential: --token {TOKEN}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
