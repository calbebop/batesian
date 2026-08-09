"""
Deliberately vulnerable MCP Streamable HTTP test server for validating:
  - mcp-dns-rebind-origin-001: the server does NOT validate the Origin header, so
    it processes a request carrying a foreign Origin instead of rejecting it with
    HTTP 403. A local/private-bound server is then reachable from a victim's
    browser via DNS rebinding (CWE-350 / CWE-346; the class behind CVE-2025-49596).

Two postures, selected by the first argument:

    vulnerable  serves the handshake wire only and validates nothing. ONE finding.
    wire-split  serves BOTH wires and validates Origin on the handshake wire ONLY.
                ONE finding, on the 2026-07-28 wire, labelled as such. The rule
                used to send only initialize, so it could not see this at all: a
                2026-07-28 server has no initialize, and a server that has fixed
                one wire and not the other reads as clean if you only probe the
                fixed one. Origin checking is normally middleware, and the two
                wires can sit behind different handlers.

The requirement is byte-identical in 2026-07-28, where it moved to the
transports/streamable-http page. It is stated for "all incoming connections", is
not scoped to a method, and is not conditioned on the server being local; only the
bind-to-localhost SHOULD beside it is.

Flow the scanner drives on each wire:
  - handshake with no Origin -> 200 + JSON-RPC result (this is the baseline)
  - the same request with Origin: https://...invalid -> 200 + result is the finding
    (a compliant server returns HTTP 403 Forbidden for a present, invalid Origin)

Validate against it:
  python testdata/mcp_dns_rebind_origin_server.py vulnerable
  python testdata/mcp_dns_rebind_origin_server.py wire-split
  batesian scan --target http://127.0.0.1:7794 --rule-ids mcp-dns-rebind-origin-001 -v
"""
import sys
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7794
MODERN_VERSION = "2026-07-28"

POSTURES = ("vulnerable", "wire-split")
POSTURE = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"


async def mcp(request: Request) -> Response:
    body = await request.json()
    req_id = body.get("id")
    method = body.get("method", "")

    # Which wire this request belongs to, by the header every 2026-07-28 request
    # must carry.
    is_modern = request.headers.get("mcp-protocol-version") == MODERN_VERSION

    # Origin validation, per wire, ahead of any dispatch: it is a transport-level
    # check, which is what lets the two wires disagree.
    #
    # In wire-split the handshake wire is FIXED and the modern one is not. The
    # asymmetry is the point: a rule that probes one wire and reports for the server
    # generalises from what it tested to what it did not.
    if request.headers.get("origin") and POSTURE == "wire-split" and not is_modern:
        return Response(status_code=403)

    if method == "server/discover":
        if POSTURE != "wire-split":
            # No modern wire here. Answering server/discover without advertising the
            # revision is what a handshake-era server does, and the scanner must not
            # read the mere answer as a modern wire.
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {
                "code": -32601, "message": "Method not found"}}, status_code=200)
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "supportedVersions": [MODERN_VERSION],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "rebind-fixture", "version": "1.0"},
        }})

    # VULNERABLE (in the posture above): the Origin header is never checked; the
    # request is processed regardless of its value.
    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "rebind-fixture", "version": "1.0"},
            "capabilities": {},
        }})
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})


app = Starlette(routes=[
    Route("/mcp", mcp, methods=["POST"]),
    Route("/", mcp, methods=["POST"]),
])

if __name__ == "__main__":
    if POSTURE not in POSTURES:
        sys.exit(f"unknown posture {POSTURE!r}; expected one of {', '.join(POSTURES)}")
    print(f"[*] MCP DNS-rebinding (no Origin validation) server ({POSTURE}) on port {PORT}",
          flush=True)
    if POSTURE == "vulnerable":
        print("[*] Vulnerability: processes any Origin instead of returning HTTP 403",
              flush=True)
    else:
        print(f"[*] Wires: handshake + MCP {MODERN_VERSION}. Origin is validated on the "
              "handshake wire ONLY, so the one finding must name the modern wire.",
              flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
