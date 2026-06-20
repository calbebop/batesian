"""
Deliberately vulnerable MCP OAuth proxy test server for validating:
  - mcp-confused-deputy-001: the authorization endpoint does NOT enforce exact
    redirect_uri validation, so it redirects the user agent to an unregistered,
    attacker-supplied redirect_uri. This violates RFC 6749 Section 4.1.2.1 (the
    server must reject a mismatching redirect_uri and must not redirect to it) and
    is the confused-deputy authorization-code-harvest primitive (CWE-441/CWE-601).

Flow the scanner drives:
  - GET /.well-known/oauth-authorization-server -> registration + authorization endpoints
  - POST /register (DCR) -> 201, accepts and echoes ANY redirect_uris (no allowlist)
  - GET /authorize?...&redirect_uri=<R> -> 302 Location: <R> (no exact-match check)

A compliant server validates that redirect_uri exactly matches a URI registered
for the client and rejects a mismatch with an error instead of redirecting to it.

Validate against it:
  python testdata/mcp_confused_deputy_server.py
  batesian scan --target http://127.0.0.1:7793 --rule-ids mcp-confused-deputy-001 -v

Run: python testdata/mcp_confused_deputy_server.py
"""
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7793


async def metadata(request: Request) -> Response:
    base = str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": base,
        "registration_endpoint": f"{base}/register",
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
    })


async def register(request: Request) -> Response:
    body = await request.json()
    # VULNERABLE: accept any redirect_uris with no allowlist; echo them back.
    return JSONResponse(
        {"client_id": "static-proxy-client", "redirect_uris": body.get("redirect_uris", [])},
        status_code=201,
    )


async def authorize(request: Request) -> Response:
    redirect_uri = request.query_params.get("redirect_uri", "")
    # VULNERABLE: no exact-match validation; redirect to whatever was supplied.
    if redirect_uri:
        return RedirectResponse(redirect_uri + "?code=fake-auth-code", status_code=302)
    return JSONResponse({"error": "invalid_request"}, status_code=400)


app = Starlette(routes=[
    Route("/.well-known/oauth-authorization-server", metadata, methods=["GET"]),
    Route("/register", register, methods=["POST"]),
    Route("/authorize", authorize, methods=["GET"]),
])

if __name__ == "__main__":
    print(f"[*] MCP confused-deputy vulnerable OAuth proxy on port {PORT}", flush=True)
    print("[*] Vulnerability: /authorize redirects to any (unregistered) redirect_uri", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
