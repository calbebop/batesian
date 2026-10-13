"""
Deliberately vulnerable MCP OAuth authorization server for validating:
  - mcp-oauth-metadata-ssrf-001: the dynamic client registration (DCR) endpoint
    FETCHES registrant-supplied URL metadata (`jwks_uri`, etc.) server-side
    without an allow-list, so a registrant can point it at internal services or
    cloud metadata endpoints (SSRF in the OAuth discovery chain, CWE-918).

Flow the scanner drives:
  - GET /.well-known/oauth-authorization-server -> advertises registration_endpoint
  - POST /register with jwks_uri/logo_uri/... pointing at the scanner's OOB
    listener -> the server fetches jwks_uri (and logo_uri) server-side, hitting
    the OOB listener and confirming SSRF

A safe server would never fetch registrant-supplied URLs at registration time.

Validate against it (OOB listener auto-starts locally):
  python testdata/mcp_oauth_metadata_ssrf_server.py --allow-metadata-fetch
  batesian scan --target http://127.0.0.1:7791 --rule-ids mcp-oauth-metadata-ssrf-001 -v

Outbound metadata fetches are disabled unless --allow-metadata-fetch is set.
"""
import argparse
import json
import urllib.request
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import uvicorn

PORT = 7791
# Fields the server (vulnerably) dereferences during registration.
FETCHED_FIELDS = ["jwks_uri", "logo_uri", "sector_identifier_uri"]


async def metadata(request: Request) -> JSONResponse:
    base = f"http://127.0.0.1:{PORT}"
    return JSONResponse({
        "issuer": base,
        "registration_endpoint": f"{base}/register",
        "token_endpoint": f"{base}/token",
        "authorization_endpoint": f"{base}/authorize",
    })


async def register(request: Request) -> Response:
    if not request.app.state.allow_metadata_fetch:
        return JSONResponse({"error": "metadata fetch disabled; restart with --allow-metadata-fetch"},
                            status_code=403)
    body = await request.json()
    for field in FETCHED_FIELDS:
        url = body.get(field)
        if not url:
            continue
        # VULNERABLE: dereference the registrant-supplied URL server-side.
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read(1024)
        except Exception:
            pass
    return JSONResponse({"client_id": "c-123", "client_name": body.get("client_name")}, status_code=201)


app = Starlette(routes=[
    Route("/.well-known/oauth-authorization-server", metadata, methods=["GET"]),
    Route("/register", register, methods=["POST"]),
])
app.state.allow_metadata_fetch = False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP OAuth metadata fetch fixture")
    parser.add_argument("--allow-metadata-fetch", action="store_true",
                        help="allow the fixture to fetch registrant-supplied URLs")
    args = parser.parse_args()
    app.state.allow_metadata_fetch = args.allow_metadata_fetch
    print(f"[*] MCP OAuth metadata-SSRF vulnerable server on port {PORT}", flush=True)
    if args.allow_metadata_fetch:
        print(f"[*] DCR fetches registrant-supplied URLs {FETCHED_FIELDS}", flush=True)
    else:
        print("[*] Outbound metadata fetches disabled", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
