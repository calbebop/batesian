"""
Batesian MCP validation target: OAuth audience matching bug probes
(mcp-oauth-audience-002).

Exposes four MCP-shaped endpoints that share the same forged-token detection
logic, each demonstrating a different aud-validation bug class plus a strict
control. All endpoints accept POST /mcp with a Bearer JWT and an MCP
initialize body, mirroring the wire shape the Go executor expects.

Endpoint matrix:

  /vulnerable-substring/mcp   --> aud check uses substring match
                                  (`expected in token_aud`).
  /vulnerable-casefold/mcp    --> aud check lowercases both sides before
                                  comparing.
  /vulnerable-array-skip/mcp  --> aud check inspects only string-form aud and
                                  treats array-shape as already-validated.
  /secure/mcp                 --> aud check is strict, exact, case-sensitive
                                  per RFC 7519 §4.1.3.

The expected audience advertised by every endpoint is
`https://api.example.com/mcp` (also exposed at
`/.well-known/oauth-protected-resource`) so a Batesian scan run with
`--audience-claim https://api.example.com/mcp` (or no claim, relying on RFC
9728 auto-discovery) exercises every probe.

Run:
    python testdata/mcp_oauth_audience_server.py

Then scan with the rule:
    batesian scan --target http://127.0.0.1:7785 \
                  --rule-ids mcp-oauth-audience-002 \
                  --audience-claim https://api.example.com/mcp -v

This server is intentionally misconfigured. Do not run on a public network.
"""
import base64
import json
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

EXPECTED_AUD = "https://api.example.com/mcp"
PORT = 7785


def _decode_jwt_payload(authorization: str | None) -> dict | None:
    """Best-effort JWT payload decode. The deliberately vulnerable handlers
    below skip signature verification on purpose; they exist to exercise the
    audience-matching logic, not the signing path."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.removeprefix("Bearer ")
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _ok_initialize() -> JSONResponse:
    return JSONResponse({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "batesian-audience-testdata",
                "version": "1.0",
            },
        },
    })


def _challenge() -> Response:
    return Response(
        content=json.dumps({"error": "invalid_token"}),
        status_code=401,
        media_type="application/json",
        headers={
            "WWW-Authenticate": (
                'Bearer error="invalid_token", '
                f'resource_metadata="http://127.0.0.1:{PORT}/.well-known/oauth-protected-resource"'
            ),
        },
    )


async def resource_metadata(request: Request) -> JSONResponse:
    return JSONResponse({
        "resource": EXPECTED_AUD,
        "authorization_servers": [f"http://127.0.0.1:{PORT}"],
    })


async def vulnerable_substring(request: Request) -> Response:
    payload = _decode_jwt_payload(request.headers.get("authorization"))
    if not payload:
        return _challenge()
    aud = payload.get("aud")
    if isinstance(aud, str) and EXPECTED_AUD in aud:
        return _ok_initialize()
    return _challenge()


async def vulnerable_casefold(request: Request) -> Response:
    payload = _decode_jwt_payload(request.headers.get("authorization"))
    if not payload:
        return _challenge()
    aud = payload.get("aud")
    if isinstance(aud, str) and aud.lower() == EXPECTED_AUD.lower():
        return _ok_initialize()
    return _challenge()


async def vulnerable_array_skip(request: Request) -> Response:
    payload = _decode_jwt_payload(request.headers.get("authorization"))
    if not payload:
        return _challenge()
    aud = payload.get("aud")
    if isinstance(aud, list):
        return _ok_initialize()
    if isinstance(aud, str) and aud == EXPECTED_AUD:
        return _ok_initialize()
    return _challenge()


async def secure(request: Request) -> Response:
    payload = _decode_jwt_payload(request.headers.get("authorization"))
    if not payload:
        return _challenge()
    aud = payload.get("aud")
    if isinstance(aud, str) and aud == EXPECTED_AUD:
        return _ok_initialize()
    if isinstance(aud, list) and EXPECTED_AUD in aud:
        return _ok_initialize()
    return _challenge()


routes = [
    Route("/.well-known/oauth-protected-resource", resource_metadata, methods=["GET"]),
    Route("/vulnerable-substring/mcp", vulnerable_substring, methods=["POST"]),
    Route("/vulnerable-casefold/mcp", vulnerable_casefold, methods=["POST"]),
    Route("/vulnerable-array-skip/mcp", vulnerable_array_skip, methods=["POST"]),
    Route("/secure/mcp", secure, methods=["POST"]),
]

app = Starlette(routes=routes)

if __name__ == "__main__":
    print(f"Starting MCP audience-validation testdata server on http://127.0.0.1:{PORT}")
    print("  GET  /.well-known/oauth-protected-resource")
    print("  POST /vulnerable-substring/mcp")
    print("  POST /vulnerable-casefold/mcp")
    print("  POST /vulnerable-array-skip/mcp")
    print("  POST /secure/mcp")
    uvicorn.run(app, host="127.0.0.1", port=PORT)
