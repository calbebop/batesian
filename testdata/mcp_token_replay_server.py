"""
Deliberately vulnerable MCP test server for validating:

  mcp-token-replay-001: an OAuth-participating resource server whose gate
  accepts anything bearing a well-formed bearer - including tokens signed
  with a secret it cannot know, and unsigned alg:none tokens.

Postures:
  vulnerable (default) - publishes RFC 9728 protected-resource metadata,
                         refuses an UNauthenticated initialize, but accepts
                         any request carrying any bearer token whatsoever.
                         The forged-probe family MUST fire (three findings:
                         two high for wrong/missing aud, one critical for
                         alg:none); judging lands at initialize because the
                         anonymous control is refused there.
  patched              - same metadata, same refusal of anonymous calls, but
                         tokens are verified against the one credential this
                         fixture issued (tok-valid): an exact-match check, so
                         random-keyed signatures fail it identically to how
                         a signature-invalid JWT fails real validation. All
                         forged probes MUST be rejected; the rule stays
                         silent.

Verification-model note: the patched posture implements exact presentation
checking rather than RS256/JWKS validation, which keeps the fixture inside
the project's dependency set (starlette/uvicorn only). A random-key HMAC
signature fails an exact-match check for the same reason it fails signature
verification - the server cannot reproduce it - so the regression signal
(bad token rejected, good behavior silent) is preserved.

Only initialize is implemented; no tool surface exists, keeping the probe
purely about token handling.

Validate against it:
  python testdata/mcp_token_replay_server.py vulnerable  # 3 findings fire
  python testdata/mcp_token_replay_server.py patched     # silent

Run: python testdata/mcp_token_replay_server.py [posture]
Scan: batesian scan --target http://127.0.0.1:7813 --rule-ids mcp-token-replay-001 -v
"""
import sys

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

PORT = 7813

VALID_TOKENS = {"tok-valid"}


async def protected_resource_metadata(request: Request) -> JSONResponse:
    return JSONResponse({
        "resource": f"http://127.0.0.1:{PORT}",
        "authorization_servers": [f"http://127.0.0.1:{PORT}"],
        "scopes_supported": ["mcp:read"],
        "bearer_methods_supported": ["header"],
    })


async def jsonrpc(request: Request) -> JSONResponse:
    body = await request.json()
    method = body.get("method")
    rid = body.get("id", 1)

    if method != "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": rid,
                             "error": {"code": -32601, "message": "Method not found"}})

    auth = request.headers.get("authorization", "")
    token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""

    if request.app.state.posture == "patched":
        # Exact presentation check: only the credential this fixture issued
        # passes. Random-keyed signatures and alg:none fail here exactly as
        # they fail cryptographic verification.
        if token not in VALID_TOKENS:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": rid,
                 "error": {"code": -32001, "message": "invalid_token: signature or issuer rejected"}},
                status_code=401)

    elif not token:
        # VULNERABLE posture refuses only ABSENT credentials, so the rule's
        # anonymous control reads "initialize gates" and judges its forged
        # probes right here - yet any well-formed bearer sails through.
        return JSONResponse(
            {"jsonrpc": "2.0", "id": rid,
             "error": {"code": -32001, "message": "unauthorized: bearer token required"}},
            status_code=401)

    return JSONResponse({
        "jsonrpc": "2.0", "id": rid,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "serverInfo": {"name": "token-replay-fixture", "version": "1.0"},
        },
    })


routes = [
    Route("/", jsonrpc, methods=["POST"]),
    Route("/mcp", jsonrpc, methods=["POST"]),
    Route("/api", jsonrpc, methods=["POST"]),
    Route("/rpc", jsonrpc, methods=["POST"]),
    Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
]

app = Starlette(routes=routes)
app.state.posture = "vulnerable"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        app.state.posture = sys.argv[1]
    print(f"[*] MCP token-replay fixture ({app.state.posture}) on port {PORT}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
