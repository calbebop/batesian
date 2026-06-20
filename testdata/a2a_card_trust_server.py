"""
Deliberately vulnerable A2A test server for validating:
  - a2a-card-trust-001: agent-card TRUST DURABILITY gaps not covered by the
    signature-algorithm rule (a2a-jws-algconf-001):

      * Canonicalization / signature stripping (CONFIRMED, high): the card is
        SIGNED at /.well-known/agent-card.json but UNSIGNED at the legacy path
        /.well-known/agent.json, so a client steered to the legacy path skips
        signature verification entirely.
      * Stale-cache trust (INDICATOR, medium): the card is served with
        Cache-Control: public, max-age=86400, immutable - the trust anchor is
        cached for a day with no revalidation, so a rotated/compromised card
        keeps being trusted.
      * Signature freshness (INDICATOR, medium): the signature's protected
        header declares no `exp`, so it never expires.

This is a static card server (no JSON-RPC); no authentication is involved.

Validate against it:
  python testdata/a2a_card_trust_server.py
  batesian scan --target http://127.0.0.1:3105 --rule-ids a2a-card-trust-001 -v

Run: python testdata/a2a_card_trust_server.py
"""
import base64
import json
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

PORT = 3105

AGENT_URL = "https://agent.example/a2a"


def protected_header() -> str:
    # alg present, but NO exp -> signature never expires (freshness indicator).
    header = json.dumps({"alg": "RS256"}).encode()
    return base64.urlsafe_b64encode(header).rstrip(b"=").decode()


SIGNED_CARD = {
    "name": "Vulnerable Card-Trust Agent",
    "url": AGENT_URL,
    "version": "1.0.0",
    "signatures": [{"protected": protected_header(), "signature": "ZmFrZS1zaWc"}],
}

UNSIGNED_CARD = {
    "name": "Vulnerable Card-Trust Agent",
    "url": AGENT_URL,
    "version": "1.0.0",
}


async def signed_card(request: Request) -> JSONResponse:
    # VULNERABLE: long-lived, immutable cache on a security-critical trust anchor.
    return JSONResponse(SIGNED_CARD, headers={"Cache-Control": "public, max-age=86400, immutable"})


async def unsigned_card(request: Request) -> JSONResponse:
    # VULNERABLE: legacy path serves the same agent's card WITHOUT signatures.
    return JSONResponse(UNSIGNED_CARD, headers={"Cache-Control": "public, max-age=86400, immutable"})


app = Starlette(routes=[
    Route("/.well-known/agent-card.json", signed_card, methods=["GET"]),
    Route("/.well-known/agent.json", unsigned_card, methods=["GET"]),
])

if __name__ == "__main__":
    print(f"[*] A2A card-trust vulnerable server on port {PORT}", flush=True)
    print("[*] Vulnerability: signed primary path, unsigned legacy path + stale-cache trust anchor", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT)
