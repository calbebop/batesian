#!/usr/bin/env python3
"""A FastMCP server that requires a bearer token, for the validation gate.

This is a third-party, auth-enforcing MCP server rather than a hand-rolled
fixture: the validation-results.md thesis is that pointing the scanner at code
the project did not write catches defects the fixtures cannot. FastMCP's
StaticTokenVerifier rejects any request that does not carry a known token with
the required scope, so an unauthenticated scan cannot get past initialize.

Booted in CI by .github/scripts/validate_fastmcp.py. Not a vulnerable fixture;
do not confuse it with the testdata/ servers.
"""
import sys

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7805

# A single known token with the scope the server requires. The unauthenticated
# scan carries none of this; the credentialed scan uses the token via --token.
verifier = StaticTokenVerifier(
    tokens={
        "batesian-valid-token": {
            "client_id": "batesian",
            "scopes": ["read:data"],
        }
    },
    required_scopes=["read:data"],
)

mcp = FastMCP(name="batesian-validation-target", auth=verifier)


@mcp.tool
def echo(text: str) -> str:
    """Echo the input text."""
    return text


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="127.0.0.1", port=PORT)
