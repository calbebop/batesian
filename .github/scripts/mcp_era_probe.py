#!/usr/bin/env python3
"""Probe the MCP reference server to see whether it speaks the 2026-07-28 era.

Batesian's MCP rules target the handshake-based revisions. Modern-era rule work
is gated on a real stateless server existing to validate against, and this
script is what watches for that. It boots the reference server, sends a modern
server/discover request, and classifies the reply.

Classification mirrors internal/attack/mcp/era.go exactly: the MCP
specification reserves JSON-RPC error codes -32020 to -32099 for itself, so a
code in that range can only come from a modern server, while -32000 to -32019
is implementation-defined and says nothing about era. The reference server
answers this probe with -32000 "Server not initialized", so a check for "did I
get a JSON-RPC error" would call every legacy server modern.

Writes era=legacy|modern|unknown to GITHUB_OUTPUT. Exits non-zero only when the
probe itself could not be run, so a genuine "still legacy" result is a quiet
success rather than a failing job.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

PORT = os.environ.get("PROBE_PORT", "3180")
ENDPOINT = f"http://127.0.0.1:{PORT}/mcp"
MODERN_VERSION = "2026-07-28"

# The range the specification reserves for itself. Keep in sync with
# modernErrCodeMin / modernErrCodeMax in internal/attack/mcp/era.go.
MODERN_ERR_MIN = -32099
MODERN_ERR_MAX = -32020


def parse_body(raw: bytes, content_type: str):
    """Decode a JSON-RPC body, unwrapping an SSE frame when the server streams.

    An SSE event's payload may span several data: lines, and blank data: lines
    are keep-alives, so take the first non-empty one that parses.
    """
    text = raw.decode("utf-8", errors="replace")
    if "event-stream" in content_type:
        for line in text.splitlines():
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload:
                    try:
                        return json.loads(payload)
                    except json.JSONDecodeError:
                        continue
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def classify(status: int, body) -> str:
    """Return 'modern' or 'legacy' for a server/discover reply."""
    if isinstance(body, dict):
        # A DiscoverResult means the server implements the modern discovery RPC.
        if isinstance(body.get("result"), dict) and 200 <= status < 300:
            return "modern"
        error = body.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            if isinstance(code, int) and MODERN_ERR_MIN <= code <= MODERN_ERR_MAX:
                return "modern"
    return "legacy"


def probe():
    """Send a well-formed modern server/discover request and classify the reply.

    The request carries the headers and _meta fields a modern request requires.
    A malformed probe would earn -32020 HeaderMismatch, which is itself a modern
    signal, so it would report modernity it never demonstrated.
    """
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": "era-watch",
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
                "io.modelcontextprotocol/clientInfo": {"name": "batesian-era-watch", "version": "1.0"},
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }).encode()

    request = urllib.request.Request(
        ENDPOINT,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MODERN_VERSION,
            "Mcp-Method": "server/discover",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status, raw = response.status, response.read()
            ctype = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        # A rejection is expected and informative: the body decides the era.
        status, raw = exc.code, exc.read()
        ctype = exc.headers.get("Content-Type", "") if exc.headers else ""
    except Exception as exc:  # noqa: BLE001 - any transport failure is inconclusive
        return "unknown", f"probe could not reach {ENDPOINT}: {exc}"

    body = parse_body(raw, ctype)
    era = classify(status, body)
    rendered = json.dumps(body) if body is not None else raw.decode("utf-8", errors="replace")
    detail = f"HTTP {status}\n{rendered[:600]}"
    return era, detail


def emit(era: str, detail: str) -> None:
    print(f"era={era}")
    print(detail)
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as handle:
        handle.write(f"era={era}\n")
        # Multi-line values need the heredoc form.
        handle.write("detail<<PROBE_EOF\n")
        handle.write(detail + "\n")
        handle.write("PROBE_EOF\n")


def main() -> int:
    # shell=True on Windows, where npx is a .cmd shim that Popen cannot exec
    # directly. CI runs Linux, but keeping this portable means the script can be
    # run by hand to check the gate without waiting for the weekly job.
    npx = ["npx", "-y", "@modelcontextprotocol/server-everything", "streamableHttp"]
    server = subprocess.Popen(
        " ".join(npx) if os.name == "nt" else npx,
        shell=os.name == "nt",
        env={**os.environ, "PORT": PORT},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        # npx may need to fetch the package before the server binds.
        deadline = time.time() + 120
        while time.time() < deadline:
            if server.poll() is not None:
                emit("unknown", "reference server exited before it accepted connections")
                return 1
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=2)
                break
            except urllib.error.HTTPError:
                break  # answering at all means it is listening
            except Exception:  # noqa: BLE001
                time.sleep(2)
        else:
            emit("unknown", "reference server did not start within the timeout")
            return 1

        era, detail = probe()
        emit(era, detail)
        # Only a broken probe is a failure. "Still legacy" is the expected
        # steady state and must not page anyone.
        return 1 if era == "unknown" else 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    sys.exit(main())
