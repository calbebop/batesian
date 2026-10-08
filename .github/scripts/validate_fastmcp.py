#!/usr/bin/env python3
"""Validate findings and clean rule outcomes against secured FastMCP."""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from validation_outcomes import incomplete_rules

HOST = "127.0.0.1"
PORT = 7805
BASE = f"http://{HOST}:{PORT}"
EP = f"{BASE}/mcp"
SERVER = os.environ.get("BATESIAN_FASTMCP_SERVER", ".github/scripts/fastmcp_secured_server.py")
BINARY = os.environ.get("BATESIAN_BIN", "./batesian")
TOKEN = "batesian-valid-token"


def _read(log):
    log.flush()
    log.seek(0)
    return log.read()


def wait_ready(proc, log, deadline_s=60):
    """FastMCP takes longer to start than a bare Starlette app. Ready when POST
    /mcp gets any HTTP response: a 401 to an unauthenticated initialize is the
    expected 'up and gating' answer."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                  "clientInfo": {"name": "ci", "version": "1"}}}).encode()
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"FastMCP exited early (code {proc.returncode}); log:\n{_read(log)}")
        try:
            req = urllib.request.Request(EP, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2)
            return
        except urllib.error.HTTPError:
            return  # got an HTTP status (e.g. 401) -> it is up
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    raise RuntimeError(f"FastMCP not ready at {EP} within {deadline_s}s; log:\n{_read(log)}")


def start():
    log = tempfile.NamedTemporaryFile("w+", suffix="-fastmcp.log", delete=False, encoding="utf-8")
    proc = subprocess.Popen([sys.executable, SERVER, str(PORT)],
                            stdout=log, stderr=subprocess.STDOUT, text=True)
    try:
        wait_ready(proc, log)
    except Exception:
        stop(proc, log)
        raise
    return proc, log


def stop(proc, log=None):
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=8)
    if log is not None:
        try:
            log.close()
        except Exception:  # noqa: BLE001
            pass


def scan(*extra):
    out = subprocess.run([BINARY, "scan", "--target", BASE, "--output", "json", "--timeout", "20", *extra],
                         capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise RuntimeError(f"batesian exited {out.returncode}:\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    doc = json.loads(out.stdout)
    return {f["rule_id"] for f in doc.get("findings", [])}, doc


def main():
    proc, log = start()
    try:
        unauth, unauth_doc = scan()
        cred, cred_doc = scan("--token", TOKEN)
    finally:
        stop(proc, log)

    ok = True
    # Anonymous MCP rules legitimately skip when FastMCP refuses initialize.
    fp_ok = not unauth and not unauth_doc["errors"]
    print(f"[{'PASS' if fp_ok else 'FAIL'}] FastMCP unauthenticated (false-positive gate): "
          f"findings={sorted(unauth)}; errors={unauth_doc['errors']}")
    ok &= fp_ok

    # This tracks FastMCP's current Origin-protection default.
    cred_ok = "mcp-dns-rebind-origin-001" in cred
    print(f"[{'PASS' if cred_ok else 'FAIL'}] FastMCP authenticated (dns-rebind true positive): "
          f"mcp-dns-rebind-origin-001 {'present' if cred_ok else 'ABSENT'}; fired {sorted(cred)}")
    ok &= cred_ok

    clean_rule = "mcp-tool-poisoning-001"
    skipped, errors = incomplete_rules(cred_doc, {clean_rule})
    clean_ok = clean_rule not in cred and not skipped and not errors
    print(f"[{'PASS' if clean_ok else 'FAIL'}] FastMCP authenticated (clean tool manifest): "
          f"fired={clean_rule in cred}; skipped={skipped}; errors={errors}")
    ok &= clean_ok

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
