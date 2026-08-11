#!/usr/bin/env python3
"""CI validation harness for testdata/mcp_oauth_dcr_server.py.

The DCR rules (mcp-oauth-dcr-001, mcp-confused-deputy-001,
mcp-oauth-metadata-ssrf-001) each register a client to test what dynamic client
registration accepts, so a scan necessarily changes the target's state. RFC 7592
client management is how they clean it up. This fixture has two postures that
turn on whether the server implements that management:

  managed    returns registration_client_uri + token, so each rule deletes its
             client. After a scan, GET /__clients must report 0.
  unmanaged  returns neither, so the clients remain. After a scan, GET /__clients
             must report the 3 the rules registered (batesian-cd, batesian-probe,
             batesian-ssrf).

The property under test is the cleanup-and-report-leftovers behaviour: the
scanner must leave no state behind when the server lets it clean up, and must say
so when it cannot.

The two postures run on separate ports (the fixture takes an optional port
argument) so a process that did not shut down cleanly between them cannot hold
the second posture's port. Run by .github/workflows/validation.yml.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

FIXTURE = os.environ.get("BATESIAN_FIXTURE", "testdata/mcp_oauth_dcr_server.py")
BINARY = os.environ.get("BATESIAN_BIN", "./batesian")
# Separate ports per posture: a leaked process from one cannot confound the other.
PORTS = {"managed": 7788, "unmanaged": 7789}


def _read(log):
    log.flush()
    log.seek(0)
    return log.read()


def wait_meta(base, proc, log, deadline_s=30):
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"fixture exited early (code {proc.returncode}); log:\n{_read(log)}")
        try:
            with urllib.request.urlopen(f"{base}/.well-known/oauth-authorization-server", timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:  # noqa: BLE001 - not ready yet
            time.sleep(0.5)
    raise RuntimeError(f"fixture did not serve metadata within {deadline_s}s; log:\n{_read(log)}")


def start(posture):
    port = PORTS[posture]
    base = f"http://127.0.0.1:{port}"
    log = tempfile.NamedTemporaryFile("w+", suffix="-dcr.log", delete=False, encoding="utf-8")
    proc = subprocess.Popen([sys.executable, FIXTURE, posture, str(port)],
                            stdout=log, stderr=subprocess.STDOUT, text=True)
    try:
        wait_meta(base, proc, log)
    except Exception:
        stop(proc, log)
        raise
    return proc, log, base


def stop(proc, log=None):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    if log is not None:
        try:
            log.close()
        except Exception:  # noqa: BLE001
            pass


def scan_count(base):
    """Run batesian, then GET /__clients and return (leftover client count, fired rules)."""
    out = subprocess.run([BINARY, "scan", "--target", base, "--output", "json", "--timeout", "20"],
                         capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise RuntimeError(f"batesian exited {out.returncode}:\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    findings = sorted({f["rule_id"] for f in json.loads(out.stdout).get("findings", [])})
    with urllib.request.urlopen(f"{base}/__clients", timeout=5) as r:
        doc = json.loads(r.read())
    return doc.get("count", 0), findings


def check(name, ok, detail):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    return ok


def main():
    ok = True
    for posture, expected in [("managed", 0), ("unmanaged", 3)]:
        proc, log, base = start(posture)
        try:
            count, findings = scan_count(base)
        finally:
            stop(proc, log)
        detail = "scan leaves 0 clients via RFC 7592 cleanup" if posture == "managed" \
            else "3 registered clients left behind (oauth-dcr, confused-deputy, metadata-ssrf)"
        ok &= check(f"oauth-dcr {posture} ({detail})", count == expected,
                    f"count={count} (expected {expected}); findings={findings}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
