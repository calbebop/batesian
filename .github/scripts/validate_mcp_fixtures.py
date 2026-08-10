#!/usr/bin/env python3
"""CI validation harness for the MCP "property" fixtures in testdata/.

Companion to validate_secured_agent.py (#195). Each fixture below pins one
regression class by asserting a property that has broken before, so a regression
is a difference the gate catches:

  mcp_transient_failure_server    ok / 401 / 502 all differ. 401 reading like 502
                                  (a refusal like an undetermined probe) is the
                                  probe-honesty bug (#146/#149).
  mcp_session_as_credential_*     vulnerable + open-handshake fire; patched +
                                  session-presence-auth silent. session-presence-auth
                                  is the C# SDK shape that false-positived until the
                                  anonymous-handshake control landed (#171).
  mcp_log_optin_server            always fires; on-optin silent; never NOT TESTED.
                                  never is the one that matters: emitting logs is a
                                  MAY, so silence there must read as not-tested, not
                                  clean (#184).
  mcp_large_body_server           large finding set == small finding set. A body
                                  read limit that truncates silently made the large
                                  server hide every unauth finding (S8).

Run by .github/workflows/validation.yml.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

BINARY = os.environ.get("BATESIAN_BIN", "./batesian")
FIXTURE_DIR = os.environ.get("BATESIAN_FIXTURE_DIR", "testdata")
SCAN_TIMEOUT = "20"

UNAUTH_FAMILY = {
    "mcp-tools-unauth-001",
    "mcp-resources-unauth-001",
    "mcp-prompts-unauth-001",
    "mcp-completion-unauth-001",
    "mcp-logging-unauth-001",
}


def _read(log):
    log.flush()
    log.seek(0)
    return log.read()


def wait_for_mcp(proc, log, port, deadline_s=40):
    """Poll POST /mcp until the fixture responds. Any HTTP status counts as up; a
    connection refused or timeout does not. (A modern-only fixture answers
    `initialize` with an error status, which still means it is serving.)"""
    url = f"http://127.0.0.1:{port}/mcp"
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "ci", "version": "1"}},
    }).encode()
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"fixture exited early (code {proc.returncode}); log:\n{_read(log)}")
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2)
            return  # 2xx
        except urllib.error.HTTPError:
            return  # the server answered; it is up
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    raise RuntimeError(f"fixture on {url} not ready within {deadline_s}s; log:\n{_read(log)}")


def start(script, port, *args):
    """Start a testdata fixture, logging to a temp file (a pipe deadlocks uvicorn)."""
    log = tempfile.NamedTemporaryFile("w+", suffix="-mcp-fixture.log", delete=False, encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(FIXTURE_DIR, script), *args],
        stdout=log, stderr=subprocess.STDOUT, text=True,
    )
    try:
        wait_for_mcp(proc, log, port)
    except Exception:
        stop(proc, log)
        raise
    return proc, log


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


def scan(port, *extra):
    """Run batesian; return (fired rule-id set, skipped rule-id set, doc)."""
    out = subprocess.run(
        [BINARY, "scan", "--target", f"http://127.0.0.1:{port}", "--output", "json",
         "--timeout", SCAN_TIMEOUT, *extra],
        capture_output=True, text=True, timeout=180,
    )
    if out.returncode != 0:
        raise RuntimeError(f"batesian scan exited {out.returncode}:\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    doc = json.loads(out.stdout)
    fired = {f["rule_id"] for f in doc.get("findings", [])}
    skipped = {s["rule_id"] for s in doc.get("skipped", [])}
    return fired, skipped, doc


def check(name, ok, detail):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    return ok


def transient():
    """ok fires, 401 is clean, 502 is not-tested. They must all differ.

    The property is scoped to the unauth family — the surface the ok/401/502 mode
    varies. The fixture leaves Origin unvalidated, so mcp-dns-rebind-origin-001
    fires in every mode; that is a different surface, not part of this property,
    so it is excluded rather than asserted against."""
    ok_all = True

    p, l = start("mcp_transient_failure_server.py", 7802, "7802", "ok")
    try:
        fired, _, _ = scan(7802)
    finally:
        stop(p, l)
    fired_unauth = fired & UNAUTH_FAMILY
    ok_all &= check("transient ok (the unauth family fires)", bool(fired_unauth),
                    f"unauth fired {sorted(fired_unauth)}")

    p, l = start("mcp_transient_failure_server.py", 7802, "7802", "401")
    try:
        fired, skipped, _ = scan(7802)
    finally:
        stop(p, l)
    # 401 is auth enforced: the unauth family ran and found nothing (clean) —
    # neither firing nor skipped.
    ok_all &= check("transient 401 (unauth family clean, auth enforced)",
                    not (fired & UNAUTH_FAMILY) and not (skipped & UNAUTH_FAMILY),
                    f"unauth fired {sorted(fired & UNAUTH_FAMILY)}; skipped {sorted(skipped & UNAUTH_FAMILY)}")

    p, l = start("mcp_transient_failure_server.py", 7802, "7802", "502")
    try:
        fired, skipped, _ = scan(7802)
    finally:
        stop(p, l)
    # 502 is an undetermined probe: the unauth family is not-tested (skipped), the
    # outcome distinct from the 401 clean. If 502 ever reads like 401 (clean), the
    # probe-honesty conflation is back.
    ok_all &= check("transient 502 (unauth family not tested, distinct from clean)",
                    not (fired & UNAUTH_FAMILY) and bool(skipped & UNAUTH_FAMILY),
                    f"unauth fired {sorted(fired & UNAUTH_FAMILY)}; skipped {sorted(skipped & UNAUTH_FAMILY)}")
    return ok_all


def session_as_credential():
    """vulnerable/open-handshake fire; patched/session-presence-auth silent."""
    ok_all = True
    rid = "mcp-session-as-credential-001"
    for posture, expect_fire in [("vulnerable", True), ("open-handshake", True),
                                 ("patched", False), ("session-presence-auth", False)]:
        p, l = start("mcp_session_as_credential_server.py", 7803, posture)
        try:
            fired, _, _ = scan(7803, "--token", "tok-a")
        finally:
            stop(p, l)
        fires = rid in fired
        ok_all &= check(f"session-as-credential {posture}", fires == expect_fire,
                        f"{rid} {'fired' if fires else 'silent'} (expect {'fire' if expect_fire else 'silent'})")
    return ok_all


def log_optin():
    """always fires; on-optin silent; never not-tested (not clean)."""
    ok_all = True
    rid = "mcp-log-optin-001"

    p, l = start("mcp_log_optin_server.py", 7804, "always")
    try:
        fired, _, _ = scan(7804)
    finally:
        stop(p, l)
    ok_all &= check("log-optin always (fires)", rid in fired, str(sorted(fired)))

    p, l = start("mcp_log_optin_server.py", 7804, "on-optin")
    try:
        fired, _, _ = scan(7804)
    finally:
        stop(p, l)
    ok_all &= check("log-optin on-optin (silent)", rid not in fired, str(sorted(fired)))

    p, l = start("mcp_log_optin_server.py", 7804, "never")
    try:
        fired, skipped, _ = scan(7804)
    finally:
        stop(p, l)
    ok_all &= check("log-optin never (not tested, not clean)",
                    rid not in fired and rid in skipped,
                    f"fired {sorted(fired)}; skipped {sorted(skipped)}")
    return ok_all


def large_body():
    """A large response set must equal a small one; truncation made it smaller."""
    p, l = start("mcp_large_body_server.py", 7801, "7801", "1200")
    try:
        large, _, _ = scan(7801)
    finally:
        stop(p, l)
    p, l = start("mcp_large_body_server.py", 7801, "7801", "8")
    try:
        small, _, _ = scan(7801)
    finally:
        stop(p, l)
    return check("large-body (large finding set == small finding set)",
                 large == small, f"large {sorted(large)}; small {sorted(small)}")


def main():
    suites = [
        ("transient", transient()),
        ("session-as-credential", session_as_credential()),
        ("log-optin", log_optin()),
        ("large-body", large_body()),
    ]
    print()
    for name, ok in suites:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    return 0 if all(ok for _, ok in suites) else 1


if __name__ == "__main__":
    sys.exit(main())
