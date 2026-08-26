#!/usr/bin/env python3
"""CI validation harness for the A2A push-callback-auth fixture.

Companion to validate_secured_agent.py. a2a-push-callback-auth-001 grades what
an agent's outgoing push notification carried, which needs a live OOB listener:
batesian starts its own during the scan, so the harness only has to start the
fixture and read the verdict.

  unsigned    -> the agent accepted the integrity token at registration and
                 dropped it on the outbound call: the rule MUST fire.
                 Receivers get nothing to authenticate, so completions can be
                 forged (#231).
  signed      -> the callback presents the configured token in the documented
                 header: the boundary held, the rule MUST stay silent.
  nocallback  -> registration accepted but no outbound call ever made: the
                 oracle never ran, so the rule MUST report NOT TESTED (skipped),
                 never clean - silence there is could-not-tell, not secure.

Only the v1.0 two-step wire is served, so --rule-ids isolates the rule under
test from unrelated A2A discovery noise.

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
FIXTURE = os.environ.get("BATESIAN_FIXTURE", "testdata/a2a_push_callback_auth_server.py")
PORT = 7810
RULE = "a2a-push-callback-auth-001"

SCAN_ARGS = [
    "scan",
    "--target", f"http://127.0.0.1:{PORT}",
    "--rule-ids", RULE,
    "--output", "json",
    "--timeout", "20",
]


def _read(log):
    log.flush()
    log.seek(0)
    return log.read()


def _ready(deadline_s=40):
    """Poll POST / until uvicorn answers. Any HTTP status counts as up."""
    url = f"http://127.0.0.1:{PORT}"
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                  "clientInfo": {"name": "ci", "version": "1"}}}).encode()
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=2)
            return
        except urllib.error.HTTPError:
            return
        except (urllib.error.URLError, OSError):
            time.sleep(0.25)
    raise RuntimeError(f"fixture on {url} not ready within {deadline_s}s")


def start_fixture(posture):
    log = tempfile.NamedTemporaryFile("w+", suffix="-cbauth-fixture.log", delete=False,
                                      encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, FIXTURE, posture],
        stdout=log, stderr=subprocess.STDOUT, text=True,
    )
    try:
        _ready()
    except Exception:
        stop_fixture(proc, log)
        raise
    return proc, log


def stop_fixture(proc, log=None):
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


def scan():
    out = subprocess.run([BINARY, *SCAN_ARGS], capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        raise RuntimeError(f"batesian scan exited {out.returncode}:\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    doc = json.loads(out.stdout)
    fired = {f["rule_id"] for f in doc.get("findings", [])}
    skipped = {s["rule_id"] for s in doc.get("skipped", [])}
    return fired, skipped


def check(name, ok, detail):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    return ok


def main():
    ok_all = True

    for posture, expect in [("unsigned", "fire"), ("signed", "silent")]:
        proc, log = start_fixture(posture)
        try:
            fired, skipped = scan()
        finally:
            stop_fixture(proc, log)
        # "Ran and found nothing" must be distinguishable from "never ran": a
        # skip here means the fixture was not exercised, which would make the
        # signed pass vacuous.
        ran = RULE in fired or RULE not in skipped
        fires = RULE in fired
        ok_all &= check(f"{posture} (must {expect})", ran and fires == (expect == "fire"),
                        f"{RULE} {'fired' if fires else ('skipped' if not ran else 'silent')}")

    proc, log = start_fixture("nocallback")
    try:
        fired, skipped = scan()
    finally:
        stop_fixture(proc, log)
    not_tested = RULE in skipped
    ok_all &= check("nocallback (not tested, never clean)",
                    not_tested and RULE not in fired,
                    f"fired {RULE in fired}; skipped {RULE in skipped}")

    print()
    print(f"[{'PASS' if ok_all else 'FAIL'}] push-callback-auth")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
