#!/usr/bin/env python3
"""CI validation harness for testdata/a2a_secured_agent.py.

a2a_secured_agent.py is the only fixture in testdata/ that ENFORCES
authorization, so it is the false-positive gate the A2A rules have never had in
CI: every prior validation ran against no-auth servers, where the cross-principal
rules' discriminators suppress. Pointing the scanner at an agent that enforces
authorization is what found three shipped A2A false negatives (#175, #176, #177),
and none of that was reachable from a fixture or the Go harness.

This harness starts the fixture in each of its three postures, runs a real
`batesian scan` against it, and asserts the documented outcome
(testdata/README.md). It exits non-zero on any mismatch and prints the fired vs
expected rule ids so a regression is immediately readable.

  secured     -> 0 findings. Any finding is a false positive.
  idor        -> the five ownership rules fire:
                 a2a-multitenant-isolation-001, a2a-delegation-integrity-001,
                 a2a-task-cancel-idor-001, a2a-push-binding-001,
                 a2a-task-enumeration-001
  unauth-read -> a2a-task-idor-001 fires

Run by .github/workflows/validation.yml; not meant for any target other than the
local fixture.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HOST = "127.0.0.1"
PORT = 3111
BASE = f"http://{HOST}:{PORT}"
CARD_URL = f"{BASE}/.well-known/agent-card.json"
FIXTURE = os.environ.get("BATESIAN_FIXTURE", "testdata/a2a_secured_agent.py")
BINARY = os.environ.get("BATESIAN_BIN", "./batesian")
SCAN_TIMEOUT = 20  # seconds, per request

# Rule ids that MUST fire on the idor posture (membership, not count: some fire
# more than once).
IDOR_RULES = {
    "a2a-multitenant-isolation-001",
    "a2a-delegation-integrity-001",
    "a2a-task-cancel-idor-001",
    "a2a-push-binding-001",
    "a2a-task-enumeration-001",
}

# Two principals are required by the cross-principal rules; --token drives the
# rules that read a single credential. Verbatim from the fixture's docstring.
SCAN_ARGS = [
    "scan",
    "--target", BASE,
    "--token", "tok-a",
    "--principal", "name=a,token=tok-a,tenant=A",
    "--principal", "name=b,token=tok-b,tenant=B",
    "--output", "json",
    "--timeout", str(SCAN_TIMEOUT),
]


def _read(log):
    log.flush()
    log.seek(0)
    return log.read()


def wait_for_card(proc, log, deadline_s=40):
    """Poll the agent card until the fixture serves it, surfacing the log on failure."""
    deadline = time.time() + deadline_s
    last_err = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"fixture exited early with code {proc.returncode}; log:\n{_read(log)}")
        try:
            with urllib.request.urlopen(CARD_URL, timeout=2) as r:
                if r.status == 200:
                    return
        except Exception as e:  # noqa: BLE001 - any error means not ready yet
            last_err = e
        time.sleep(0.5)
    raise RuntimeError(f"fixture did not serve {CARD_URL} within {deadline_s}s ({last_err}); log:\n{_read(log)}")


def start_fixture(posture):
    """Start the fixture, logging to a temp file.

    A pipe would deadlock: uvicorn logs every request and fills the OS buffer,
    blocking the server so the scan times out. A file is bounded only by disk and
    is still readable on failure (the era-watch workflow does the same).
    """
    log = tempfile.NamedTemporaryFile("w+", suffix="-fixture.log", delete=False, encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, FIXTURE, posture],
        stdout=log, stderr=subprocess.STDOUT, text=True,
    )
    try:
        wait_for_card(proc, log)
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
        except Exception:  # noqa: BLE001 - best-effort cleanup of a temp file handle
            pass


def fired_rules():
    """Run batesian and return (set of fired rule ids, parsed json doc)."""
    out = subprocess.run([BINARY, *SCAN_ARGS], capture_output=True, text=True, timeout=180)
    # batesian exits non-zero only on operational error, not on findings, so a
    # non-zero exit here is itself a regression worth surfacing with the output.
    if out.returncode != 0:
        raise RuntimeError(f"batesian scan exited {out.returncode}:\nstdout:\n{out.stdout}\nstderr:\n{out.stderr}")
    doc = json.loads(out.stdout)
    return {f["rule_id"] for f in doc.get("findings", [])}, doc


def check(name, ok, detail):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")
    return ok


def scan_posture(posture):
    proc, log = start_fixture(posture)
    try:
        return fired_rules()
    finally:
        stop_fixture(proc, log)


def main():
    all_ok = True

    rules, doc = scan_posture("secured")
    total = doc.get("summary", {}).get("total", len(rules))
    ok = total == 0 and len(rules) == 0
    all_ok &= ok
    check("secured (false-positive gate: no rule may fire)", ok,
          f"expected 0 findings, got {total}: {sorted(rules)}")

    rules, _ = scan_posture("idor")
    missing = IDOR_RULES - rules
    ok = not missing
    all_ok &= ok
    check("idor (the five ownership rules must fire)", ok,
          f"missing {sorted(missing)}; fired {sorted(rules)}")

    rules, _ = scan_posture("unauth-read")
    ok = "a2a-task-idor-001" in rules
    all_ok &= ok
    check("unauth-read (a2a-task-idor-001 must fire)", ok,
          f"a2a-task-idor-001 {'present' if ok else 'ABSENT'}; fired {sorted(rules)}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
