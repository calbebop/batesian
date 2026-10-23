#!/usr/bin/env python3
"""Validate A2A authorization rules against the secured-agent fixture."""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

from validation_outcomes import finding_quality_issues, incomplete_rules, rule_statuses

HOST = "127.0.0.1"
PORT = 3111
BASE = f"http://{HOST}:{PORT}"
CARD_URL = f"{BASE}/.well-known/agent-card.json"
FIXTURE = os.environ.get("BATESIAN_FIXTURE", "testdata/a2a_secured_agent.py")
BINARY = os.environ.get("BATESIAN_BIN", "./batesian")
SCAN_TIMEOUT = 20  # seconds, per request

# Rule ids that must fire on the idor posture.
IDOR_RULES = {
    "a2a-multitenant-isolation-001",
    "a2a-delegation-integrity-001",
    "a2a-task-cancel-idor-001",
    "a2a-task-enumeration-001",
}
PUSH_RULE = "a2a-push-binding-001"
SECURED_RULES = IDOR_RULES | {PUSH_RULE, "a2a-task-idor-001"}
IDOR_CONFIDENCE = {rid: "confirmed" for rid in IDOR_RULES}
IDOR_CONFIDENCE["a2a-task-enumeration-001"] = "indicator"

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
    skipped, errors = incomplete_rules(doc, SECURED_RULES)
    statuses = rule_statuses(doc, SECURED_RULES)
    ok = total == 0 and len(rules) == 0 and not skipped and not errors and \
        all(status == "no_findings" for status in statuses.values())
    all_ok &= ok
    check("secured (authorization rules complete cleanly)", ok,
          f"total={total}; findings={sorted(rules)}; skipped={skipped}; errors={errors}")

    rules, doc = scan_posture("idor")
    missing = IDOR_RULES - rules
    statuses = rule_statuses(doc, IDOR_RULES)
    quality = finding_quality_issues(doc, IDOR_CONFIDENCE)
    ok = not missing and not quality and PUSH_RULE not in rules and \
        all(status == "findings" for status in statuses.values())
    all_ok &= ok
    check("idor (four ownership rules fire; push binding stays inconclusive)", ok,
          f"missing {sorted(missing)}; quality {quality}; fired {sorted(rules)}")

    rules, doc = scan_posture("push-binding")
    quality = finding_quality_issues(doc, {PUSH_RULE: "confirmed"})
    unexpected = rules & (SECURED_RULES - {PUSH_RULE})
    ok = PUSH_RULE in rules and not quality and not unexpected and \
        rule_statuses(doc, {PUSH_RULE})[PUSH_RULE] == "findings"
    all_ok &= ok
    check("push-binding (scoped task reads, unscoped push config)", ok,
          f"quality {quality}; unexpected {sorted(unexpected)}; fired {sorted(rules)}")

    rules, doc = scan_posture("idor-paged")
    quality = finding_quality_issues(doc, {"a2a-task-enumeration-001": "indicator"})
    ok = "a2a-task-enumeration-001" in rules and \
        rule_statuses(doc, {"a2a-task-enumeration-001"})["a2a-task-enumeration-001"] == "findings" and not quality
    all_ok &= ok
    check("idor-paged (task enumeration must fire)", ok,
          f"quality {quality}; fired {sorted(rules)}")

    rules, doc = scan_posture("unauth-read")
    quality = finding_quality_issues(doc, {"a2a-task-idor-001": "confirmed"})
    ok = "a2a-task-idor-001" in rules and \
        rule_statuses(doc, {"a2a-task-idor-001"})["a2a-task-idor-001"] == "findings" and not quality
    all_ok &= ok
    check("unauth-read (a2a-task-idor-001 must fire)", ok,
          f"quality {quality}; fired {sorted(rules)}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
