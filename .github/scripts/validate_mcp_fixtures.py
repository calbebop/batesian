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
  mcp_tool_param_traversal_*      vulnerable fires; patched silent. Patched pins
                                  the containment discriminator (generic refusal,
                                  no resolution echo), so silence means the
                                  boundary held rather than that the oracle was
                                  blind (#226).
  mcp_scope_confusion_server      vulnerable fires (limited token dispatches like
                                  full while anonymous is refused); patched and
                                  open stay silent - enforced scopes are a pass,
                                  an open server belongs to tools-unauth (#227).
  mcp_shadow_surface_server       shadow-open high, shadow-hardened medium, none
                                  silent: severity tracks whether a foreign origin
                                  can reach the surface, and a closed port is an
                                  answer, not could-not-tell (#228).
  mcp_tool_poisoning_server       poisoned fires checks 1-3 on one STABLE manifest;
                                  drifting alternates two benign manifests so only
                                  the drift check fires; clean silent. The split
                                  keeps drift from firing where content was the
                                  defect, and vice versa (#229).
  mcp_vulnerable_version_*        one patch below the fix fires citing advisories;
                                  exactly at the fix is silent (exclusive bound);
                                  unknown identity matches nothing because the
                                  table is closed, not heuristic (#230).

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


def traversal():
    """vulnerable fires confirmed/high; patched stays silent.

    The patched posture pins the discriminator rather than a vacuous pass: it
    refuses outside-root paths generically without echoing any resolution, so
    silence there means containment held, not that the oracle was blind."""
    ok_all = True
    rid = "mcp-tool-param-traversal-001"
    p, l = start("mcp_tool_param_traversal_server.py", 7805, "vulnerable")
    try:
        fired, _, _ = scan(7805)
    finally:
        stop(p, l)
    ok_all &= check("traversal vulnerable (fires)", rid in fired,
                    f"fired {sorted(fired)}")

    p, l = start("mcp_tool_param_traversal_server.py", 7805, "patched")
    try:
        fired, _, _ = scan(7805)
    finally:
        stop(p, l)
    ok_all &= check("traversal patched (silent)", rid not in fired,
                    f"fired {sorted(fired)}")
    return ok_all


def scope_confusion():
    """Both tokens authenticate; only the full one should reach delete_item.

    vulnerable ignores scopes entirely (limited dispatches like full) while an
    anonymous call is refused - the confirmed failure. patched refuses the
    limited token with insufficient_scope before validation. open authenticates
    nothing at all, which suppresses the rule because identity gates nothing
    (that surface belongs to mcp-tools-unauth-001)."""
    ok_all = True
    rid = "mcp-scope-confusion-001"
    principals = ["--token", "tok-a",
                  "--principal", "name=full,token=tok-a",
                  "--principal", "name=limited,token=tok-b"]
    for posture, expect_fire in [("vulnerable", True), ("patched", False), ("open", False)]:
        p, l = start("mcp_scope_confusion_server.py", 7806, posture)
        try:
            fired, skipped, _ = scan(7806, *principals)
        finally:
            stop(p, l)
        fires = rid in fired
        ok_all &= check(f"scope-confusion {posture}", fires == expect_fire,
                        f"{rid} {'fired' if fires else 'silent'}; skipped {rid in skipped}")
    return ok_all


def shadow_surface():
    """shadow-open is the full chain (unauthenticated plus foreign Origin
    accepted, high); shadow-hardened refuses the Origin twin (medium); none
    binds no second listener at all, and a closed port is an answer, so
    silence there is checked-and-absent."""
    ok_all = True
    rid = "mcp-shadow-surface-001"

    def severity_for(doc):
        for f in doc.get("findings", []):
            if f.get("rule_id") == rid:
                return f.get("severity")
        return None

    for posture, expect_sev in [("shadow-open", "high"), ("shadow-hardened", "medium"), ("none", None)]:
        p, l = start("mcp_shadow_surface_server.py", 7807, posture)
        try:
            fired, _, doc = scan(7807)
        finally:
            stop(p, l)
        sev = severity_for(doc)
        if expect_sev is None:
            ok_all &= check("shadow none (silent)", rid not in fired,
                            f"fired {sorted(fired)}")
        else:
            ok_all &= check(f"shadow {posture} ({expect_sev})",
                            rid in fired and sev == expect_sev,
                            f"severity {sev}; fired {sorted(fired)}")
    return ok_all


def tool_poisoning():
    """poisoned carries hidden characters, injection phrasing and a duplicate
    name pair in ONE stable manifest (checks 1-3 fire, drift must not);
    drifting alternates two benign manifests so ONLY the drift check fires;
    clean is factual, unique and stable."""
    ok_all = True
    rid = "mcp-tool-poisoning-001"
    p, l = start("mcp_tool_poisoning_server.py", 7808, "poisoned")
    try:
        fired, _, _ = scan(7808)
    finally:
        stop(p, l)
    ok_all &= check("poisoning poisoned (fires)", rid in fired,
                    f"fired {sorted(fired)}")

    p, l = start("mcp_tool_poisoning_server.py", 7808, "drifting")
    try:
        fired, _, _ = scan(7808)
    finally:
        stop(p, l)
    ok_all &= check("poisoning drifting (drift check fires)", rid in fired,
                    f"fired {sorted(fired)}")

    p, l = start("mcp_tool_poisoning_server.py", 7808, "clean")
    try:
        fired, _, _ = scan(7808)
    finally:
        stop(p, l)
    ok_all &= check("poisoning clean (silent)", rid not in fired,
                    f"fired {sorted(fired)}")
    return ok_all


def vulnerable_version():
    """One patch below the fix fires citing the advisory; exactly at the fix is
    silent (exclusive bound); an unrelated identity matches nothing because the
    table is closed rather than heuristic."""
    ok_all = True
    rid = "mcp-vulnerable-version-001"
    for posture, expect_fire in [("vulnerable", True), ("patched", False), ("unknown", False)]:
        p, l = start("mcp_vulnerable_version_server.py", 7809, posture)
        try:
            fired, _, _ = scan(7809)
        finally:
            stop(p, l)
        fires = rid in fired
        ok_all &= check(f"vulnerable-version {posture}", fires == expect_fire,
                        f"{rid} {'fired' if fires else 'silent'}")
    return ok_all


def task_entropy():
    """weak mints counter handles (sequential + thin alphabet, the extension's
    bearer-token MUST broken); clean mints uuid-shaped handles and must be
    fully silent."""
    ok_all = True
    rid = "mcp-task-id-entropy-001"

    p, l = start("mcp_task_entropy_server.py", 7812, "weak")
    try:
        fired, _, _ = scan(7812)
    finally:
        stop(p, l)
    ok_all &= check("task-entropy weak (fires)", rid in fired, f"fired {sorted(fired)}")

    p, l = start("mcp_task_entropy_server.py", 7812, "clean")
    try:
        fired, _, _ = scan(7812)
    finally:
        stop(p, l)
    ok_all &= check("task-entropy clean (silent)", rid not in fired,
                    f"fired {sorted(fired)}")
    return ok_all


def main():
    suites = [
        ("transient", transient()),
        ("session-as-credential", session_as_credential()),
        ("log-optin", log_optin()),
        ("large-body", large_body()),
        ("traversal", traversal()),
        ("scope-confusion", scope_confusion()),
        ("shadow-surface", shadow_surface()),
        ("tool-poisoning", tool_poisoning()),
        ("vulnerable-version", vulnerable_version()),
        ("task-entropy", task_entropy()),
    ]
    print()
    for name, ok in suites:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    return 0 if all(ok for _, ok in suites) else 1


if __name__ == "__main__":
    sys.exit(main())
