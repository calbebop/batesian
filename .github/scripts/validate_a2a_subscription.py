#!/usr/bin/env python3
"""Check subscription findings against vulnerable and bound A2A fixtures."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time

from validation_outcomes import rule_statuses


BASE = "http://127.0.0.1:3107"
RULE = "a2a-subscription-scope-001"
BINARY = os.environ.get("BATESIAN_BIN", "./batesian")


def wait_for_fixture(proc, log):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", 3107), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    log.seek(0)
    raise RuntimeError(f"subscription fixture did not start:\n{log.read()}")


def scan(posture):
    env = os.environ.copy()
    env["BATESIAN_PUSH_POSTURE"] = posture
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as log:
        proc = subprocess.Popen(
            [sys.executable, "testdata/a2a_push_binding_server.py"],
            stdout=log, stderr=subprocess.STDOUT, env=env,
        )
        try:
            wait_for_fixture(proc, log)
            completed = subprocess.run(
                [BINARY, "scan", "--target", BASE, "--protocol", "a2a",
                 "--rule-ids", RULE,
                 "--principal", "name=tenant-a,token=tok-a,tenant=A",
                 "--principal", "name=tenant-b,token=tok-b,tenant=B",
                 "--output", "json", "--timeout", "5"],
                capture_output=True, text=True, timeout=90, check=False,
            )
            if completed.returncode:
                raise AssertionError(f"scan failed: {completed.stdout}\n{completed.stderr}")
            return json.loads(completed.stdout)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def validate():
    vulnerable = scan("vulnerable")
    findings = [finding for finding in vulnerable.get("findings", []) if finding.get("rule_id") == RULE]
    if rule_statuses(vulnerable, {RULE})[RULE] != "findings" or len(findings) != 1:
        raise AssertionError(f"vulnerable subscription was not reported: {vulnerable}")
    finding = findings[0]
    if finding.get("confidence") != "indicator" or "task-tenant-a" in json.dumps(finding):
        raise AssertionError(f"subscription finding overstated or leaked task ID: {finding}")
    print("[PASS] vulnerable subscription reported as an indicator")

    bound = scan("bound")
    if rule_statuses(bound, {RULE})[RULE] != "no_findings" or bound.get("findings"):
        raise AssertionError(f"bound subscription was not clean: {bound}")
    print("[PASS] bound subscription returned no findings")


if __name__ == "__main__":
    validate()
