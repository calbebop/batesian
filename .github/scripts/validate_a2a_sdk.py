#!/usr/bin/env python3
"""Check Batesian against a live agent built with the official A2A SDK."""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from importlib.metadata import version
from uuid import uuid4


PORT = 3120
BASE = f"http://127.0.0.1:{PORT}"
RPC = f"{BASE}/a2a/jsonrpc"
BINARY = os.environ.get("BATESIAN_BIN", "./batesian")


def request(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"A2A-Version": "1.0", "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


def wait_for_card(proc, log):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            return request(f"{BASE}/.well-known/agent-card.json")
        except Exception:
            time.sleep(0.5)
    log.seek(0)
    raise RuntimeError(f"SDK agent did not start:\n{log.read()}")


def run_batesian(*args):
    result = subprocess.run(
        [BINARY, *args], capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"batesian {args[0]} failed ({result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return json.loads(result.stdout)


def check_task_exchange():
    sent = request(
        RPC,
        {
            "jsonrpc": "2.0",
            "id": "send",
            "method": "SendMessage",
            "params": {
                "message": {
                    "role": 1,
                    "parts": [{"text": "hello"}],
                    "messageId": str(uuid4()),
                },
                "configuration": {"returnImmediately": True},
            },
        },
    )
    task_id = sent.get("result", {}).get("task", {}).get("id")
    if not task_id:
        raise AssertionError(f"SendMessage did not return a v1 task: {sent}")

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        fetched = request(
            RPC,
            {
                "jsonrpc": "2.0",
                "id": "get",
                "method": "GetTask",
                "params": {"id": task_id},
            },
        )
        task = fetched.get("result", {})
        if task.get("id") == task_id and task.get("status", {}).get("state") == "TASK_STATE_COMPLETED":
            print("[PASS] SDK SendMessage/GetTask task exchange")
            return
        time.sleep(0.2)
    raise AssertionError(f"SDK task did not complete: {fetched}")


def validate(card):
    interfaces = card.get("supportedInterfaces", [])
    if not any(i.get("protocolBinding") == "JSONRPC" and i.get("url") == RPC for i in interfaces):
        raise AssertionError(f"SDK card did not advertise JSON-RPC endpoint: {interfaces}")

    probed = run_batesian(
        "probe", "--target", BASE, "--protocol", "a2a", "--output", "json", "--timeout", "10"
    )
    if probed.get("target") != RPC or probed.get("agent_card", {}).get("name") != card.get("name"):
        raise AssertionError(f"Batesian did not resolve the SDK card and endpoint: {probed}")
    print("[PASS] Batesian card discovery and JSON-RPC routing")

    check_task_exchange()

    scanned = run_batesian(
        "scan", "--target", BASE, "--protocol", "a2a", "--rule-ids",
        "a2a-session-smuggle-001", "--output", "json", "--timeout", "10"
    )
    skipped = scanned.get("skipped", [])
    errors = scanned.get("errors", [])
    if skipped or errors:
        raise AssertionError(f"A2A rule was not exercised against the SDK: skipped={skipped} errors={errors}")
    findings = scanned.get("findings", [])
    if not any(
        finding.get("rule_id") == "a2a-session-smuggle-001"
        and finding.get("confidence") == "confirmed"
        for finding in findings
    ):
        raise AssertionError(f"expected confirmed SDK role injection, got {findings}")
    print("[PASS] Batesian confirmed role injection on the SDK wire")


def main():
    print(f"A2A SDK {version('a2a-sdk')}", flush=True)
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as log:
        proc = subprocess.Popen(
            [sys.executable, "testdata/a2a_sdk_agent.py", str(PORT)],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            validate(wait_for_card(proc, log))
        except Exception:
            log.seek(0)
            print(log.read(), file=sys.stderr)
            raise
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


if __name__ == "__main__":
    main()
