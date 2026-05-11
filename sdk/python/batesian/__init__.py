"""
Batesian Python SDK

Thin wrapper around the Batesian CLI binary. Invokes the binary as a subprocess,
passes arguments, parses JSON output, and returns typed Python objects.

Usage::

    from batesian import Scanner

    scanner = Scanner(target="https://agent.example.com")
    results = scanner.run(rules=["a2a-push-ssrf-001", "mcp-tool-poison-001"])

    for finding in results.findings:
        print(f"[{finding.severity}] {finding.rule_id}: {finding.title}")

    assert results.critical_count == 0
"""

from batesian._scanner import Scanner
from batesian._models import Results, Finding, ScanError
from batesian._binary import find_binary, BinaryNotFoundError

__all__ = ["Scanner", "Results", "Finding", "ScanError", "find_binary", "BinaryNotFoundError"]
__version__ = "0.1.0"
