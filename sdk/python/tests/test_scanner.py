"""Tests for batesian._scanner.Scanner.

The binary is never actually invoked in these tests. Instead, subprocess.run
is monkeypatched to return controlled JSON output, isolating the SDK logic
from the Go binary.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from batesian._models import Results, ScanError
from batesian._scanner import Scanner
from batesian._binary import BinaryNotFoundError


MOCK_FINDINGS = [
    {
        "rule_id": "a2a-push-ssrf-001",
        "rule_name": "A2A Push Notification SSRF",
        "severity": "high",
        "confidence": "confirmed",
        "title": "Server made outbound request",
        "description": "OOB callback received.",
        "evidence": "HTTP GET from 1.2.3.4",
        "remediation": "Validate callback URLs.",
        "target_url": "https://agent.example.com",
    }
]

MOCK_JSON_OUTPUT = json.dumps(
    {
        "target": "https://agent.example.com",
        "findings": MOCK_FINDINGS,
        "rules_run": 1,
        "duration_ms": 500,
    }
)


def _mock_proc(stdout: str = MOCK_JSON_OUTPUT, returncode: int = 0, stderr: str = "") -> MagicMock:
    mock = MagicMock()
    mock.stdout = stdout
    mock.stderr = stderr
    mock.returncode = returncode
    return mock


@pytest.fixture
def scanner():
    with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
        return Scanner(target="https://agent.example.com", timeout=10)


class TestScannerRun:
    def test_returns_results_with_findings(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            results = scanner.run()
        assert isinstance(results, Results)
        assert len(results.findings) == 1
        assert results.findings[0].rule_id == "a2a-push-ssrf-001"
        assert results.findings[0].confidence == "confirmed"
        assert results.findings[0].is_confirmed is True
        assert results.high_count == 1
        assert results.critical_count == 0

    def test_passes_target_to_cli(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run()
        cmd = mock_run.call_args[0][0]
        assert "--target" in cmd
        assert "https://agent.example.com" in cmd

    def test_uses_json_output_format(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run()
        cmd = mock_run.call_args[0][0]
        assert "--output" in cmd
        assert "json" in cmd

    def test_passes_rule_ids(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(rules=["a2a-push-ssrf-001", "mcp-tool-poison-001"])
        cmd = mock_run.call_args[0][0]
        assert "--rule-ids" in cmd
        assert "a2a-push-ssrf-001,mcp-tool-poison-001" in cmd

    def test_passes_protocol(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(protocol="mcp")
        cmd = mock_run.call_args[0][0]
        assert "--protocol" in cmd
        assert "mcp" in cmd

    def test_passes_severities(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(severities=["critical", "high"])
        cmd = mock_run.call_args[0][0]
        assert "--severity" in cmd
        assert "critical,high" in cmd

    def test_passes_oob_flag(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(oob=True)
        cmd = mock_run.call_args[0][0]
        assert "--oob" in cmd

    def test_oob_url_overrides_oob_flag(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(oob=True, oob_url="https://oob.example.com/tok")
        cmd = mock_run.call_args[0][0]
        assert "--oob-url" in cmd
        assert "--oob" not in cmd

    def test_raises_scan_error_on_empty_output(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc(stdout="")):
            with pytest.raises(ScanError, match="no output"):
                scanner.run()

    def test_raises_scan_error_on_invalid_json(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc(stdout="not json")):
            with pytest.raises(ScanError, match="parse"):
                scanner.run()

    def test_raises_scan_error_on_timeout(self, scanner):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="batesian", timeout=10)):
            with pytest.raises(ScanError, match="timed out"):
                scanner.run()

    def test_zero_findings_is_valid(self, scanner):
        empty_output = json.dumps({"target": "https://x.com", "findings": [], "rules_run": 5, "duration_ms": 100})
        with patch("subprocess.run", return_value=_mock_proc(stdout=empty_output)):
            results = scanner.run()
        assert results.critical_count == 0
        assert results.findings == []

    def test_token_passed_to_cli(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://x.com", token="secret-token")
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--token" in cmd
        assert "secret-token" in cmd

    def test_oauth_flags_passed(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(
                target="https://x.com",
                token_url="https://auth.example.com/token",
                client_id="my-client",
                client_secret="my-secret",
                oauth_scopes=["read", "write"],
            )
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--token-url" in cmd
        assert "--client-id" in cmd
        assert "--client-secret" in cmd
        assert "--oauth-scopes" in cmd
        assert "read,write" in cmd

    def test_oauth_audience_passed(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(
                target="https://x.com",
                token_url="https://auth.example.com/token",
                client_id="my-client",
                client_secret="my-secret",
                oauth_audience="https://api.example.com",
            )
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--oauth-audience" in cmd
        assert "https://api.example.com" in cmd

    def test_pkce_auth_url_passed(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(
                target="https://mcp.example.com",
                auth_url="https://auth.example.com/authorize",
                token_url="https://auth.example.com/token",
                client_id="my-client",
                oauth_scopes=["mcp:read"],
            )
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--auth-url" in cmd
        assert "https://auth.example.com/authorize" in cmd
        # Client secret must NOT be sent for PKCE.
        assert "--client-secret" not in cmd

    def test_pkce_redirect_port_passed(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(
                target="https://mcp.example.com",
                auth_url="https://auth.example.com/authorize",
                token_url="https://auth.example.com/token",
                client_id="my-client",
                redirect_port=12345,
            )
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--redirect-port" in cmd
        idx = cmd.index("--redirect-port")
        assert cmd[idx + 1] == "12345"

    def test_pkce_no_browser_flag(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(
                target="https://mcp.example.com",
                auth_url="https://auth.example.com/authorize",
                token_url="https://auth.example.com/token",
                client_id="my-client",
                no_browser=True,
            )
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--no-browser" in cmd

    def test_no_browser_omitted_by_default(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://x.com")
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--no-browser" not in cmd
        assert "--auth-url" not in cmd
        assert "--redirect-port" not in cmd

    def test_verbose_flag_passed(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://x.com", verbose=True)
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "-v" in cmd


    def test_raises_scan_error_on_nonzero_exit(self, scanner):
        """Non-zero returncode with valid JSON must still raise ScanError."""
        with patch("subprocess.run", return_value=_mock_proc(returncode=1, stderr="internal error")):
            with pytest.raises(ScanError, match="exited with code 1"):
                scanner.run()

    def test_passes_tags_to_cli(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(tags=["injection", "auth"])
        cmd = mock_run.call_args[0][0]
        assert "--tags" in cmd
        assert "injection,auth" in cmd

    def test_passes_rules_dir(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(rules_dir="/custom/rules")
        cmd = mock_run.call_args[0][0]
        assert "--rules-dir" in cmd
        assert "/custom/rules" in cmd


class TestScannerProbe:
    def _probe_output(self):
        return json.dumps({"name": "Test Agent", "url": "https://agent.example.com", "flags": []})

    def test_probe_returns_dict(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com")
        output = self._probe_output()
        with patch("subprocess.run", return_value=_mock_proc(stdout=output)):
            result = s.probe()
        assert isinstance(result, dict)
        assert result["name"] == "Test Agent"

    def test_probe_passes_protocol(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com")
        with patch("subprocess.run", return_value=_mock_proc(stdout=self._probe_output())) as mock_run:
            s.probe(protocol="mcp")
        cmd = mock_run.call_args[0][0]
        assert "probe" in cmd
        assert "--protocol" in cmd
        assert "mcp" in cmd

    def test_probe_raises_on_empty_output(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com")
        with patch("subprocess.run", return_value=_mock_proc(stdout="")):
            with pytest.raises(ScanError, match="no output"):
                s.probe()

    def test_probe_raises_on_nonzero_exit(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com")
        with patch("subprocess.run", return_value=_mock_proc(stdout=self._probe_output(), returncode=1)):
            with pytest.raises(ScanError, match="exited with code 1"):
                s.probe()

    def test_probe_passes_token(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com", token="my-tok")
        with patch("subprocess.run", return_value=_mock_proc(stdout=self._probe_output())) as mock_run:
            s.probe()
        cmd = mock_run.call_args[0][0]
        assert "--token" in cmd
        assert "my-tok" in cmd

    def test_probe_raises_on_invalid_json(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com")
        with patch("subprocess.run", return_value=_mock_proc(stdout="not json")):
            with pytest.raises(ScanError, match="parse"):
                s.probe()

    def test_probe_raises_on_timeout(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="batesian", timeout=60)):
            with pytest.raises(ScanError, match="timed out"):
                s.probe()

    def test_probe_passes_skip_tls(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com", skip_tls=True)
        with patch("subprocess.run", return_value=_mock_proc(stdout=self._probe_output())) as mock_run:
            s.probe()
        cmd = mock_run.call_args[0][0]
        assert "--skip-tls" in cmd

    def test_probe_passes_config(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com", config="/tmp/batesian.yaml")
        with patch("subprocess.run", return_value=_mock_proc(stdout=self._probe_output())) as mock_run:
            s.probe()
        cmd = mock_run.call_args[0][0]
        assert "--config" in cmd
        assert "/tmp/batesian.yaml" in cmd

    def test_probe_passes_verbose(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://agent.example.com", verbose=True)
        with patch("subprocess.run", return_value=_mock_proc(stdout=self._probe_output())) as mock_run:
            s.probe()
        cmd = mock_run.call_args[0][0]
        assert "-v" in cmd


class TestScannerBuildCommand:
    def test_skip_tls_flag(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://x.com", skip_tls=True)
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--skip-tls" in cmd

    def test_config_file_passed(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://x.com", config="/path/to/batesian.yaml")
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--config" in cmd
        assert "/path/to/batesian.yaml" in cmd
