"""Tests for batesian._models."""

import pytest
from batesian._models import Finding, Results, ScanError


FINDING_DICT = {
    "rule_id": "a2a-push-ssrf-001",
    "rule_name": "A2A Push Notification SSRF",
    "severity": "high",
    "confidence": "confirmed",
    "title": "Server made outbound request to attacker-controlled URL",
    "description": "The push notification callback was delivered.",
    "evidence": "OOB callback received from 1.2.3.4",
    "remediation": "Validate callback URLs against an allowlist.",
    "target_url": "https://agent.example.com",
}


class TestFinding:
    def test_from_dict_all_fields(self):
        f = Finding.from_dict(FINDING_DICT)
        assert f.rule_id == "a2a-push-ssrf-001"
        assert f.severity == "high"
        assert f.confidence == "confirmed"
        assert f.is_confirmed is True
        assert f.is_high is True
        assert f.is_critical is False

    def test_from_dict_missing_fields_defaults_to_empty(self):
        f = Finding.from_dict({})
        assert f.rule_id == ""
        assert f.severity == ""
        assert f.is_confirmed is False

    def test_is_critical(self):
        f = Finding.from_dict({**FINDING_DICT, "severity": "critical"})
        assert f.is_critical is True
        assert f.is_high is False

    def test_immutable(self):
        f = Finding.from_dict(FINDING_DICT)
        with pytest.raises((AttributeError, TypeError)):
            f.severity = "low"  # type: ignore[misc]


class TestResults:
    def _make_results(self, severities: list[str]) -> Results:
        findings = [
            Finding.from_dict({**FINDING_DICT, "severity": s, "confidence": "confirmed"})
            for s in severities
        ]
        return Results(target="https://agent.example.com", findings=findings)

    def test_critical_count(self):
        r = self._make_results(["critical", "critical", "high"])
        assert r.critical_count == 2

    def test_high_count(self):
        r = self._make_results(["high", "medium", "low"])
        assert r.high_count == 1

    def test_medium_count(self):
        r = self._make_results(["medium", "medium"])
        assert r.medium_count == 2

    def test_low_count(self):
        r = self._make_results(["low"])
        assert r.low_count == 1

    def test_confirmed_count(self):
        findings = [
            Finding.from_dict({**FINDING_DICT, "confidence": "confirmed"}),
            Finding.from_dict({**FINDING_DICT, "confidence": "indicator"}),
        ]
        r = Results(target="https://x.com", findings=findings)
        assert r.confirmed_count == 1

    def test_findings_by_severity(self):
        r = self._make_results(["critical", "high", "high"])
        assert len(r.findings_by_severity("high")) == 2
        assert len(r.findings_by_severity("critical")) == 1
        assert len(r.findings_by_severity("low")) == 0

    def test_findings_for_rule(self):
        f1 = Finding.from_dict({**FINDING_DICT, "rule_id": "a2a-push-ssrf-001"})
        f2 = Finding.from_dict({**FINDING_DICT, "rule_id": "mcp-tool-poison-001"})
        r = Results(target="https://x.com", findings=[f1, f2])
        assert len(r.findings_for_rule("a2a-push-ssrf-001")) == 1
        assert len(r.findings_for_rule("mcp-tool-poison-001")) == 1
        assert len(r.findings_for_rule("nonexistent")) == 0

    def test_from_dict(self):
        data = {
            "target": "https://agent.example.com",
            "findings": [FINDING_DICT],
            "rules_run": 5,
            "duration_ms": 1200,
        }
        r = Results.from_dict(data)
        assert r.target == "https://agent.example.com"
        assert len(r.findings) == 1
        assert r.rules_run == 5
        assert r.duration_ms == 1200
        # Verify confidence flows through from JSON into the Finding object.
        assert r.findings[0].confidence == "confirmed"
        assert r.findings[0].is_confirmed is True

    def test_from_dict_empty_findings(self):
        r = Results.from_dict({"target": "https://x.com", "findings": []})
        assert r.critical_count == 0
        assert r.high_count == 0


class TestScanError:
    def test_attributes(self):
        err = ScanError("something failed", returncode=1, stderr="exit 1")
        assert str(err) == "something failed"
        assert err.returncode == 1
        assert err.stderr == "exit 1"

    def test_default_attributes(self):
        err = ScanError("failed")
        assert err.returncode is None
        assert err.stderr == ""
