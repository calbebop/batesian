"""Data models returned by the Batesian scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Finding:
    """A single vulnerability finding from a Batesian scan."""

    rule_id: str
    rule_name: str
    severity: str
    confidence: str
    title: str
    description: str
    evidence: str
    remediation: str
    target_url: str

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            rule_id=d.get("rule_id", ""),
            rule_name=d.get("rule_name", ""),
            severity=d.get("severity", ""),
            confidence=d.get("confidence", ""),
            title=d.get("title", ""),
            description=d.get("description", ""),
            evidence=d.get("evidence", ""),
            remediation=d.get("remediation", ""),
            target_url=d.get("target_url", ""),
        )

    @property
    def is_confirmed(self) -> bool:
        """True when Batesian confirmed the vulnerability via a live exploit."""
        return self.confidence == "confirmed"

    @property
    def is_critical(self) -> bool:
        return self.severity == "critical"

    @property
    def is_high(self) -> bool:
        return self.severity == "high"


@dataclass
class Results:
    """The complete output from a Batesian scan."""

    target: str
    findings: List[Finding] = field(default_factory=list)
    rules_run: int = 0
    duration_ms: int = 0

    @classmethod
    def from_dict(cls, d: dict) -> "Results":
        findings = [Finding.from_dict(f) for f in d.get("findings", [])]
        return cls(
            target=d.get("target", ""),
            findings=findings,
            rules_run=d.get("rules_run", 0),
            duration_ms=d.get("duration_ms", 0),
        )

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    @property
    def confirmed_count(self) -> int:
        return sum(1 for f in self.findings if f.is_confirmed)

    def findings_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def findings_for_rule(self, rule_id: str) -> List[Finding]:
        return [f for f in self.findings if f.rule_id == rule_id]


class ScanError(Exception):
    """Raised when the Batesian CLI exits with a non-zero status or produces no output."""

    def __init__(self, message: str, returncode: Optional[int] = None, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr
