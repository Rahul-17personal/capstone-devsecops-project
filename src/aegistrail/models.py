"""Domain models used by AegisTrail."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    target: str
    package: str
    installed_version: str
    fixed_version: str
    severity: str
    vulnerability_id: str
    title: str = ""

    @classmethod
    def from_trivy(cls, target: str, vuln: dict[str, Any]) -> "Finding":
        return cls(
            target=target,
            package=str(vuln.get("PkgName") or "unknown"),
            installed_version=str(vuln.get("InstalledVersion") or ""),
            fixed_version=str(vuln.get("FixedVersion") or ""),
            severity=str(vuln.get("Severity") or "UNKNOWN").upper(),
            vulnerability_id=str(vuln.get("VulnerabilityID") or "UNKNOWN"),
            title=str(vuln.get("Title") or ""),
        )


@dataclass
class ScanSummary:
    image: str
    findings: list[Finding] = field(default_factory=list)
    scanner_version: str = "unknown"
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
        for finding in self.findings:
            severity = finding.severity if finding.severity in counts else "UNKNOWN"
            counts[severity] += 1
        return counts
