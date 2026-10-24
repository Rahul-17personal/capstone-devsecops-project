"""Configuration and policy-gate evaluation."""

from dataclasses import dataclass
from pathlib import Path
import tomllib

from aegistrail.models import ScanSummary


@dataclass(frozen=True)
class Policy:
    fail_on_severity: tuple[str, ...] = ("CRITICAL",)
    report_severity: tuple[str, ...] = ("UNKNOWN", "HIGH", "CRITICAL")
    minimum_findings_to_fail: int = 1

    @classmethod
    def from_toml(cls, path: str | Path) -> "Policy":
        with Path(path).open("rb") as handle:
            data = tomllib.load(handle)
        fail = _normalize_severities(data.get("fail_on_severity", ["CRITICAL"]))
        report = _normalize_severities(data.get("report_severity", ["UNKNOWN", "HIGH", "CRITICAL"]))
        minimum = data.get("minimum_findings_to_fail", 1)
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
            raise ValueError("minimum_findings_to_fail must be an integer greater than or equal to 1")
        return cls(fail, report, minimum)


def _normalize_severities(values: object) -> tuple[str, ...]:
    valid = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if not isinstance(values, list) or not values:
        raise ValueError("severity settings must be a non-empty array")
    normalized = tuple(dict.fromkeys(str(value).upper() for value in values))
    invalid = set(normalized) - valid
    if invalid:
        raise ValueError(f"unsupported severity value(s): {', '.join(sorted(invalid))}")
    return normalized


def evaluate_policy(summary: ScanSummary, policy: Policy) -> tuple[bool, list[str]]:
    """Return whether the scan passed and human-readable reasons."""
    blocking = [finding for finding in summary.findings
                if finding.severity in policy.fail_on_severity]
    if len(blocking) >= policy.minimum_findings_to_fail:
        details = ", ".join(
            f"{finding.vulnerability_id} ({finding.severity}, {finding.package})"
            for finding in blocking
        )
        return False, [f"Found {len(blocking)} blocking finding(s): {details}"]
    return True, ["No policy-blocking findings were detected."]
