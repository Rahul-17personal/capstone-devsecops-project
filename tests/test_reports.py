import json
from pathlib import Path

from aegistrail.models import Finding, ScanSummary
from aegistrail.policy import Policy
from aegistrail.reports import write_reports
from aegistrail.trivy import parse_trivy_json


def test_parse_trivy_json_counts_severities():
    data = {
        "SchemaVersion": 2,
        "Results": [{
            "Target": "os",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-X", "PkgName": "pkg", "Severity": "critical"},
                {"VulnerabilityID": "CVE-Y", "PkgName": "pkg2", "Severity": "HIGH"},
            ],
        }],
    }
    summary = parse_trivy_json(data, "sample:1")
    assert len(summary.findings) == 2
    assert summary.severity_counts["CRITICAL"] == 1
    assert summary.severity_counts["HIGH"] == 1


def test_sample_fixture_is_valid_trivy_json():
    fixture = Path(__file__).parent / "fixtures" / "trivy-sample.json"
    summary = parse_trivy_json(json.loads(fixture.read_text(encoding="utf-8")), "sample:1")
    assert summary.severity_counts["CRITICAL"] == 1
    assert summary.severity_counts["HIGH"] == 1


def test_reports_are_created(tmp_path):
    summary = ScanSummary("demo:1", [
        Finding("os", "openssl", "1.0", "1.1", "CRITICAL", "CVE-TEST")
    ])
    json_path, markdown_path = write_reports(summary, Policy(), tmp_path)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["policy_passed"] is False
    assert "CVE-TEST" in markdown_path.read_text(encoding="utf-8")
