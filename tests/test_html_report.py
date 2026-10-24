import json

from aegistrail.html_report import write_html_report


def test_html_report_renders_status_counts_and_escapes_values(tmp_path):
    source = tmp_path / "results.json"
    output = tmp_path / "summary.html"
    source.write_text(
        json.dumps(
            {
                "image": "demo:<tag>",
                "policy_passed": False,
                "policy_reasons": ["Blocked by HIGH finding"],
                "severity_counts": {"CRITICAL": 1, "HIGH": 2},
                "findings_detected": 3,
                "findings_reported": 1,
                "findings": [
                    {
                        "severity": "HIGH",
                        "vulnerability_id": "CVE-TEST",
                        "package": "<script>alert(1)</script>",
                        "installed_version": "1.0",
                        "fixed_version": "1.1",
                        "target": "os",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    written = write_html_report(source, output)
    report = written.read_text(encoding="utf-8")
    assert 'class="status fail">POLICY FAIL</span>' in report
    assert "CVE-TEST" in report
    assert "&lt;script&gt;" in report
    assert "<script>alert(1)</script>" not in report
    assert "CRITICAL" in report
