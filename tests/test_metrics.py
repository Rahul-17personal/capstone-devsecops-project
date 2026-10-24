import json

from aegistrail.metrics import render_metrics


def test_metrics_reflect_latest_scan_and_escape_image_labels(tmp_path):
    report = tmp_path / "results.json"
    report.write_text(
        json.dumps(
            {
                "image": 'demo:"quoted"',
                "policy_passed": False,
                "findings_detected": 3,
                "severity_counts": {"CRITICAL": 1, "HIGH": 2},
            }
        ),
        encoding="utf-8",
    )

    output = render_metrics(report)
    assert "aegistrail_scan_report_available 1" in output
    assert r'image="demo:\"quoted\"",severity="CRITICAL"} 1' in output
    assert r'image="demo:\"quoted\"",severity="LOW"} 0' in output
    assert "aegistrail_findings_detected" in output
    assert "aegistrail_scan_policy_passed" in output


def test_metrics_report_absence_is_explicit(tmp_path):
    output = render_metrics(tmp_path / "missing.json")
    assert "aegistrail_scan_report_available 0" in output
    assert "aegistrail_scan_policy_passed" not in output
