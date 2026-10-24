"""JSON and Markdown report writers."""

import json
from pathlib import Path

from aegistrail.models import ScanSummary
from aegistrail.policy import Policy, evaluate_policy


def write_reports(summary: ScanSummary, policy: Policy, out_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    passed, reasons = evaluate_policy(summary, policy)
    reported_findings = [
        item for item in summary.findings if item.severity in policy.report_severity
    ]
    payload = {
        "image": summary.image,
        "scanner_schema_version": summary.scanner_version,
        "policy_passed": passed,
        "policy_reasons": reasons,
        "severity_counts": summary.severity_counts,
        "findings_detected": len(summary.findings),
        "findings_reported": len(reported_findings),
        "report_severity": list(policy.report_severity),
        "findings": [
            {
                "target": item.target,
                "package": item.package,
                "installed_version": item.installed_version,
                "fixed_version": item.fixed_version,
                "severity": item.severity,
                "vulnerability_id": item.vulnerability_id,
                "title": item.title,
            }
            for item in reported_findings
        ],
    }
    json_path = destination / "results.json"
    markdown_path = destination / "summary.md"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(_markdown(payload), encoding="utf-8")
    return json_path, markdown_path


def _markdown(payload: dict) -> str:
    status = "PASS" if payload["policy_passed"] else "FAIL"
    lines = [
        "# AegisTrail Image Scan",
        "",
        f"- **Image:** `{payload['image']}`",
        f"- **Policy result:** **{status}**",
        f"- **Findings detected:** {payload['findings_detected']}",
        f"- **Findings included in detail:** {payload['findings_reported']}",
        "",
        "## Severity summary (all detected findings)",
        "",
        "| Severity | Findings |",
        "|---|---:|",
    ]
    for severity, count in payload["severity_counts"].items():
        lines.append(f"| {severity} | {count} |")
    lines.extend(["", "## Policy", ""])
    lines.extend(f"- {reason}" for reason in payload["policy_reasons"])
    lines.extend([
        "",
        "## Findings",
        "",
        "Detailed rows are filtered by configured report severities: "
        + ", ".join(payload["report_severity"]),
        "",
    ])
    if not payload["findings"]:
        lines.append("No findings matched the configured report severities.")
    else:
        lines.extend([
            "| Severity | ID | Package | Installed | Fixed in | Target |",
            "|---|---|---|---|---|---|",
        ])
        for finding in payload["findings"]:
            cells = [
                finding["severity"], finding["vulnerability_id"], finding["package"],
                finding["installed_version"], finding["fixed_version"], finding["target"],
            ]
            lines.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in cells) + " |")
    lines.append("")
    return "\n".join(lines)
