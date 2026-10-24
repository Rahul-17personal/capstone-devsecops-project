"""Accessible, self-contained HTML report generation."""

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def write_html_report(json_report_path: str | Path, output_path: str | Path) -> Path:
    """Render the existing JSON report as a self-contained HTML page."""
    payload: dict[str, Any] = json.loads(
        Path(json_report_path).read_text(encoding="utf-8")
    )
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    passed = payload.get("policy_passed") is True
    status = "PASS" if passed else "FAIL"
    status_class = "pass" if passed else "fail"
    counts = payload.get("severity_counts") or {}

    cards = []
    for severity in _SEVERITIES:
        count = int(counts.get(severity, 0))
        cards.append(
            f'<article class="card {severity.lower()}">'
            f"<span>{severity}</span><strong>{count:,}</strong></article>"
        )

    rows = []
    for finding in payload.get("findings") or []:
        severity = str(finding.get("severity") or "UNKNOWN").upper()
        severity_class = severity.lower() if severity in _SEVERITIES else "unknown"
        values = (
            severity,
            finding.get("vulnerability_id", ""),
            finding.get("package", ""),
            finding.get("installed_version", ""),
            finding.get("fixed_version", ""),
            finding.get("target", ""),
        )
        escaped = [html.escape(str(value)) for value in values]
        rows.append(
            "<tr>"
            f'<td><span class="severity {severity_class}">{escaped[0]}</span></td>'
            + "".join(f"<td>{value}</td>" for value in escaped[1:])
            + "</tr>"
        )

    findings_html = (
        "\n".join(rows)
        if rows
        else '<tr><td colspan="6" class="empty">No findings match the configured report severities.</td></tr>'
    )
    reasons = payload.get("policy_reasons") or ["No policy details were recorded."]
    reasons_html = "\n".join(
        f"<li>{html.escape(str(reason))}</li>" for reason in reasons
    )
    image = html.escape(str(payload.get("image", "unknown")), quote=True)
    detected = int(payload.get("findings_detected", 0))
    reported = int(payload.get("findings_reported", 0))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisTrail scan report — {image}</title>
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#637083; --line:#dce3ed; --surface:#f5f7fb; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:#eef2f8; color:var(--ink); font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1180px; margin:32px auto; padding:0 20px; }}
header,.panel {{ background:#fff; border:1px solid var(--line); border-radius:16px; padding:24px; margin-bottom:18px; }}
.eyebrow {{ color:#465dd8; text-transform:uppercase; letter-spacing:.12em; font-size:.75rem; font-weight:800; }}
h1 {{ margin:.25rem 0 .5rem; font-size:clamp(1.7rem,4vw,2.5rem); }}
h2 {{ margin:0 0 16px; font-size:1.2rem; }}
.meta {{ color:var(--muted); overflow-wrap:anywhere; }}
.status {{ display:inline-block; border-radius:999px; padding:5px 12px; font-weight:800; font-size:.8rem; }}
.status.pass {{ color:#075b37; background:#d9f8e7; }}
.status.fail {{ color:#8c1d27; background:#fee2e4; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(145px,1fr)); gap:12px; margin-bottom:18px; }}
.card {{ padding:17px; background:#fff; border:1px solid var(--line); border-radius:14px; display:flex; flex-direction:column; gap:8px; }}
.card span {{ color:var(--muted); font-size:.78rem; font-weight:750; }}
.card strong {{ font-size:1.9rem; }}
.critical {{ border-top:4px solid #be123c; }} .high {{ border-top:4px solid #ea580c; }}
.medium {{ border-top:4px solid #ca8a04; }} .low {{ border-top:4px solid #2563eb; }}
.unknown {{ border-top:4px solid #64748b; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ text-align:left; padding:11px 12px; border-bottom:1px solid var(--line); overflow-wrap:anywhere; }}
th {{ background:var(--surface); font-size:.78rem; color:#48566a; text-transform:uppercase; letter-spacing:.04em; }}
.table-wrap {{ overflow-x:auto; }}
.severity {{ display:inline-block; border-radius:6px; padding:3px 7px; font-weight:800; font-size:.72rem; background:#e8edf4; }}
.severity.critical {{ color:#991b1b; background:#fee2e2; }} .severity.high {{ color:#9a3412; background:#ffedd5; }}
.severity.medium {{ color:#854d0e; background:#fef3c7; }} .severity.low {{ color:#1d4ed8; background:#dbeafe; }}
.empty {{ text-align:center; color:var(--muted); padding:28px; }}
footer {{ text-align:center; color:var(--muted); font-size:.82rem; padding:12px; }}
@media(max-width:640px) {{ main {{ margin:12px auto; padding:0 10px; }} header,.panel {{ padding:16px; }} }}
</style>
</head>
<body><main>
<header>
  <div class="eyebrow">AegisTrail · Container Security</div>
  <h1>Image vulnerability report</h1>
  <p class="meta">Image: <strong>{image}</strong></p>
  <p><span class="status {status_class}">POLICY {status}</span>
     &nbsp; {detected:,} findings detected · {reported:,} findings shown</p>
  <p class="meta">Report generated {generated}</p>
</header>
<section class="cards">{"".join(cards)}</section>
<section class="panel">
  <h2>Policy evaluation</h2>
  <ul>{reasons_html}</ul>
  <p class="meta">Detailed findings are filtered by the report severities configured in policy.toml.</p>
</section>
<section class="panel">
  <h2>Findings detail</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Vulnerability</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>Target</th></tr></thead>
    <tbody>{findings_html}</tbody>
  </table></div>
</section>
<footer>Generated by AegisTrail. A clean scan is not a guarantee that an image is secure.</footer>
</main></body></html>
"""
    destination.write_text(document, encoding="utf-8")
    return destination
