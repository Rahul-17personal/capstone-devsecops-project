"""Small Prometheus text-format exporter using only the Python standard library."""

import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _label(value: object) -> str:
    """Escape a string value for a Prometheus label."""
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_metrics(report_path: str | Path) -> str:
    """Render gauges from the latest AegisTrail results.json report."""
    path = Path(report_path)
    lines = [
        "# HELP aegistrail_scan_report_available Whether a readable scan report is available.",
        "# TYPE aegistrail_scan_report_available gauge",
    ]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("scan report root must be an object")
        report_timestamp = path.stat().st_mtime
    except (OSError, ValueError, json.JSONDecodeError):
        lines.append("aegistrail_scan_report_available 0")
        return "\n".join(lines) + "\n"

    lines.append("aegistrail_scan_report_available 1")
    image = _label(payload.get("image", "unknown"))
    counts = payload.get("severity_counts") or {}

    lines.extend(
        [
            "# HELP aegistrail_vulnerabilities Current findings grouped by severity and image.",
            "# TYPE aegistrail_vulnerabilities gauge",
        ]
    )
    for severity in _SEVERITIES:
        count = int(counts.get(severity, 0))
        lines.append(
            f'aegistrail_vulnerabilities{{image="{image}",severity="{severity}"}} {count}'
        )

    lines.extend(
        [
            "# HELP aegistrail_findings_detected Number of findings in the latest scan.",
            "# TYPE aegistrail_findings_detected gauge",
            f'aegistrail_findings_detected{{image="{image}"}} {int(payload.get("findings_detected", 0))}',
            "# HELP aegistrail_scan_policy_passed Whether the latest scan passed the policy gate (1=yes, 0=no).",
            "# TYPE aegistrail_scan_policy_passed gauge",
            f'aegistrail_scan_policy_passed{{image="{image}"}} {1 if payload.get("policy_passed") is True else 0}',
            "# HELP aegistrail_last_scan_timestamp_seconds Unix timestamp from the report file modification time.",
            "# TYPE aegistrail_last_scan_timestamp_seconds gauge",
            f'aegistrail_last_scan_timestamp_seconds{{image="{image}"}} {report_timestamp:.3f}',
            "# HELP aegistrail_exporter_scrape_timestamp_seconds Current exporter scrape time.",
            "# TYPE aegistrail_exporter_scrape_timestamp_seconds gauge",
            f"aegistrail_exporter_scrape_timestamp_seconds {time.time():.3f}",
        ]
    )
    return "\n".join(lines) + "\n"


def serve_metrics(reports_dir: str, host: str = "127.0.0.1", port: int = 8000) -> int:
    """Start a lightweight HTTP server exposing /metrics and /healthz."""
    report_path = Path(reports_dir) / "results.json"

    class MetricsHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/metrics":
                body = render_metrics(report_path).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            elif self.path == "/healthz":
                body = b"ok\n"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
            else:
                body = b"not found\n"
                self.send_response(HTTPStatus.NOT_FOUND)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format_string: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), MetricsHandler)
    print(f"AegisTrail metrics available at http://{host}:{port}/metrics")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping AegisTrail metrics exporter.")
    finally:
        server.server_close()
    return 0
