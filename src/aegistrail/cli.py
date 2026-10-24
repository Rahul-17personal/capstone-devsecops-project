"""Command-line interface for AegisTrail."""

import argparse
import json
import os
import sys
from pathlib import Path

from aegistrail.html_report import write_html_report
from aegistrail.metrics import serve_metrics
from aegistrail.notifications import NotificationError, send_slack_notification
from aegistrail.policy import Policy, evaluate_policy
from aegistrail.reports import write_reports
from aegistrail.trivy import TrivyError, convert_trivy_json_to_sarif, scan_image


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegistrail",
        description="Policy-driven container image security gate",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan an image with Trivy")
    scan.add_argument("--image", required=True, help="Image reference, for example alpine:3.24")
    scan.add_argument("--policy", default="policy.toml", help="TOML policy path")
    scan.add_argument("--out-dir", default="artifacts", help="Directory for generated reports")

    metrics = subparsers.add_parser(
        "serve-metrics", help="Expose the latest scan report as Prometheus metrics"
    )
    metrics.add_argument(
        "--reports-dir", default="artifacts", help="Directory containing results.json"
    )
    metrics.add_argument("--host", default="127.0.0.1", help="Metrics bind address")
    metrics.add_argument("--port", default=8000, type=int, help="Metrics port")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "serve-metrics":
        return serve_metrics(args.reports_dir, args.host, args.port)

    try:
        policy = Policy.from_toml(args.policy)
        Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        raw_json_path = Path(args.out_dir) / "trivy-raw.json"
        summary = scan_image(args.image, raw_json_path)
        json_path, markdown_path = write_reports(summary, policy, args.out_dir)
        sarif_path = convert_trivy_json_to_sarif(
            raw_json_path, Path(args.out_dir) / "results.sarif"
        )
        html_path = write_html_report(json_path, Path(args.out_dir) / "summary.html")
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        passed, reasons = evaluate_policy(summary, policy)

        print(f"Image: {summary.image}")
        print(f"Findings: {len(summary.findings)}")
        print("Severity counts: " + json.dumps(summary.severity_counts, sort_keys=True))
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {markdown_path}")
        print(f"HTML report: {html_path}")
        print(f"SARIF report: {sarif_path}")
        for reason in reasons:
            print(f"Policy: {reason}")

        webhook_url = os.environ.get("AEGISTRAIL_SLACK_WEBHOOK_URL")
        if webhook_url:
            try:
                send_slack_notification(webhook_url, payload)
                print("Slack notification: delivered")
            except NotificationError as exc:
                print(f"Warning: {exc}", file=sys.stderr)
        else:
            print("Slack notification: skipped (webhook not configured)")
        return 0 if passed else 2
    except (TrivyError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"AegisTrail error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
