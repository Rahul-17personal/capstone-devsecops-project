"""Command-line interface for AegisTrail."""

import argparse
import json
import sys
from pathlib import Path

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
    scan.add_argument("--image", required=True, help="Image reference, for example alpine:3.20")
    scan.add_argument("--policy", default="policy.toml", help="TOML policy path")
    scan.add_argument("--out-dir", default="artifacts", help="Directory for generated reports")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        policy = Policy.from_toml(args.policy)
        Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        raw_json_path = Path(args.out_dir) / "trivy-raw.json"
        summary = scan_image(args.image, raw_json_path)
        json_path, markdown_path = write_reports(summary, policy, args.out_dir)
        sarif_path = convert_trivy_json_to_sarif(
            raw_json_path, Path(args.out_dir) / "results.sarif"
        )
        passed, reasons = evaluate_policy(summary, policy)
        print(f"Image: {summary.image}")
        print(f"Findings: {len(summary.findings)}")
        print("Severity counts: " + json.dumps(summary.severity_counts, sort_keys=True))
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {markdown_path}")
        print(f"SARIF report: {sarif_path}")
        for reason in reasons:
            print(f"Policy: {reason}")
        return 0 if passed else 2
    except (TrivyError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"AegisTrail error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
