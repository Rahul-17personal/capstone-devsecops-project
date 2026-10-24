# Capstone DevSecOps Project

AegisTrail is an independently designed container image security gate for DevSecOps workflows. It runs Trivy, evaluates findings against a project-owned policy, and produces JSON, Markdown, and SARIF reports.

> This repository is an original implementation. Trivy performs vulnerability detection; AegisTrail owns policy evaluation and CI reporting.

## Features

- Scan a container image with Trivy JSON output.
- Block builds with HIGH or CRITICAL findings by default.
- Keep UNKNOWN findings visible for triage without treating them as clean.
- Generate JSON and Markdown summaries plus native Trivy SARIF 2.1.0.
- Upload SARIF findings to GitHub Code Scanning on a manual image scan.
- Run offline unit tests without Docker or network access.

## Requirements

- Python 3.11+
- Trivy installed and available on `PATH` for local live scans

## Quick start

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest
```

Scan an image (Trivy must be installed):

```bash
python -m aegistrail scan --image alpine:3.24 --policy policy.toml --out-dir artifacts
```

A non-zero exit code indicates a scan error or a policy failure. Review `artifacts/summary.md`, `artifacts/results.json`, `artifacts/results.sarif`, and `artifacts/trivy-raw.json`.

## Policy

Edit `policy.toml` to choose which severities fail the build and which appear in detailed reports. The default gate fails on **HIGH** or **CRITICAL** findings. UNKNOWN, HIGH, and CRITICAL findings appear in detailed reports; UNKNOWN findings are visible for manual triage but do not fail the gate unless explicitly configured.

## GitHub Actions

Pushes and pull requests run unit tests. To scan a container image, open **Actions → AegisTrail Container Security → Run workflow**, choose an image (default: `alpine:3.24`), and run it. The scan job has `security-events: write` permission only for SARIF publication; its results are uploaded to GitHub Code Scanning and attached as a workflow artifact. GitHub Code Scanning is available for public repositories on GitHub.com; private repositories may require an eligible plan and Code Security enabled.

## Project layout

```text
src/aegistrail/   # CLI, scan models, Trivy integration, policy and reporting
tests/            # offline unit tests and synthetic sample data
.github/workflows/security-scan.yml
policy.toml
pyproject.toml
```

## Scope and limitations

- Initial scope is container image vulnerability scanning. It does not yet scan source code, Terraform, hosts, or Kubernetes clusters.
- Container-image findings may point to package/image paths rather than source-code lines in GitHub Code Scanning.
- Results depend on the Trivy database available during a scan; a successful scan is not a guarantee of security.
- Do not commit credentials. Use least-privilege secrets for future private-registry support.

## Initial baseline observation

The first Trivy run against `alpine:3.20` reported `CVE-2026-107891` against `musl` and `musl-utils` (installed `1.2.5-r3`, fixed version listed as `1.2.5-r4`). Trivy classified both records as `UNKNOWN`; they remain visible for triage and do not fail the default HIGH/CRITICAL-only gate. Trivy also marked the scanned Alpine 3.20 image as end-of-service-life. A comparison scan of `alpine:3.24` returned zero vulnerability records at scan time. See the [official Alpine release branches](https://www.alpinelinux.org/releases/).

## Development

```bash
pytest
ruff check .
```

## Roadmap

1. Add baseline/delta comparison for existing findings.
2. Add image provenance and signature checks.
3. Consider metrics and dashboard integration after the core gate is stable.

## License

MIT. See [LICENSE](LICENSE).
