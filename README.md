# Capstone DevSecOps Project

AegisTrail is an independently designed container image security gate for DevSecOps workflows. It runs Trivy, evaluates findings against a project-owned policy, and produces machine-readable and human-readable reports.

> This repository is an original implementation. Trivy performs vulnerability detection; AegisTrail owns policy evaluation and reporting.

## Features

- Scan a container image with Trivy JSON output.
- Apply configurable severity policy and fail CI when a gate is breached.
- Emit JSON and Markdown reports.
- Run unit tests without Docker or network access.
- Use GitHub Actions for tests on pushes and pull requests, with an optional manual image scan.

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
python -m aegistrail scan --image alpine:3.20 --policy policy.toml --out-dir artifacts
```

A non-zero exit code indicates a scan error or a policy failure. Review `artifacts/summary.md` and `artifacts/results.json`.

## Policy

Edit `policy.toml` to choose which severities fail the build. By default, CRITICAL findings fail the gate; HIGH findings are reported but do not fail it.

## Project layout

```text
src/aegistrail/   # CLI, scan models, Trivy integration, policy and reporting
 tests/           # offline unit tests and synthetic sample data
 .github/workflows/security-scan.yml
 policy.toml
 pyproject.toml
```

## Scope and limitations

- Initial scope is container image vulnerability scanning. It does not yet scan source code, Terraform, hosts, or Kubernetes clusters.
- Results depend on the Trivy database available during a scan; a successful scan is not a guarantee of security.
- Do not commit credentials. Use least-privilege secrets for future private-registry support.

## Development

```bash
pytest
ruff check .
```

## Roadmap

1. Add SARIF output and GitHub Code Scanning upload.
2. Add baseline/delta comparison for existing findings.
3. Add image provenance and signature checks.
4. Consider metrics and dashboard integration after the core gate is stable.

## License

MIT. See [LICENSE](LICENSE).
