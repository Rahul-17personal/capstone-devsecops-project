"""Trivy invocation, conversion, and result parsing."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from aegistrail.models import Finding, ScanSummary


class TrivyError(RuntimeError):
    """Raised when Trivy is unavailable or a scan fails."""


def parse_trivy_json(data: dict[str, Any], image: str) -> ScanSummary:
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = str(result.get("Target") or "unknown")
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(Finding.from_trivy(target, vuln))
    metadata = data.get("Metadata") or {}
    return ScanSummary(
        image=image,
        findings=findings,
        scanner_version=str(data.get("SchemaVersion") or "unknown"),
        raw_metadata=metadata if isinstance(metadata, dict) else {},
    )


def _trivy_executable() -> str:
    executable = shutil.which("trivy")
    if not executable:
        raise TrivyError("Trivy was not found on PATH. Install Trivy before running a live scan.")
    return executable


def scan_image(image: str, output_path: str | Path | None = None) -> ScanSummary:
    executable = _trivy_executable()
    command = [
        executable, "image",
        "--format", "json",
        "--scanners", "vuln",
        "--quiet",
        image,
    ]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired as exc:
        raise TrivyError(f"Trivy scan timed out for image {image!r}") from exc
    if completed.returncode != 0:
        message = completed.stderr.strip() or f"Trivy exited with code {completed.returncode}"
        raise TrivyError(message)

    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise TrivyError("Trivy returned invalid JSON output") from exc

    if output_path is not None:
        raw_path = Path(output_path)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return parse_trivy_json(data, image)


def convert_trivy_json_to_sarif(
    input_path: str | Path,
    output_path: str | Path,
) -> Path:
    """Use Trivy's native SARIF formatter so package/image locations stay scanner-derived."""
    executable = _trivy_executable()
    source = Path(input_path)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not source.is_file():
        raise TrivyError(f"Trivy JSON report does not exist: {source}")

    command = [
        executable, "convert",
        "--format", "sarif",
        "--output", str(destination),
        str(source),
    ]
    try:
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=300
        )
    except subprocess.TimeoutExpired as exc:
        raise TrivyError("Trivy JSON-to-SARIF conversion timed out") from exc
    if completed.returncode != 0:
        message = completed.stderr.strip() or f"Trivy SARIF conversion exited with code {completed.returncode}"
        raise TrivyError(message)
    if not destination.is_file() or destination.stat().st_size == 0:
        raise TrivyError("Trivy completed SARIF conversion without creating a report")
    return destination
