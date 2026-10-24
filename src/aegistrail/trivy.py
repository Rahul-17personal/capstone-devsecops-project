"""Trivy invocation and result parsing."""

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


def scan_image(image: str, output_path: str | Path | None = None) -> ScanSummary:
    executable = shutil.which("trivy")
    if not executable:
        raise TrivyError("Trivy was not found on PATH. Install Trivy before running a live scan.")

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
