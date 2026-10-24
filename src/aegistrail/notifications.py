"""Optional Slack notifications via incoming webhook; no Slack SDK required."""

import json
from urllib.error import URLError
from urllib.request import Request, urlopen


class NotificationError(RuntimeError):
    """Raised when an optional notification cannot be delivered."""


def send_slack_notification(webhook_url: str, payload: dict) -> None:
    """Post a concise scan result to a Slack incoming webhook."""
    passed = payload.get("policy_passed") is True
    counts = payload.get("severity_counts") or {}
    status = "PASSED" if passed else "BLOCKED"
    text = "\n".join(
        [
            f"AegisTrail security scan {status}",
            f"Image: {payload.get('image', 'unknown')}",
            f"Findings: {int(payload.get('findings_detected', 0))}",
            "Severity counts: "
            + ", ".join(
                f"{severity}={int(counts.get(severity, 0))}"
                for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
            ),
        ]
    )
    body = json.dumps({"text": text}).encode("utf-8")
    request = Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=8) as response:
            if not 200 <= response.status < 300:
                raise NotificationError("Slack returned a non-success HTTP status")
    except (URLError, TimeoutError, OSError) as exc:
        raise NotificationError(
            "Slack notification could not be delivered; check the webhook and network"
        ) from exc
