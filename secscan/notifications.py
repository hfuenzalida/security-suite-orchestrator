"""Webhook notifications (redacted payloads)."""

from __future__ import annotations

import json
import urllib.request

from secscan.constants import ORCHESTRATOR_VERSION
from secscan.findings_unified import collect_findings
from secscan.redaction import redact_sensitive_obj


def post_notification_webhook(webhook_url: str, report: dict, extra: dict) -> None:
    from secscan.cli_output import ok, warn

    body = {
        "event": "security_scan",
        "scan_path": report.get("scan_path"),
        "target_url": report.get("target_url"),
        "total_findings": report.get("total_findings"),
        "unified_findings": len(collect_findings(report)),
        "report_json": report.get("_output_path"),
        "html_report": report.get("_html_path"),
        "run_id": report.get("_run_id"),
        "workspace": report.get("_workspace"),
        "orchestrator_version": ORCHESTRATOR_VERSION,
    }
    body.update(extra)
    body = redact_sensitive_obj(body)
    try:
        raw = json.dumps(body, default=str).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=raw,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "SecuritySuiteOrchestrator/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            code = resp.getcode()
        ok(f"Notification webhook sent (HTTP {code})")
    except Exception as e:
        warn(f"Notification webhook failed — {e}")
