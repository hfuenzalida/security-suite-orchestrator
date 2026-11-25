"""Aggregate scan phases into the top-level JSON report (split from orchestrator)."""

from __future__ import annotations

import datetime
from typing import Any

from secscan.phase_status import summarize_phases


def build_report(scan_path: str, url: str | None, phases: dict[str, Any]) -> dict[str, Any]:
    total_findings = 0
    summary: dict[str, int] = {}
    for _phase_name, tools in phases.items():
        if not isinstance(tools, dict):
            continue
        for tool, data in tools.items():
            if not isinstance(data, dict):
                continue
            raw = data.get("count", 0)
            try:
                n = int(raw)
            except (TypeError, ValueError):
                n = 0
            total_findings += n
            summary[tool] = n

    return {
        "generated_at": datetime.datetime.now().isoformat(),
        "scan_path": scan_path,
        "target_url": url,
        "total_findings": total_findings,
        "summary": summary,
        "phases": phases,
        "phase_status": summarize_phases(phases),
    }
