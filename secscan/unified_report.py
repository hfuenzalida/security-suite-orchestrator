"""Unified findings + triage slice merged onto the JSON report (orchestrator core path)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secscan.findings_unified import (
    collect_findings,
    filter_findings_by_baseline,
)
from secscan.path_scope import filter_findings_by_path_scope


def apply_unified_findings_to_report(
    report: dict[str, Any],
    baseline_fps: set[str],
    *,
    path_scope: tuple[Path, tuple[str, ...], tuple[str, ...]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """
    Populate unified counts, triage slice, and return (all, after_baseline, suppressed_count).
    Optional path_scope: (scan_root, include_globs, exclude_globs) filters file-backed rows.
    """
    unified_all = collect_findings(report)
    scope_dropped = 0
    if path_scope is not None:
        root, inc, exc = path_scope
        unified_all, scope_dropped = filter_findings_by_path_scope(unified_all, root, inc, exc)
        report["path_scope_dropped_count"] = scope_dropped
    else:
        report.pop("path_scope_dropped_count", None)
    unified_gate, n_suppressed = filter_findings_by_baseline(unified_all, baseline_fps)
    report["findings_unified_count"] = len(unified_all)
    report["findings_unified_after_baseline"] = len(unified_gate)
    report["baseline_suppressed_count"] = n_suppressed
    report["unified_fingerprints_triage"] = [
        {
            "correlation_id": f.get("correlation_id"),
            "phase": f.get("phase"),
            "tool": f.get("tool"),
            "type": f.get("type"),
            "severity": f.get("severity"),
        }
        for f in unified_all[:500]
    ]
    return unified_all, unified_gate, n_suppressed
