"""
Structured audit metadata embedded in every JSON report (gate truth, baseline pins, procedural order).

See AUDITABILITY.md and REPORT_TIERS.md.
"""

from __future__ import annotations

import hashlib
from argparse import Namespace
from pathlib import Path
from typing import Any

from secscan.audit_integrity import sha256_file


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _baseline_audit_block(baseline_path: str | None) -> dict[str, Any]:
    if not baseline_path:
        return {
            "applied": False,
            "path_resolved": None,
            "path_sha256": None,
            "file_content_sha256": None,
        }
    p = Path(baseline_path).expanduser()
    try:
        resolved = str(p.resolve())
    except OSError:
        resolved = str(p)
    out: dict[str, Any] = {
        "applied": True,
        "path_resolved": resolved,
        "path_sha256": _sha256_text(resolved),
    }
    try:
        if p.is_file():
            out["file_content_sha256"] = sha256_file(p)
        else:
            out["file_content_sha256"] = None
    except OSError:
        out["file_content_sha256"] = None
    return out


def _sorted_phase_timeline(phase_timings: dict[str, Any] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, meta in (phase_timings or {}).items():
        if not isinstance(meta, dict):
            continue
        rows.append(
            {
                "phase": name,
                "started_at": meta.get("started_at"),
                "duration_ms": meta.get("duration_ms"),
            }
        )
    rows.sort(key=lambda r: (r.get("started_at") or "", r.get("phase") or ""))
    return rows


def _exploit_summary(phases: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(phases, dict):
        return {"confirmed_count": 0, "potential_count": 0, "phase_ran": False}
    ex = phases.get("exploit")
    if not isinstance(ex, dict):
        return {"confirmed_count": 0, "potential_count": 0, "phase_ran": False}
    inner = ex.get("exploit")
    if not isinstance(inner, dict):
        return {"confirmed_count": 0, "potential_count": 0, "phase_ran": True}
    conf = inner.get("confirmed") or []
    pot = inner.get("potential") or []
    n_c = len(conf) if isinstance(conf, list) else 0
    n_p = len(pot) if isinstance(pot, list) else 0
    return {
        "confirmed_count": n_c,
        "potential_count": n_p,
        "phase_ran": True,
    }


def build_auditability_embed(
    report: dict[str, Any],
    args: Namespace,
    *,
    suppressed_baseline_count: int,
    unified_after_baseline_count: int,
    exit_code: int,
    exit_reason: str,
) -> dict[str, Any]:
    """
    Machine-readable audit block: what to trust for gates vs human HTML/PDF,
    baseline fingerprints, ordered phase timeline, PoC summary.
    """
    baseline_path = getattr(args, "baseline", None) or report.get("baseline_path")
    tier = str(report.get("report_tier") or getattr(args, "report_tier", "full") or "full")
    return {
        "schema_version": 1,
        "doc": "AUDITABILITY.md",
        "gate_truth": {
            "fail_on_evaluated_against": "unified_findings_after_baseline",
            "primary_artifact": "report.json",
            "correlation_hints_are_heuristic_only": True,
            "correlation_hints_doc": "CORRELATION_JOIN_RULES.md",
            "references": ["CI_AND_GATES.md", "REPORT_TIERS.md", "CORRELATION_JOIN_RULES.md"],
        },
        "human_report_role": {
            "html_and_pdf_are_narrative": True,
            "insufficient_alone_for_automated_merge_gates": True,
            "report_tier": tier,
            "summary": (report.get("report_policy") or {}).get("ci_note", ""),
        },
        "baseline": _baseline_audit_block(str(baseline_path) if baseline_path else None),
        "policy_outcome": {
            "exit_code": exit_code,
            "fail_on": getattr(args, "fail_on", "never"),
            "exit_reason": exit_reason or "",
            "unified_findings_after_baseline": unified_after_baseline_count,
            "suppressed_by_baseline": suppressed_baseline_count,
        },
        "procedural_timeline": _sorted_phase_timeline(report.get("phase_timings")),
        "dynamic_validation_summary": {
            "exploit_phase": _exploit_summary(report.get("phases")),
        },
        "integrity_hooks": {
            "audit_log_jsonl_configured": bool(getattr(args, "audit_log_jsonl", None)),
            "hmac_sign_report_requested": bool(getattr(args, "hmac_sign_report", False)),
            "sanitize_exports": bool(getattr(args, "sanitize_exports", False)),
        },
        "runner_context": {
            "ci_profile": bool(getattr(args, "ci_profile", False)),
            "sarif_source": getattr(args, "sarif_source", "tool_native"),
        },
    }
