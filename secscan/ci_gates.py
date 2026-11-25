"""Exit policy and notification predicates."""

from __future__ import annotations

from secscan.findings_unified import collect_findings


def assess_fail_on(
    report: dict,
    mode: str,
    *,
    unified_filtered: list[dict] | None = None,
) -> tuple[int, str]:
    """Return (exit_code, reason). Non-zero exit_code means the policy matched."""
    if mode == "never":
        return 0, ""
    phases = report.get("phases", {})
    unified = unified_filtered if unified_filtered is not None else collect_findings(report)

    if mode == "any":
        if len(unified) > 0:
            return 1, f"--fail-on any: {len(unified)} unified finding(s) after baseline"
        return 0, ""

    if mode == "exploit":
        ex = phases.get("exploit", {}).get("exploit", {})
        n = len(ex.get("confirmed", []))
        if n > 0:
            return 1, f"--fail-on exploit: {n} confirmed PoC finding(s)"
        return 0, ""

    if mode == "critical":
        for f in unified:
            if f.get("severity", "").upper() == "CRITICAL":
                return 1, "--fail-on critical: CRITICAL severity in unified findings (after baseline)"
        return 0, ""

    if mode == "high":
        for f in unified:
            su = f.get("severity", "").upper()
            if su in ("CRITICAL", "HIGH"):
                return 1, f"--fail-on high: {su} severity in unified findings (after baseline)"
        return 0, ""

    return 0, ""


def should_send_notification(
    report: dict,
    notify_on: str,
    *,
    unified_filtered: list[dict] | None = None,
) -> bool:
    if notify_on == "never":
        return False
    unified = unified_filtered if unified_filtered is not None else collect_findings(report)
    phases = report.get("phases", {})
    ex = phases.get("exploit", {}).get("exploit", {})
    n_ex = len(ex.get("confirmed", []))

    if notify_on == "exploit":
        return n_ex > 0
    if notify_on == "any":
        return len(unified) > 0
    if notify_on == "critical":
        return any(f.get("severity", "").upper() == "CRITICAL" for f in unified)
    if notify_on == "high":
        return any(f.get("severity", "").upper() in ("CRITICAL", "HIGH") for f in unified)
    return False
