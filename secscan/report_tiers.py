"""Report tier policy: executive vs technical vs full HTML/PDF narrative."""

from __future__ import annotations

from typing import Any

from secscan.findings_unified import SEVERITY_ORDER

VALID_TIERS = frozenset({"executive", "technical", "full"})


def normalize_report_tier(raw: str | None) -> str:
    s = (raw or "full").strip().lower()
    return s if s in VALID_TIERS else "full"


def partition_findings(findings: list[dict[str, Any]]) -> tuple[list[dict], list[dict]]:
    """
    Split unified findings into authoritative (EXPLOITED) vs everything else.
    EXPLOITED includes PoC confirmations, live secret hits, etc.
    """
    auth: list[dict[str, Any]] = []
    rest: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if str(f.get("result", "")).upper() == "EXPLOITED":
            auth.append(f)
        else:
            rest.append(f)
    return auth, rest


def order_findings_display(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """EXPLOITED first (by severity), then other findings (by severity)."""
    auth, rest = partition_findings(findings)

    def _sev_key(f: dict[str, Any]) -> int:
        return SEVERITY_ORDER.get(str(f.get("severity", "")).upper(), 99)

    auth.sort(key=_sev_key)
    rest.sort(key=_sev_key)
    return auth + rest


def summarize_counts_by_phase(findings: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        ph = str(f.get("phase", "?"))
        out[ph] = out.get(ph, 0) + 1
    return dict(sorted(out.items(), key=lambda x: (-x[1], x[0])))


def build_report_policy_embed(tier: str) -> dict[str, Any]:
    """Embedded in JSON report for consumers and compliance notes."""
    t = normalize_report_tier(tier)
    policies = {
        "executive": {
            "summary": (
                "Human-readable HTML/PDF emphasize confirmed exploitation and high-signal items; "
                "static/potential noise is summarized only."
            ),
            "dynamic_truth": (
                "Sections labeled 'Dynamic validation (authoritative)' list unified rows with "
                "result EXPLOITED (PoC phase, live secrets). Scanner-only hits are not treated as confirmed compromise."
            ),
            "ci_note": "CI gates use JSON/SARIF/JUnit and --fail-on — not the executive HTML alone.",
        },
        "technical": {
            "summary": (
                "Full unified findings in two bands: authoritative (EXPLOITED) first, then potential/static."
            ),
            "dynamic_truth": (
                "PoC confirmations and EXPLOITED unified rows appear before other findings; "
                "correlation_hints in JSON links PoC to static rows where heuristics match."
            ),
            "ci_note": "Same as executive for automation; HTML is for triage.",
        },
        "full": {
            "summary": "Legacy-style layout: all phases in severity order with tool summary.",
            "dynamic_truth": (
                "Authoritative EXPLOITED rows are still listed first within the findings block when possible."
            ),
            "ci_note": "Prefer technical tier for clearer separation; full preserves older visual habits.",
        },
    }
    doc = policies[t]
    return {
        "tier": t,
        "doc": "REPORT_TIERS.md",
        **doc,
    }
