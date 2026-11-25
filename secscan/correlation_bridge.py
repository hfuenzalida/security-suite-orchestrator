"""Heuristic links between PoC confirmations and static findings (P2 discipline)."""

from __future__ import annotations

import urllib.parse
from typing import Any


def build_correlation_hints(phases: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Pair exploit confirmations with semgrep/bandit rows when paths or URLs overlap.
    Not definitive — triage aid only.
    """
    hints: list[dict[str, Any]] = []
    exploit = phases.get("exploit", {}).get("exploit", {})
    confirmed = exploit.get("confirmed") or []
    if not confirmed:
        return hints

    sast = phases.get("sast", {})
    static_rows: list[dict[str, Any]] = []
    for f in sast.get("semgrep", {}).get("findings", []) or []:
        if isinstance(f, dict):
            static_rows.append(
                {"tool": "semgrep", "id": f.get("check_id"), "path": f.get("path", "")}
            )
    for f in sast.get("bandit", {}).get("findings", []) or []:
        if isinstance(f, dict):
            static_rows.append(
                {
                    "tool": "bandit",
                    "id": f.get("test_id"),
                    "path": str(f.get("filename", "")),
                }
            )

    for ex in confirmed:
        if not isinstance(ex, dict):
            continue
        tgt = str(ex.get("target", "") or ex.get("url", ""))
        path_hint = ""
        try:
            path_hint = urllib.parse.urlparse(tgt).path or tgt
        except Exception:
            path_hint = tgt
        path_hint = path_hint.lower()
        matched: list[dict[str, Any]] = []
        for row in static_rows:
            p = str(row.get("path", "")).lower().replace("\\", "/")
            if p and (p in path_hint or path_hint in p or _tail_match(p, path_hint)):
                matched.append(row)
        if matched:
            hints.append({
                "exploit_type": ex.get("type"),
                "exploit_target": tgt[:500],
                "related_static": matched[:8],
                "note": "Heuristic path/URL overlap — verify manually.",
            })
    return hints


def _tail_match(file_path: str, url_path: str) -> bool:
    """e.g. /api/foo matches .../api/foo."""
    if not file_path or not url_path:
        return False
    parts = file_path.rsplit("/", 1)
    if len(parts) == 2 and parts[1] and parts[1] in url_path:
        return True
    return False
