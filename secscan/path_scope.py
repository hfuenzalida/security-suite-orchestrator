"""
Filter unified findings by path glob (monorepo / service boundaries).

URL-only locations (DAST) are kept when include globs are set — scope applies to file paths.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any


def _location_path_part(location: str) -> str | None:
    """Extract filesystem path from location (file:line) or return None for URLs."""
    s = (location or "").strip()
    if not s:
        return None
    if "://" in s:
        return None
    if ":" not in s:
        return s
    head, tail = s.rsplit(":", 1)
    if tail.isdigit():
        return head
    return s


def _normalize_rel(path_part: str, scan_root: Path) -> str | None:
    try:
        p = Path(path_part)
        if p.is_absolute():
            full = p.resolve()
        else:
            full = (scan_root / p).resolve()
        rel = full.relative_to(scan_root.resolve())
        return rel.as_posix()
    except (OSError, ValueError):
        try:
            return Path(path_part).as_posix().lstrip("./")
        except ValueError:
            return None


def finding_matches_path_scope(
    finding: dict[str, Any],
    scan_root: Path,
    include_globs: tuple[str, ...],
    exclude_globs: tuple[str, ...],
) -> bool:
    """
    If include_globs non-empty, keep only file-backed rows matching at least one pattern.
    Exclude globs apply after. URL / non-path rows always pass (DAST preserved).
    """
    loc = str(finding.get("location", "") or "")
    path_part = _location_path_part(loc)
    if path_part is None:
        return True
    rel = _normalize_rel(path_part, scan_root)
    key = rel if rel is not None else path_part.replace("\\", "/")

    if include_globs:
        if not any(fnmatch.fnmatch(key, g) or fnmatch.fnmatch(key, "**/" + g) for g in include_globs):
            return False
    if exclude_globs:
        if any(fnmatch.fnmatch(key, g) or fnmatch.fnmatch(key, "**/" + g) for g in exclude_globs):
            return False
    return True


def filter_findings_by_path_scope(
    findings: list[dict[str, Any]],
    scan_root: Path,
    include_globs: tuple[str, ...],
    exclude_globs: tuple[str, ...],
) -> tuple[list[dict[str, Any]], int]:
    """Return filtered list and count of rows removed."""
    if not include_globs and not exclude_globs:
        return findings, 0
    kept: list[dict[str, Any]] = []
    dropped = 0
    for f in findings:
        if not isinstance(f, dict):
            kept.append(f)
            continue
        if finding_matches_path_scope(f, scan_root, include_globs, exclude_globs):
            kept.append(f)
        else:
            dropped += 1
    return kept, dropped
