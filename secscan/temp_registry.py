"""Track temp files for optional end-of-run cleanup (--wipe-temp)."""

from __future__ import annotations

import os
from pathlib import Path

_registered: list[Path] = []


def register_temp_path(path: str | os.PathLike[str] | None) -> None:
    """Register a path created under /tmp or cwd for best-effort deletion."""
    if not path:
        return
    try:
        p = Path(path).resolve()
        if p not in _registered:
            _registered.append(p)
    except OSError:
        pass


def wipe_registered_temp_paths() -> tuple[int, list[str]]:
    """
    Unlink files (ignore missing). Returns (count_removed, errors).
    """
    removed = 0
    errors: list[str] = []
    for p in list(_registered):
        try:
            if p.is_file():
                p.unlink()
                removed += 1
        except OSError as e:
            errors.append(f"{p}: {e}")
    _registered.clear()
    return removed, errors


def clear_registry() -> None:
    """Testing / reset."""
    _registered.clear()


def registry_snapshot(*, max_sample: int = 16) -> dict[str, object]:
    """For report JSON: count + sample basenames (no full paths — reduces leak risk in shared uploads)."""
    n = len(_registered)
    samples = [p.name for p in _registered[:max_sample]]
    return {
        "registered_count": n,
        "sample_basenames": samples,
        "truncated": n > max_sample,
    }
