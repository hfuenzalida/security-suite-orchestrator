"""Lightweight validation helpers (no third-party schema libs)."""

from __future__ import annotations

from typing import Any


def as_dict(obj: Any, label: str) -> tuple[dict[str, Any] | None, str | None]:
    if isinstance(obj, dict):
        return obj, None
    return None, f"{label} must be a JSON object"


def as_list(obj: Any, label: str) -> tuple[list[Any] | None, str | None]:
    if isinstance(obj, list):
        return obj, None
    return None, f"{label} must be a JSON array"
