"""JSON parsing tolerant of leading noise from CLI tools."""

from __future__ import annotations

import json


def safe_json_decode(raw: str) -> object | None:
    """Parse JSON even when the tool prints a warning line before the JSON block."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        if start == -1:
            start = raw.find("[")
        if start != -1:
            try:
                return json.loads(raw[start:])
            except json.JSONDecodeError:
                pass
    return None
