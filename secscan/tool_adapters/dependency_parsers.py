"""
Validated JSON parsing for dependency scanners (pip-audit, safety).
"""

from __future__ import annotations

import json
from typing import Any

from secscan.tool_adapters.common import as_dict, as_list

PIP_AUDIT_JSON_ADAPTER = "pip-audit-json/1"
SAFETY_JSON_ADAPTER = "safety-json/1"


def parse_pip_audit_json(raw_text: str) -> tuple[list[dict[str, Any]], str | None]:
    """
    pip-audit --format json: top-level object with \"dependencies\" array (modern),
    or legacy shapes — mirror previous orchestrator behavior.
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        return [], f"invalid JSON: {e}"

    if isinstance(data, list):
        deps = [x for x in data if isinstance(x, dict)]
        return deps, None

    root, err = as_dict(data, "pip-audit output")
    if err:
        return [], err

    raw_deps = root.get("dependencies", root)
    lst, err = as_list(raw_deps, "dependencies")
    if err:
        return [], err

    out: list[dict[str, Any]] = []
    for item in lst:
        if isinstance(item, dict):
            out.append(item)
    return out, None


def parse_safety_json(raw_text: str) -> tuple[Any, str | None]:
    """
    safety check --json: historically a JSON array of vulnerability rows; sometimes wrapped.
    Returns raw structure for downstream counting (list or dict).
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        return None, f"invalid JSON: {e}"

    if isinstance(data, (list, dict)):
        return data, None
    return None, "safety JSON root must be array or object"
