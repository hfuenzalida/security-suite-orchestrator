"""
Validated JSON parsing for secret-scanning CLIs (gitleaks, detect-secrets).

Adapter IDs document the expected output shape; bump when tool JSON changes.
"""

from __future__ import annotations

import json
from typing import Any

from secscan.tool_adapters.common import as_dict, as_list

GITLEAKS_REPORT_ADAPTER = "gitleaks-json-array/1"
DETECT_SECRETS_REPORT_ADAPTER = "detect-secrets-json/1"


def parse_gitleaks_report_json(raw_text: str) -> tuple[list[dict[str, Any]], str | None]:
    """
    gitleaks detect --report-format json writes a JSON array of finding objects.
    See https://github.com/gitleaks/gitleaks — fields include RuleID, File, StartLine.
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        return [], f"invalid JSON: {e}"

    root, err = as_list(data, "gitleaks report root")
    if err:
        return [], err

    findings: list[dict[str, Any]] = []
    for item in root:
        if isinstance(item, dict):
            findings.append(item)
    return findings, None


def parse_detect_secrets_report_json(raw_text: str) -> tuple[dict[str, Any], str | None]:
    """
    detect-secrets scan emits {"results": { path: [ {type, line_number, ...}, ... ], ... }}
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        return {}, f"invalid JSON: {e}"

    root, err = as_dict(data, "detect-secrets output")
    if err:
        return {}, err

    results_obj = root.get("results")
    inner, err = as_dict(results_obj, "results")
    if err:
        return {}, err
    return inner, None
