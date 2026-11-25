"""
Semgrep / Bandit JSON adapters.

Semgrep: https://semgrep.dev/docs/json/
Bandit: JSON output from `bandit -f json`
"""

from __future__ import annotations

import json
from typing import Any

from secscan.tool_adapters.common import as_dict, as_list

# Bump when CLI JSON contract changes (reported under phase results[\"integration\"]).
SEMGREP_JSON_ADAPTER = "semgrep-cli-json/1"
BANDIT_JSON_ADAPTER = "bandit-json/1"


def parse_semgrep_json(raw_text: str) -> tuple[list[dict[str, Any]], str | None]:
    """
    Parse and validate semgrep --json stdout.
    Returns (findings, error_message). On error, findings is empty.
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        return [], f"invalid JSON: {e}"

    root, err = as_dict(data, "semgrep output")
    if err:
        return [], err

    results_obj = root.get("results")
    lst, err = as_list(results_obj, "results")
    if err:
        return [], err

    findings: list[dict[str, Any]] = []
    for item in lst:
        if isinstance(item, dict):
            findings.append(item)
    return findings, None


def parse_bandit_json(raw_text: str) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    """
    Parse and validate bandit -f json stdout.
    Returns (findings, metrics_dict, error_message). metrics may be {}.
    """
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        return [], {}, f"invalid JSON: {e}"

    root, err = as_dict(data, "bandit output")
    if err:
        return [], {}, err

    results_obj = root.get("results")
    lst, err = as_list(results_obj, "results")
    if err:
        return [], {}, err

    findings: list[dict[str, Any]] = []
    for item in lst:
        if isinstance(item, dict):
            findings.append(item)

    metrics: dict[str, Any] = {}
    m = root.get("metrics")
    if isinstance(m, dict):
        metrics = m

    return findings, metrics, None
