"""
NDJSON / line-oriented parsing for DAST CLIs (nuclei).
"""

from __future__ import annotations

import json
from typing import Any

NUCLEI_JSONL_ADAPTER = "nuclei-jsonl/1"
SCHEMATHESIS_ADAPTER = "schemathesis-cli/1"


def parse_nuclei_jsonl(stdout: str) -> tuple[list[dict[str, Any]], int]:
    """
    nuclei -json emits one JSON object per line. Malformed lines are skipped.

    Returns (findings, skipped_line_count).
    """
    findings: list[dict[str, Any]] = []
    skipped = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if isinstance(obj, dict):
            findings.append(obj)
        else:
            skipped += 1
    return findings, skipped
