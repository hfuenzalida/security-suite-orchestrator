"""Report tier partitioning and policy embed."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.report_tiers import (  # noqa: E402
    build_report_policy_embed,
    normalize_report_tier,
    order_findings_display,
    partition_findings,
    summarize_counts_by_phase,
)


def test_normalize_tier():
    assert normalize_report_tier("executive") == "executive"
    assert normalize_report_tier(None) == "full"
    assert normalize_report_tier("bogus") == "full"


def test_partition_and_order():
    a = {"phase": "SAST", "severity": "HIGH", "result": "POTENTIAL", "type": "x"}
    b = {"phase": "PoC", "severity": "MEDIUM", "result": "EXPLOITED", "type": "y"}
    auth, rest = partition_findings([a, b])
    assert len(auth) == 1 and auth[0]["type"] == "y"
    assert len(rest) == 1
    ordered = order_findings_display([a, b])
    assert ordered[0]["result"] == "EXPLOITED"


def test_summarize_counts():
    s = summarize_counts_by_phase([
        {"phase": "A", "severity": "LOW"},
        {"phase": "A", "severity": "LOW"},
        {"phase": "B", "severity": "LOW"},
    ])
    assert s["A"] == 2 and s["B"] == 1


def test_policy_embed():
    p = build_report_policy_embed("executive")
    assert p["tier"] == "executive"
    assert "dynamic_truth" in p
