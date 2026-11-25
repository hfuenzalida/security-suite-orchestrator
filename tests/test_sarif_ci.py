"""SARIF unified mode and CI profile helpers."""
import argparse
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.ci_profile import CI_EXTRA_SKIP, apply_ci_profile_to_args  # noqa: E402
from secscan.sarif_emit import write_sarif_unified_findings  # noqa: E402


def test_ci_profile_merges_skip():
    args = argparse.Namespace(skip=["auth"], fail_on="never", report_tier="full")
    apply_ci_profile_to_args(args)
    assert "recon" in args.skip
    assert "auth" in args.skip
    assert args.fail_on == "high"
    assert args.report_tier == "technical"


def test_ci_profile_respects_explicit_fail_on():
    args = argparse.Namespace(skip=[], fail_on="exploit", report_tier="full")
    apply_ci_profile_to_args(args)
    assert args.fail_on == "exploit"


def test_sarif_unified_writes_results(tmp_path):
    findings = [
        {
            "phase": "SAST",
            "tool": "semgrep",
            "type": "test-rule",
            "severity": "HIGH",
            "location": "app.py:10",
            "evidence": "x",
            "correlation_id": "a" * 64,
        }
    ]
    out = tmp_path / "out.sarif"
    n = write_sarif_unified_findings(findings, str(out))
    assert n == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    run = data["runs"][0]
    assert run["properties"]["secscan:sarifSource"] == "unified"
    assert len(run["results"]) == 1


def test_sarif_unified_empty(tmp_path):
    out = tmp_path / "e.sarif"
    n = write_sarif_unified_findings([], str(out))
    assert n == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["runs"][0]["results"] == []
