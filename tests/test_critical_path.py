"""Critical orchestration paths: gates, unified slice, phase_status, report core."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.ci_gates import assess_fail_on  # noqa: E402
from secscan.phase_status import summarize_phases  # noqa: E402
from secscan.report_core import build_report  # noqa: E402
from secscan.unified_report import apply_unified_findings_to_report  # noqa: E402


def _minimal_report_with_finding(severity: str = "HIGH"):
    phases = {
        "sast": {
            "semgrep": {
                "count": 1,
                "findings": [{
                    "check_id": "x",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1},
                    "extra": {"severity": "ERROR", "message": "m"},
                }],
            },
        },
    }
    r = build_report("/repo", "http://t.local", phases)
    r["phases"] = phases
    return r


def test_assess_fail_on_any_and_high():
    r = _minimal_report_with_finding("HIGH")
    unified_all, unified_gate, _ = apply_unified_findings_to_report(r, set())
    assert len(unified_gate) >= 1
    code, reason = assess_fail_on(r, "any", unified_filtered=unified_gate)
    assert code == 1 and "unified" in reason.lower()
    code2, _ = assess_fail_on(r, "never", unified_filtered=unified_gate)
    assert code2 == 0


def test_assess_fail_on_exploit_uses_phase_not_unified():
    r = build_report("/r", "http://x", {})
    r["phases"] = {
        "exploit": {
            "exploit": {
                "confirmed": [{"type": "x"}],
                "count": 1,
            },
        },
    }
    code, reason = assess_fail_on(r, "exploit", unified_filtered=[])
    assert code == 1 and "PoC" in reason


def test_apply_unified_with_baseline_suppresses():
    r = _minimal_report_with_finding()
    unified_all, unified_gate, n = apply_unified_findings_to_report(r, set())
    cid = unified_all[0].get("correlation_id")
    assert cid
    _, gate2, n2 = apply_unified_findings_to_report(r, {str(cid).lower()})
    assert n2 == 1
    assert len(gate2) == len(unified_all) - 1


def test_build_report_phase_status_roundtrip():
    phases = {"secrets": {"gitleaks": {"count": 0, "findings": [], "error": "boom"}}}
    r = build_report(".", None, phases)
    st = summarize_phases(r["phases"])
    assert st["secrets"]["ok"] is False
