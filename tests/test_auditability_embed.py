"""Structured auditability block on JSON reports."""
import sys
from argparse import Namespace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.auditability_embed import build_auditability_embed  # noqa: E402


def test_auditability_gate_truth_and_timeline(tmp_path):
    args = Namespace(
        baseline=None,
        fail_on="high",
        audit_log_jsonl=None,
        hmac_sign_report=False,
        sanitize_exports=False,
        ci_profile=False,
        sarif_source="unified",
        report_tier="technical",
    )
    report = {
        "report_tier": "technical",
        "report_policy": {"ci_note": "test"},
        "phase_timings": {
            "sast": {"started_at": "2020-01-01T00:00:01", "duration_ms": 100},
            "dast": {"started_at": "2020-01-01T00:00:00", "duration_ms": 50},
        },
        "phases": {"exploit": {"exploit": {"confirmed": [{"x": 1}], "potential": []}}},
    }
    ab = build_auditability_embed(
        report,
        args,
        suppressed_baseline_count=0,
        unified_after_baseline_count=3,
        exit_code=0,
        exit_reason="",
    )
    assert ab["schema_version"] == 1
    assert ab["gate_truth"]["fail_on_evaluated_against"] == "unified_findings_after_baseline"
    assert ab["human_report_role"]["insufficient_alone_for_automated_merge_gates"] is True
    assert ab["policy_outcome"]["unified_findings_after_baseline"] == 3
    names = [x["phase"] for x in ab["procedural_timeline"]]
    assert names == ["dast", "sast"]
    assert ab["dynamic_validation_summary"]["exploit_phase"]["confirmed_count"] == 1


def test_auditability_baseline_hashes(tmp_path):
    bf = tmp_path / "bl.json"
    bf.write_text('{"fingerprints": []}', encoding="utf-8")
    args = Namespace(
        baseline=str(bf),
        fail_on="any",
        audit_log_jsonl=None,
        hmac_sign_report=False,
        sanitize_exports=False,
        ci_profile=False,
        sarif_source="tool_native",
        report_tier="full",
    )
    report = {"report_tier": "full", "phase_timings": {}, "phases": {}}
    ab = build_auditability_embed(
        report,
        args,
        suppressed_baseline_count=2,
        unified_after_baseline_count=1,
        exit_code=1,
        exit_reason="policy",
    )
    assert ab["baseline"]["applied"] is True
    assert ab["baseline"]["file_content_sha256"] is not None
    assert len(ab["baseline"]["path_sha256"]) == 64
    assert ab["policy_outcome"]["suppressed_by_baseline"] == 2
