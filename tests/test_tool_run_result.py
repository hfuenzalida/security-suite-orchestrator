"""Canonical tool run outcome model."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.tool_run_result import (  # noqa: E402
    EXIT_NOT_FOUND,
    EXIT_TIMEOUT,
    RUN_NONZERO_EXIT,
    RUN_OK,
    ToolRunOutcome,
    attach_run_payload,
    outcome_from_exit_code,
    outcome_setup_failed,
)
from secscan.phase_status import summarize_phases  # noqa: E402


def test_outcome_from_exit_codes():
    assert outcome_from_exit_code(0).ok and outcome_from_exit_code(0).code == RUN_OK
    assert not outcome_from_exit_code(EXIT_NOT_FOUND).ok
    assert not outcome_from_exit_code(EXIT_TIMEOUT).ok
    assert outcome_from_exit_code(7).code == RUN_NONZERO_EXIT


def test_attach_propagate():
    d: dict = {"count": 0}
    attach_run_payload(d, ToolRunOutcome(False, RUN_NONZERO_EXIT, "oops", 3))
    assert d["error"] == "oops"
    assert d["run"]["code"] == RUN_NONZERO_EXIT


def test_attach_no_propagate_with_findings():
    d = {"findings": [1]}
    o = outcome_from_exit_code(9, stderr_hint="weird")
    attach_run_payload(d, o, propagate_legacy_error=False)
    assert "error" not in d
    d["ok"] = True
    st = summarize_phases({"dast": {"nuclei": d}})
    assert st["dast"]["ok"] is True


def test_setup_failed():
    d: dict = {}
    attach_run_payload(d, outcome_setup_failed("nope"))
    assert d["run"]["code"] == "SETUP_FAILED"
    assert not d["ok"]


def test_summarize_run_code_fault():
    st = summarize_phases({
        "x": {
            "t": {"count": 0, "run": {"code": "TIMEOUT", "message": "slow", "exit_code": -2}},
        },
    })
    assert st["x"]["ok"] is False
    assert "TIMEOUT" in st["x"]["errors"][0]
