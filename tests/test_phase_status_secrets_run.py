"""phase_status sees tool_run_result `run` payloads from secrets/SAST/deps shape."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.phase_status import summarize_phases  # noqa: E402


def test_summarize_sees_run_code_on_semgrep():
    phases = {
        "sast": {
            "semgrep": {
                "findings": [{"x": 1}],
                "count": 1,
                "integration": {},
                "ok": True,
                "run": {"code": "OK", "message": "", "exit_code": 0},
            },
        },
    }
    st = summarize_phases(phases)
    assert st["sast"]["ok"] is True
    assert st["sast"]["tools"]["semgrep"]["run_code"] == "OK"


def test_summarize_nonzero_with_run_signal():
    phases = {
        "sast": {
            "semgrep": {
                "findings": [{"x": 1}],
                "count": 1,
                "ok": True,
                "run": {"code": "NONZERO_EXIT", "message": "exit 1", "exit_code": 1},
            },
        },
    }
    st = summarize_phases(phases)
    assert st["sast"]["ok"] is True
