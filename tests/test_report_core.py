"""report_core edge cases (checkpoint / malformed phase payloads)."""

from secscan.report_core import build_report


def test_build_report_skips_non_dict_phase_values():
    phases = {
        "sast": {"semgrep": {"count": 2, "findings": []}},
        "corrupt": "not-a-dict",
        "mixed": {"ok_tool": {"count": 1}, "bad_tool": []},
    }
    r = build_report("/repo", None, phases)
    assert r["total_findings"] == 3
    assert r["summary"]["semgrep"] == 2
    assert r["summary"]["ok_tool"] == 1
