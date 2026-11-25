import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.export_limits import MAX_HTML_EVIDENCE_CHARS, clip_redacted_text  # noqa: E402
from secscan.export_sanitize import sanitize_report_copy  # noqa: E402


def test_clip_redacted_respects_max():
    # Avoid only-hex runs (redaction maps long hex to HEX_REDACTED).
    long = "Z" * 5000
    out = clip_redacted_text(long, 100)
    assert len(out) <= 130
    assert "truncated" in out


def test_clip_redacted_applies_patterns():
    t = "token: " + "x" * 100
    out = clip_redacted_text(t, MAX_HTML_EVIDENCE_CHARS)
    assert "REDACTED" in out or len(out) < len(t)


def test_sanitize_report_copy_truncates():
    r = {"nested": {"blob": "B" * 9000}}
    s = sanitize_report_copy(r, max_string_len=400)
    assert len(s["nested"]["blob"]) < 450
