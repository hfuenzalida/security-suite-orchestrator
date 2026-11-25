"""SAST JSON adapters."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.tool_adapters.sast import parse_bandit_json, parse_semgrep_json  # noqa: E402


def test_parse_semgrep_valid():
    raw = json.dumps({"results": [{"check_id": "x", "path": "a.py", "start": {"line": 1, "col": 1}}]})
    findings, err = parse_semgrep_json(raw)
    assert err is None
    assert len(findings) == 1
    assert findings[0]["check_id"] == "x"


def test_parse_semgrep_invalid_shape():
    raw = json.dumps({"results": "not-a-list"})
    findings, err = parse_semgrep_json(raw)
    assert findings == []
    assert err and "array" in err.lower()


def test_parse_bandit_valid():
    raw = json.dumps({"results": [{"test_id": "B101", "issue_text": "x"}], "metrics": {"_totals": {}}})
    issues, metrics, err = parse_bandit_json(raw)
    assert err is None
    assert len(issues) == 1
    assert "_totals" in metrics


def test_parse_bandit_bad_json():
    issues, metrics, err = parse_bandit_json("{")
    assert issues == []
    assert err
