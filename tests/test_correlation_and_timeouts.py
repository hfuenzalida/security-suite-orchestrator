"""Correlation bridge + timeout helpers."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.correlation_bridge import build_correlation_hints  # noqa: E402
from secscan.timeouts import scan_timeout_sec  # noqa: E402
from secscan.user_config import load_toml_defaults  # noqa: E402


def test_scan_timeout_sec_env(monkeypatch):
    monkeypatch.setenv("SECURITY_SCAN_TIMEOUT_NUCLEI", "42")
    assert scan_timeout_sec("nuclei", 300) == 42
    monkeypatch.delenv("SECURITY_SCAN_TIMEOUT_NUCLEI", raising=False)
    assert scan_timeout_sec("nuclei", 300) == 300


def test_correlation_hints_overlap():
    phases = {
        "sast": {
            "semgrep": {
                "findings": [
                    {"check_id": "x", "path": "app/api/foo.py"},
                ],
            },
            "bandit": {"findings": []},
        },
        "exploit": {
            "exploit": {
                "confirmed": [
                    {"type": "sqli", "target": "https://ex.example/api/foo?x=1"},
                ],
            },
        },
    }
    hints = build_correlation_hints(phases)
    assert len(hints) >= 1
    assert hints[0].get("related_static")


def test_load_toml_timeouts(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURITY_SCAN_TIMEOUT_SEMGREP", raising=False)
    p = tmp_path / "t.toml"
    p.write_text("[timeouts]\nsemgrep = 99\n", encoding="utf-8")
    load_toml_defaults(p)
    assert os.environ.get("SECURITY_SCAN_TIMEOUT_SEMGREP") == "99"
