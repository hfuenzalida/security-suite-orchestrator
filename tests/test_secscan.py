"""Tests for secscan package and cross-cutting helpers."""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.phase_status import summarize_phases  # noqa: E402
from secscan.user_config import env_defaults, load_toml_defaults  # noqa: E402
import security_scan as ss  # noqa: E402


def test_summarize_phases_errors():
    phases = {
        "sast": {
            "semgrep": {"count": 1, "findings": [], "error": "parse error"},
            "bandit": {"count": 0, "findings": []},
        },
    }
    st = summarize_phases(phases)
    assert st["sast"]["ok"] is False
    assert any("semgrep" in e for e in st["sast"]["errors"])


def test_safe_json_decode_trailing():
    raw = 'warning line\n{"a": 1}'
    assert ss.safe_json_decode(raw) == {"a": 1}


def test_env_defaults_model(monkeypatch):
    monkeypatch.setenv("SECURITY_SCAN_AI_MODEL", "mymodel")
    d = env_defaults()
    assert d.get("ai_model") == "mymodel"


def test_load_toml_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("SECURITY_SCAN_ZAP_BAT", raising=False)
    p = tmp_path / "c.toml"
    p.write_text(
        '[defaults]\npath = "src"\nai_model = "x"\n[paths]\nzap_bat = "Z:/zap.bat"\n',
        encoding="utf-8",
    )
    d = load_toml_defaults(p)
    assert d.get("path") == "src"
    assert d.get("ai_model") == "x"
    assert os.environ.get("SECURITY_SCAN_ZAP_BAT") == "Z:/zap.bat"
