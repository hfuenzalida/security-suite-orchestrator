"""Second-pass bug hunt: chain timeouts, ZAP shape, checkpoint JSON."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest


def test_chain_parse_step_timeout():
    from secscan.phases.chain import _parse_step_timeout

    assert _parse_step_timeout({}, 45) == 45
    assert _parse_step_timeout({"timeout": 30}, 45) == 30
    assert _parse_step_timeout({"timeout": "60"}, 45) == 60
    assert _parse_step_timeout({"timeout": "not-a-number"}, 45) == 45
    assert _parse_step_timeout({"timeout": None}, 45) == 45
    assert _parse_step_timeout({"timeout": 99999}, 45) == 600


def test_checkpoint_read_rejects_invalid_json(tmp_path):
    from secscan.checkpoint_core import checkpoint_read

    p = tmp_path / "checkpoint.json"
    p.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        checkpoint_read(p)


def test_checkpoint_read_rejects_non_object(tmp_path):
    from secscan.checkpoint_core import checkpoint_read

    p = tmp_path / "checkpoint.json"
    p.write_text("[1,2]", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON object"):
        checkpoint_read(p)


def test_phase_zap_missing_returns_zap_payload(monkeypatch):
    import secscan.phases.zap as zap_mod

    monkeypatch.setattr(zap_mod, "resolve_zap_bat", lambda: (None, "not on path"))
    out = zap_mod.phase_zap("http://localhost/")
    assert "zap" in out
    assert out["zap"]["count"] == 0
    assert out["zap"].get("error") == "zap_not_installed"
    assert out["zap"].get("alerts") == []


def test_chain_invalid_regex_warns_not_step_failure(monkeypatch):
    """Invalid capture regex should warn and continue, not abort the chain."""
    from secscan.phases import chain as chain_mod

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b"body"
    mock_resp.headers = {}

    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_resp
    mock_cm.__exit__.return_value = False
    monkeypatch.setattr(chain_mod.urllib.request, "urlopen", lambda *a, **k: mock_cm)

    cfg = {
        "steps": [
            {
                "id": "s1",
                "url": "http://example.test/",
                "capture": [{"var": "x", "regex": "("}],
            },
        ],
    }
    r = chain_mod.phase_request_chain("http://example.test/", cfg)
    assert r.get("status") == "success"
    assert r.get("count") == 1
