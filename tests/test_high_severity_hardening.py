"""Regression tests for high-severity scan findings (path escape, session scope, secrets, SARIF)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.checkpoint_core import (  # noqa: E402
    checkpoint_path,
    checkpoint_write,
    resolve_run_dir,
    validate_run_id,
)
from secscan.http_session import (  # noqa: E402
    auth_apply,
    auth_clear,
    cookie_header_for_url,
    merge_req_headers,
)
from secscan.sarif_emit import write_sarif_unified_findings  # noqa: E402
from secscan.session_sanitize import strip_session_secrets  # noqa: E402


def test_validate_run_id_rejects_traversal():
    for bad in ("../escape", "..\\escape", "/tmp/x", "C:\\Windows", "a/b", "a\\b", "", ".", ".."):
        with pytest.raises(ValueError):
            validate_run_id(bad)


def test_validate_run_id_accepts_opaque():
    assert validate_run_id("local_07f892341a") == "local_07f892341a"
    assert validate_run_id("example.com_abc123") == "example.com_abc123"


def test_resolve_run_dir_stays_under_workspace(tmp_path):
    ws = tmp_path / "scan_workspace"
    ws.mkdir()
    run = resolve_run_dir(ws, "safe_run")
    assert run.resolve().is_relative_to(ws.resolve())

    with pytest.raises(ValueError):
        resolve_run_dir(ws, "../outside")


def test_checkpoint_write_rejects_escape(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    with pytest.raises(ValueError):
        checkpoint_write(ws, "../pwn", {"version": 1})
    assert not (tmp_path / "pwn").exists()


def test_checkpoint_path_uses_validated_run(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    p = checkpoint_path(ws, "ok_run")
    assert p == ws / "ok_run" / "checkpoint.json"
    with pytest.raises(ValueError):
        checkpoint_path(ws, "../x")


def test_merge_req_headers_scopes_cookies_to_allowed_host():
    auth_clear()
    auth_apply(
        {"session": "secret"},
        {"Authorization": "Bearer tok"},
        allowed_hosts=["app.example.com"],
    )
    same = merge_req_headers(url="https://app.example.com/api")
    assert "Cookie" in same
    assert "session=secret" in same["Cookie"]
    assert same.get("Authorization") == "Bearer tok"

    other = merge_req_headers(url="https://evil.example/steal")
    assert "Cookie" not in other
    assert "Authorization" not in other

    no_url = merge_req_headers()
    assert "Cookie" not in no_url
    auth_clear()


def test_cookie_header_for_url_empty_when_out_of_scope():
    auth_clear()
    auth_apply({"a": "1"}, allowed_hosts=["good.test"])
    assert cookie_header_for_url("https://good.test/") == "a=1"
    assert cookie_header_for_url("https://bad.test/") == ""
    auth_clear()


def test_strip_session_secrets_removes_auth_and_captured():
    meta = {
        "phases": {
            "auth": {
                "session": {
                    "status": "success",
                    "cookies": {"sid": "abc"},
                    "headers": {"Authorization": "Bearer xyz"},
                    "storage_state": "/tmp/auth_state.json",
                    "count": 1,
                }
            },
            "chain": {
                "status": "success",
                "captured": {"csrf": "token-value"},
                "count": 2,
            },
        }
    }
    cleaned = strip_session_secrets(meta)
    sess = cleaned["phases"]["auth"]["session"]
    assert sess["cookies"] == {}
    assert sess["headers"] == {}
    assert sess["storage_state"] is None
    assert sess["count"] == 1
    assert cleaned["phases"]["chain"]["captured"] == {}
    # original untouched
    assert meta["phases"]["auth"]["session"]["cookies"]["sid"] == "abc"


def test_checkpoint_write_strips_secrets(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    meta = {
        "version": 1,
        "phases": {
            "auth": {
                "session": {
                    "cookies": {"sid": "live-secret"},
                    "headers": {"Authorization": "Bearer live"},
                    "storage_state": "C:/tmp/state.json",
                }
            },
            "chain": {"captured": {"csrf": "x"}},
        },
    }
    p = checkpoint_write(ws, "run1", meta)
    disk = json.loads(p.read_text(encoding="utf-8"))
    assert disk["phases"]["auth"]["session"]["cookies"] == {}
    assert disk["phases"]["auth"]["session"]["headers"] == {}
    assert disk["phases"]["auth"]["session"]["storage_state"] is None
    assert disk["phases"]["chain"]["captured"] == {}


def test_sarif_unified_redacts_secret_evidence(tmp_path):
    findings = [
        {
            "phase": "Secrets",
            "tool": "detect-secrets",
            "type": "Secret Keyword",
            "severity": "HIGH",
            "location": ".env:1",
            "evidence": "Authorization: Bearer supersecrettokenvalue99",
            "correlation_id": "b" * 64,
        }
    ]
    out = tmp_path / "s.sarif"
    write_sarif_unified_findings(findings, str(out))
    text = out.read_text(encoding="utf-8")
    assert "supersecrettokenvalue99" not in text
    assert "REDACTED" in text or "[REDACTED]" in text
