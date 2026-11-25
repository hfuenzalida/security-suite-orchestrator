"""Regression tests for medium-severity scan findings."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.config_io import interpolate_secret_refs, load_auth_config  # noqa: E402
from secscan.phases.chain import format_capture_log  # noqa: E402


def test_format_capture_log_redacts_by_default():
    msg = format_capture_log("csrf", "super-secret-token-value")
    assert "csrf" in msg
    assert "super-secret-token-value" not in msg
    assert "len=" in msg


def test_format_capture_log_unsafe_debug_opt_in(monkeypatch):
    monkeypatch.setenv("SECSCAN_UNSAFE_CHAIN_DEBUG", "1")
    msg = format_capture_log("csrf", "super-secret-token-value")
    assert "super-secret-token-value" in msg


def test_interpolate_secret_refs_resolves_env(monkeypatch):
    monkeypatch.setenv("SECSCAN_AUTH_USERNAME", "alice@example.com")
    monkeypatch.setenv("SECSCAN_AUTH_PASSWORD", "s3cret")
    raw = {
        "login_url": "https://app.example/login",
        "username": "${SECSCAN_AUTH_USERNAME}",
        "password": "${SECSCAN_AUTH_PASSWORD}",
        "nested": {"totp_secret": "${SECSCAN_AUTH_PASSWORD}"},
        "list": ["${SECSCAN_AUTH_USERNAME}"],
    }
    out = interpolate_secret_refs(raw)
    assert out["username"] == "alice@example.com"
    assert out["password"] == "s3cret"
    assert out["nested"]["totp_secret"] == "s3cret"
    assert out["list"] == ["alice@example.com"]


def test_interpolate_secret_refs_optional_default(monkeypatch):
    monkeypatch.delenv("OPTIONAL_TOTP", raising=False)
    out = interpolate_secret_refs({"totp_secret": "${OPTIONAL_TOTP:-}"})
    assert out["totp_secret"] == ""


def test_interpolate_secret_refs_missing_env_raises(monkeypatch):
    monkeypatch.delenv("MISSING_SECRET_XYZ", raising=False)
    with pytest.raises(ValueError, match="MISSING_SECRET_XYZ"):
        interpolate_secret_refs({"password": "${MISSING_SECRET_XYZ}"})


def test_load_auth_config_interpolates(tmp_path, monkeypatch):
    monkeypatch.setenv("SECSCAN_AUTH_USERNAME", "bob")
    monkeypatch.setenv("SECSCAN_AUTH_PASSWORD", "pw")
    p = tmp_path / "auth.json"
    p.write_text(
        json.dumps(
            {
                "login_url": "https://x/login",
                "username": "${SECSCAN_AUTH_USERNAME}",
                "password": "${SECSCAN_AUTH_PASSWORD}",
            }
        ),
        encoding="utf-8",
    )
    cfg = load_auth_config(str(p))
    assert cfg["username"] == "bob"
    assert cfg["password"] == "pw"


def test_auth_example_uses_env_refs_not_literals():
    example = json.loads((ROOT / "auth.example.json").read_text(encoding="utf-8"))
    assert example["username"].startswith("${")
    assert example["password"].startswith("${")
    totp = example.get("totp_secret") or ""
    assert totp == "" or totp.startswith("${")


def test_ci_workflow_declares_least_privilege_permissions():
    text = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^permissions:\s*$", text)
    assert re.search(r"(?m)^\s+contents:\s+read\s*$", text)


def test_ci_workflow_pins_pip_packages():
    text = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(encoding="utf-8")
    assert "pip install semgrep bandit pip-audit detect-secrets" not in text
    assert "requirements-ci-tools.txt" in text
    req = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    for line in req.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        assert "==" in line, f"CI dependency should be exact pin: {line}"
    tools = (ROOT / "requirements-ci-tools.txt").read_text(encoding="utf-8")
    for line in tools.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        assert "==" in line, f"CI tool pin missing: {line}"
