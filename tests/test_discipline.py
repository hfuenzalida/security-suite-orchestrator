"""Unit tests for baseline, correlation IDs, and redaction helpers."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import security_scan as ss  # noqa: E402
from argparse import Namespace

from secscan.run_manifest import build_replay_bundle, sha256_file_bytes  # noqa: E402


def test_correlation_id_stable():
    f = {
        "phase": "SAST",
        "tool": "semgrep",
        "type": "sql",
        "severity": "HIGH",
        "location": "app.py:10",
        "result": "POTENTIAL",
    }
    a = ss._stable_correlation_id(f)
    b = ss._stable_correlation_id(f)
    assert a == b
    assert len(a) == 64


def test_baseline_filter():
    f1 = {"phase": "X", "tool": "t", "type": "a", "severity": "LOW", "location": "l", "result": ""}
    f2 = dict(f1)
    f2["type"] = "b"
    ss._tag_correlation_ids([f1, f2])
    base = {f1["correlation_id"]}
    kept, n = ss.filter_findings_by_baseline([f1, f2], base)
    assert n == 1
    assert len(kept) == 1
    assert kept[0]["type"] == "b"


def test_load_baseline_file(tmp_path):
    p = tmp_path / "b.json"
    cid = "a" * 64
    p.write_text(json.dumps({"fingerprints": [cid]}), encoding="utf-8")
    s = ss.load_baseline_fingerprints(str(p))
    assert cid in s


def test_load_baseline_uppercase_hex_suppresses_match(tmp_path):
    """Baseline entries must match correlation_id (always lowercase hex from sha256)."""
    f = {
        "phase": "SAST",
        "tool": "semgrep",
        "type": "rule",
        "severity": "HIGH",
        "location": "app.py:1",
        "result": "POTENTIAL",
    }
    ss._tag_correlation_ids([f])
    cid = f["correlation_id"]
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"fingerprints": [cid.upper()]}), encoding="utf-8")
    base = ss.load_baseline_fingerprints(str(p))
    kept, n = ss.filter_findings_by_baseline([f], base)
    assert n == 1
    assert kept == []


def test_collect_findings_sort_non_string_severity():
    from secscan.findings_unified import collect_findings

    report = {
        "phases": {
            "exploit": {
                "exploit": {
                    "confirmed": [
                        {"severity": 9, "type": "a", "evidence": "", "target": "t"},
                        {"severity": "HIGH", "type": "b", "evidence": "", "target": "t"},
                    ]
                }
            }
        }
    }
    out = collect_findings(report)
    assert len(out) == 2


def test_sha256_file_bytes_missing(tmp_path):
    assert sha256_file_bytes(tmp_path / "missing.bin") is None


def test_replay_bundle_config_hash(tmp_path):
    cfg = tmp_path / "my.toml"
    cfg.write_text('[defaults]\npath = "."\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("fpdf2>=2.7\n", encoding="utf-8")
    args = Namespace(config=str(cfg), replay_include_pip_freeze=False)
    ws = tmp_path / "scan_workspace"
    rb = build_replay_bundle(str(tmp_path), args, workspace=ws, run_id="run1")
    assert rb["spec_version"] == 2
    assert rb["config_sha256"] == sha256_file_bytes(cfg)
    assert rb["config_path_effective"] == str(cfg.resolve())
    assert rb["workspace"]["run_id"] == "run1"
    assert rb["workspace"]["root"] == str(ws.resolve())
    assert "checkpoint.json" in (rb["workspace"].get("checkpoint_json") or "")
    assert "environment" in rb and "platform" in rb["environment"]
    assert "supply_chain" in rb
    assert rb["supply_chain"]["files"]["requirements_txt"] == sha256_file_bytes(tmp_path / "requirements.txt")
    assert "determinism_note" in rb
    assert "pip_freeze_sha256" not in rb


def test_replay_bundle_pip_freeze_flag(tmp_path):
    args = Namespace(config=None, replay_include_pip_freeze=True)
    ws = tmp_path / "w"
    rb = build_replay_bundle(str(tmp_path), args, workspace=ws, run_id="r")
    assert "pip_freeze_sha256" in rb
    assert len(rb["pip_freeze_sha256"]) == 64


def test_redact_bearer():
    t = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgoL-OmHYv'
    out = ss.redact_sensitive_text(t)
    assert "eyJ" not in out
    assert "REDACTED" in out


def test_redact_github_pat():
    t = "token ghp_123456789012345678901234567890123456"
    out = ss.redact_sensitive_text(t)
    assert "ghp_123456789012345678901234567890123456" not in out
    assert "ghp_[REDACTED]" in out
