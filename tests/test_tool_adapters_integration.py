"""Tests for versioned tool adapters, retries, and JSON parsing."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.tool_adapters.dast_parsers import parse_nuclei_jsonl  # noqa: E402
from secscan.tool_adapters.dependency_parsers import parse_pip_audit_json  # noqa: E402
from secscan.tool_adapters.runner import EXIT_TIMEOUT, RunMetadata, run_with_retries  # noqa: E402
from secscan.tool_adapters.secrets_parsers import parse_gitleaks_report_json  # noqa: E402


def test_run_with_retries_stops_on_timeout_then_succeeds(monkeypatch):
    calls: list[int] = []

    def fake_run(cmd, timeout):
        calls.append(1)
        if len(calls) == 1:
            return EXIT_TIMEOUT, "", "timed out"
        return 0, '{"results":[]}', ""

    monkeypatch.setattr("secscan.tool_adapters.runner._run_once", fake_run)

    code, out, err, meta = run_with_retries(["semgrep", "--json", "."], timeout=30, max_attempts=2)
    assert code == 0
    assert '"results"' in out
    assert meta.retried is True
    assert meta.attempts == 2


def test_run_with_retries_no_retry_on_missing_binary(monkeypatch):
    from secscan.subprocess_runner import run as real_run

    monkeypatch.setattr(
        "secscan.tool_adapters.runner._run_once",
        lambda cmd, timeout: real_run(["__nonexistent_tool_xyz__"], timeout=timeout),
    )
    code, out, err, meta = run_with_retries(["__nonexistent_tool_xyz__"], timeout=5, max_attempts=3)
    assert code == -1
    assert meta.attempts == 1
    assert meta.retried is False


def test_parse_gitleaks_valid_array():
    raw = '[{"RuleID":"x","File":"a.py","StartLine":1}]'
    rows, err = parse_gitleaks_report_json(raw)
    assert err is None
    assert len(rows) == 1
    assert rows[0]["RuleID"] == "x"


def test_parse_gitleaks_rejects_non_array():
    rows, err = parse_gitleaks_report_json('{"oops":1}')
    assert rows == []
    assert err is not None


def test_parse_nuclei_jsonl_skips_bad_lines():
    out = '{"template-id":"t1","info":{}}\nnot-json\n{"template-id":"t2","info":{}}\n'
    findings, skipped = parse_nuclei_jsonl(out)
    assert len(findings) == 2
    assert skipped == 1


def test_parse_pip_audit_modern_shape():
    raw = '{"dependencies":[{"name":"req","version":"1.0","vulns":[{"id":"CVE-1"}]}]}'
    deps, err = parse_pip_audit_json(raw)
    assert err is None
    assert len(deps) == 1
    assert deps[0]["name"] == "req"


def test_run_metadata_integration_dict():
    m = RunMetadata(attempts=2, elapsed_ms_total=99.5, retried=True, exit_code=0)
    d = m.as_integration_dict("test-adapter/1")
    assert d["adapter"] == "test-adapter/1"
    assert d["retried"] is True
    assert d["exit_code"] == 0
