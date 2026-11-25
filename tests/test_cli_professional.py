"""Professional CLI surface: --version, help epilog, entry compatibility."""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "security_scan.py"


def test_version_exits_zero_and_prints_orchestrator_version():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--version"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    out = (r.stdout + r.stderr).strip()
    from secscan.constants import ORCHESTRATOR_VERSION

    assert ORCHESTRATOR_VERSION in out
    assert "report_schema_compat=" in out or "0.2." in out


def test_help_includes_epilog_doc_pointers():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    h = r.stdout
    assert "USER_MANUAL.md" in h
    assert "OPERATING_GUARANTEES.md" in h
    assert "CI_AND_GATES.md" in h
    assert "REPORT_TIERS.md" in h


def test_parser_uses_security_scan_prog():
    import security_scan as ss

    # Smoke: module defines epilog used by main's parser (import side effect OK)
    assert "OPERATING_GUARANTEES" in ss._CLI_EPILOG


# --- Phase 2: NO_COLOR / CLICOLOR / --quiet ---------------------------------


def test_no_color_clears_ansi_globals(monkeypatch):
    import secscan.cli_output as co

    monkeypatch.setenv("NO_COLOR", "1")
    co.refresh_cli_ansi()
    try:
        assert co.GREEN == ""
        assert co.RED == ""
        assert co.RESET == ""
    finally:
        monkeypatch.delenv("NO_COLOR", raising=False)
        co.refresh_cli_ansi()


def test_clicolor_zero_disables_ansi(monkeypatch):
    import secscan.cli_output as co

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("CLICOLOR", "0")
    co.refresh_cli_ansi()
    try:
        assert co.GREEN == ""
    finally:
        monkeypatch.delenv("CLICOLOR", raising=False)
        co.refresh_cli_ansi()


def test_quiet_suppresses_ok_and_info(capsys):
    import secscan.cli_output as co

    co.configure_cli_output(quiet=True)
    try:
        co.ok("x")
        co.info("y")
        out, _err = capsys.readouterr()
        assert out == ""
    finally:
        co.configure_cli_output(quiet=False)


def test_quiet_fail_goes_to_stderr(capsys):
    import secscan.cli_output as co

    co.configure_cli_output(quiet=True)
    try:
        co.fail("problem")
        out, err = capsys.readouterr()
        assert out == ""
        assert "[FAIL]" in err
        assert "problem" in err
    finally:
        co.configure_cli_output(quiet=False)


def test_print_final_summary_quiet_stderr(capsys):
    from secscan.reporting.output_reports import print_final_summary

    import secscan.cli_output as co

    co.configure_cli_output(quiet=True)
    try:
        print_final_summary(
            {
                "summary": {"semgrep": 2, "bandit": 0},
                "total_findings": 2,
                "_output_path": "/tmp/report.json",
                "ai_reasoning": {"status": "skipped"},
            }
        )
        out, err = capsys.readouterr()
        assert out == ""
        assert "Total findings: 2" in err
        assert "semgrep: 2 finding(s)" in err
        assert "/tmp/report.json" in err
    finally:
        co.configure_cli_output(quiet=False)


def test_security_scan_accepts_quiet_flag():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--quiet", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    assert "--quiet" in r.stdout


# --- Phase 3: grouped help, run / replay -----------------------------------


def test_help_shows_argument_groups():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    h = r.stdout
    assert "Core scan" in h
    assert "CI & gating" in h
    assert "Replay & reproducibility" in h


def test_run_prefix_version_matches_bare():
    a = subprocess.run(
        [sys.executable, str(SCRIPT), "--version"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    b = subprocess.run(
        [sys.executable, str(SCRIPT), "run", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert a.returncode == 0 and b.returncode == 0
    assert a.stdout.strip() == b.stdout.strip()


def test_replay_stub_no_args_exits_zero():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "replay"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    assert "REPRODUCIBILITY" in (r.stdout + r.stderr) or "replay" in r.stdout.lower()


def test_replay_print_workflow():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "replay", "--print-workflow"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    assert "replay_bundle" in (r.stdout + r.stderr).lower() or "orchestrator" in (r.stdout + r.stderr).lower()


# --- Phase 4: completions + config dry-run --------------------------------


def test_help_lists_expert_productivity_flags():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    assert "Expert productivity" in r.stdout
    assert "--print-completion" in r.stdout
    assert "--config-dry-run" in r.stdout


def test_print_completion_bash():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--print-completion", "bash"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    out = r.stdout
    assert "_security_scan_complete" in out
    assert "complete " in out
    assert "--path" in out


def test_print_completion_pwsh_contains_register():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--print-completion", "pwsh"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    assert "Register-ArgumentCompleter" in r.stdout


def test_config_dry_run_exits_zero_and_prints_namespace():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--config-dry-run", "--path", ".", "--fail-on", "high"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    out = r.stdout
    assert "dry-run" in out.lower()
    assert "fail_on" in out
    assert "'high'" in out or "high" in out


def test_collect_option_strings_includes_phase4_flags():
    from secscan.cli_completions import collect_option_strings
    from secscan.cli_run_parser import build_run_parser

    p = build_run_parser({})
    opts = collect_option_strings(p)
    assert "--print-completion" in opts
    assert "--config-dry-run" in opts
    assert "--doctor" in opts


def test_doctor_subcommand_json_has_orchestrator_and_tools():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "doctor", "--profile", "ci-minimal", "--json"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    import json

    data = json.loads(r.stdout)
    assert "orchestrator_version" in data
    assert data.get("cli_entry") == "security-scan doctor"
    assert data.get("profile") == "ci-minimal"
    assert "tools" in data


def test_doctor_shorthand_flag_runs_matrix():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--doctor", "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    assert "Security Tools Verification" in r.stdout or "verification" in r.stdout.lower()


def test_help_lists_diagnostics_doctor():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    assert "Diagnostics" in r.stdout
    assert "--doctor" in r.stdout
