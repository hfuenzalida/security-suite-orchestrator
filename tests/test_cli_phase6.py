"""
Phase 6 CLI hardening: help epilog exit codes, flag inventory guards, argv safety.

See CLI_ROADMAP.md Phase 6 and CI_AND_GATES.md.
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "security_scan.py"


# If a flag is renamed or dropped accidentally, this test fails — update intentionally only.
_CRITICAL_LONG_FLAGS = frozenset(
    {
        "--path",
        "--url",
        "--fail-on",
        "--baseline",
        "--ci-profile",
        "--sarif-output",
        "--sarif-source",
        "--junit-output",
        "--config-dry-run",
        "--print-completion",
        "--doctor",
        "--quiet",
        "--replay-bundle-output",
        "--network-mode",
        "--include-glob",
        "--exclude-glob",
        "--audit-log-jsonl",
        "--sanitize-exports",
        "--version",
    }
)


def test_help_includes_exit_code_epilog():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    h = r.stdout
    assert "Exit codes" in h
    assert "CI_AND_GATES" in h
    assert "policy satisfied" in h
    assert "controlled failure" in h or "Policy/gate failure" in h


def test_critical_flags_remain_in_parser():
    from secscan.cli_completions import collect_option_strings
    from secscan.cli_run_parser import build_run_parser

    opts = set(collect_option_strings(build_run_parser({})))
    missing = _CRITICAL_LONG_FLAGS - opts
    assert not missing, f"Parser missing expected flags (rename accident?): {sorted(missing)}"


def test_version_stdout_matches_orchestrator_constant():
    from secscan.constants import ORCHESTRATOR_VERSION

    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--version"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
    out = (r.stdout + r.stderr).strip()
    assert ORCHESTRATOR_VERSION in out
    assert re.search(r"report_schema_compat=\d+", out)
    assert re.search(r"correlation_join_rules=\d+", out)


def test_unknown_flag_exits_2():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--not-a-real-flag-phase6-xyz"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 2
    err = (r.stdout + r.stderr).lower()
    assert "unrecognized" in err or "error" in err or "invalid" in err


def test_cli_run_epilog_module_contains_exit_block():
    from secscan import cli_run_parser as cr

    assert "Exit codes" in cr.CLI_RUN_EPILOG
    assert "CI_AND_GATES" in cr.CLI_RUN_EPILOG


def test_argv_with_unicode_does_not_crash_before_parse():
    """Argparse receives argv; exotic tokens should fail cleanly, not traceback."""
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help", "café-\u202e"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(ROOT),
    )
    assert r.returncode == 0
