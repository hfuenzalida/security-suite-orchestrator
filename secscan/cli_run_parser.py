"""
Grouped CLI for `security-scan` / `security-scan run` — see CLI_ROADMAP.md Phase 3.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from secscan.checkpoint_core import DEFAULT_WORKSPACE_DIR as _DEFAULT_WORKSPACE_DIR
from secscan.constants import (
    CORRELATION_JOIN_RULES_VERSION,
    ORCHESTRATOR_VERSION,
    REPORT_SCHEMA_COMPAT_VERSION,
)

CLI_RUN_EPILOG = """
Documentation:
  USER_MANUAL.md            Features, full vs partial reviews (--skip recipes), config
  OPERATING_GUARANTEES.md   Supported use, limits, versioning expectations
  CI_AND_GATES.md           Exit codes, SARIF/JUnit, --ci-profile, tool profiles
  REPORT_TIERS.md          Gate truth: JSON/SARIF/JUnit vs HTML/PDF narrative

Typical invocations:
  %(prog)s --path . --url http://localhost:8080 --output report.json
  %(prog)s run --ci-profile --fail-on high --junit-output junit.xml --sarif-output results.sarif
  %(prog)s replay --help

Subcommands:
  run     Default scan (optional — same flags as a bare invocation)
  replay  Replay-bundle workflow help (see REPRODUCIBILITY.md)
  doctor  Verify installed tools for a profile (see CI_AND_GATES.md)

Phase 4:
  --print-completion bash|zsh|pwsh   Shell completion script on stdout
  --config-dry-run                   Show merged config; no scan

Phase 5:
  doctor [--profile …] [--json] [--strict]   Tool matrix (same as check_security_tools.py)
  --doctor                         Shorthand: run default doctor check and exit

Exit codes (CI honesty — full detail in CI_AND_GATES.md):
  0  Run finished; --fail-on policy satisfied; no fatal orchestrator error
  1  Policy/gate failure, invalid args, missing checkpoint/resume target, or controlled failure

Environment:
  SECURITY_SCAN_*           Prefix for env overrides (see security_scan.toml.example).
""".strip()


def strip_optional_run_argv(argv: list[str]) -> tuple[str | None, list[str]]:
    """
    If argv starts with 'replay' or 'run', return (subcommand, rest).
    Legacy invocations (first token is a flag or path) use (None, argv).
    """
    if not argv:
        return None, argv
    head = argv[0]
    if head == "replay":
        return "replay", argv[1:]
    if head == "run":
        return "run", argv[1:]
    if head == "doctor":
        return "doctor", argv[1:]
    return None, argv


def run_replay_stub(argv: list[str]) -> None:
    """
    Document how replay_bundle is produced; no separate replay engine entry (Phase 3 stub).
    """
    parser = argparse.ArgumentParser(
        prog="security-scan replay",
        description=(
            "Replay metadata is recorded in run_manifest.replay_bundle during a normal scan. "
            "Use --replay-bundle-output to write a CI/archive JSON (orchestrator_version + replay_bundle)."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Examples:\n"
            "  security-scan --path . --url http://app --replay-bundle-output archive.json\n"
            "  security-scan run --replay-bundle-output archive.json --path . --url http://app\n"
            "See REPRODUCIBILITY.md, CORRELATION_JOIN_RULES.md, WORKSPACE_CONTRACT.md."
        ),
    )
    parser.add_argument(
        "--print-workflow",
        action="store_true",
        help="Print a short workflow summary to stdout and exit 0.",
    )
    if not argv:
        print(
            "replay: emit a bundle with --replay-bundle-output during a scan; "
            "see REPRODUCIBILITY.md. Use --print-workflow for steps.",
            file=sys.stdout,
        )
        raise SystemExit(0)
    args = parser.parse_args(argv)
    if args.print_workflow:
        print(
            "1) Run a scan with --replay-bundle-output FILE.json\n"
            "2) FILE.json contains orchestrator_version and replay_bundle (spec_version, tool pins, …)\n"
            "3) Compare with run_manifest.replay_bundle inside the full JSON report",
            file=sys.stdout,
        )
    raise SystemExit(0)


def build_run_parser(merged_defaults: dict[str, Any]) -> argparse.ArgumentParser:
    """Build `security-scan [run]` parser with logical argument groups."""
    parser = argparse.ArgumentParser(
        prog="security-scan",
        description=(
            "Security Suite Orchestrator — multi-phase local scans (SAST, secrets, dependencies, "
            "DAST, recon, PoC) with unified reporting, baselines, and CI-oriented exports.\n"
            "Optional prefix: `run` (security-scan run …) is equivalent to a bare invocation."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=CLI_RUN_EPILOG,
    )
    parser.set_defaults(**{k: v for k, v in merged_defaults.items() if k in MERGED_CONFIG_KEYS})

    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"%(prog)s {ORCHESTRATOR_VERSION} "
            f"(report_schema_compat={REPORT_SCHEMA_COMPAT_VERSION}, "
            f"correlation_join_rules={CORRELATION_JOIN_RULES_VERSION})"
        ),
    )

    g_core = parser.add_argument_group("Core scan")
    g_core.add_argument("--path", default=".", help="Path to scan (default: current directory)")
    g_core.add_argument(
        "--url",
        default=None,
        help="Target URL for DAST tools (e.g. http://localhost:8080)",
    )
    g_core.add_argument(
        "--skip",
        nargs="*",
        default=[],
        help="Phases to skip: code_ai recon secrets sast deps auth chain dast browser zap agents exploit ai",
    )
    g_core.add_argument(
        "--ai-model",
        default="qwen2.5-coder:3b",
        help="Ollama model for AI phases (default: qwen2.5-coder:3b)",
    )
    g_core.add_argument(
        "--auth-config",
        default=None,
        help="JSON/TOML file for Phase 2 login (login_url, username, password; optional totp_secret, method, selectors)",
    )
    g_core.add_argument(
        "--chain-config",
        default=None,
        help="JSON/TOML file for Phase 3 multi-step HTTP chain (steps, context, capture regex; optional seed_from_auth)",
    )
    g_core.add_argument(
        "--workspace",
        default=_DEFAULT_WORKSPACE_DIR,
        help=f"Directory for run checkpoints (default: {_DEFAULT_WORKSPACE_DIR})",
    )
    g_core.add_argument(
        "--run-id",
        default=None,
        help="Run folder name under workspace (default: derived from URL host + path hash)",
    )
    g_core.add_argument(
        "--resume",
        default=None,
        metavar="RUN_ID",
        help="Resume from workspace/RUN_ID/checkpoint.json (same --path, --url, --auth-config, --chain-config as original run)",
    )
    g_core.add_argument(
        "--no-checkpoint",
        action="store_true",
        help="Do not write or read checkpoint.json",
    )

    g_rep = parser.add_argument_group("Reports & exports")
    g_rep.add_argument("--output", default="security_report.json", help="JSON report path")
    g_rep.add_argument(
        "--html",
        default="security_report.html",
        help="HTML report path (default: security_report.html)",
    )
    g_rep.add_argument(
        "--pdf",
        default="security_report.pdf",
        help="PDF report path (default: security_report.pdf)",
    )
    g_rep.add_argument(
        "--report-tier",
        choices=("executive", "technical", "full"),
        default="full",
        help=(
            "HTML/PDF narrative: executive (EXPLOITED-first, summarize rest), "
            "technical (authoritative vs potential bands), full (single list, EXPLOITED first)"
        ),
    )
    g_rep.add_argument(
        "--sanitize-exports",
        action="store_true",
        help="Redact sensitive strings in JSON/HTML/PDF artifacts (full in-memory report unchanged)",
    )

    g_ci = parser.add_argument_group("CI & gating")
    g_ci.add_argument(
        "--fail-on",
        choices=("never", "any", "exploit", "critical", "high"),
        default="never",
        help="CI exit policy: never | any (tool counts) | exploit (PoC confirmed) | critical | high (unified severity incl. nuclei)",
    )
    g_ci.add_argument(
        "--baseline",
        default=None,
        metavar="FILE",
        help="JSON file of correlation_id hex strings (sha256) to exclude from unified gates & fail-on any/critical/high",
    )
    g_ci.add_argument(
        "--sarif-output",
        default=None,
        metavar="FILE",
        help="Write SARIF 2.1.0 for GitHub Code Scanning / CI (see --sarif-source)",
    )
    g_ci.add_argument(
        "--sarif-source",
        choices=("tool_native", "unified"),
        default="tool_native",
        help=(
            "tool_native: semgrep/bandit/nuclei only; unified: rows match --fail-on unified list "
            "(after baseline) — use for gate/Code Scanning parity"
        ),
    )
    g_ci.add_argument(
        "--junit-output",
        default=None,
        metavar="FILE",
        help="Write minimal JUnit XML for CI dashboards (reflects exit policy vs findings)",
    )
    g_ci.add_argument(
        "--emit-baseline-suggestions",
        default=None,
        metavar="FILE",
        help="Write suggested baseline fingerprints JSON from unified findings (triage aid)",
    )
    g_ci.add_argument(
        "--ci-profile",
        action="store_true",
        help="Preset for CI: skip heavy phases, technical report tier, fail_on=high if still never",
    )

    g_replay = parser.add_argument_group("Replay & reproducibility")
    g_replay.add_argument(
        "--replay-bundle-output",
        default=None,
        metavar="FILE",
        help=(
            "Write replay-bundle JSON (orchestrator version, config SHA-256, tool version pins, "
            "workspace paths) for archives or CI artifacts; see CORRELATION_JOIN_RULES.md"
        ),
    )
    g_replay.add_argument(
        "--replay-include-pip-freeze",
        action="store_true",
        help=(
            "Include pip freeze SHA-256 in run_manifest.replay_bundle (slower; full interpreter env pin). "
            "Or set SECURITY_SCAN_REPLAY_PIP_FREEZE=1. See REPRODUCIBILITY.md"
        ),
    )
    g_replay.add_argument(
        "--wipe-run-dir",
        action="store_true",
        help=(
            "After successful completion (exit 0), delete workspace/RUN_ID. "
            "Ignored with --no-checkpoint, --resume, or failed runs"
        ),
    )
    g_replay.add_argument(
        "--wipe-temp",
        action="store_true",
        help=(
            "After successful completion (exit 0), delete registered temp artifacts "
            "(nuclei target lists, auth storage paths, XSS screenshots, browser_screenshot.png). "
            "Runs after HTML/PDF are written. See WORKSPACE_CONTRACT.md"
        ),
    )

    g_safe = parser.add_argument_group("Safe operations & scope")
    g_safe.add_argument(
        "--network-mode",
        choices=("default", "minimal-outbound", "offline-static"),
        default="default",
        help=(
            "Merge recommended --skip to reduce outbound DNS/LLM: minimal-outbound (recon), "
            "offline-static (recon+code_ai+ai). See NETWORK_MODE.md / SAFE_OPERATIONS.md"
        ),
    )
    g_safe.add_argument(
        "--include-glob",
        action="append",
        default=[],
        dest="include_globs",
        metavar="PATTERN",
        help="Keep only file-backed unified findings matching glob under --path (repeatable)",
    )
    g_safe.add_argument(
        "--exclude-glob",
        action="append",
        default=[],
        dest="exclude_globs",
        metavar="PATTERN",
        help="Exclude unified findings matching glob after includes (repeatable)",
    )

    g_note = parser.add_argument_group("Notifications & audit")
    g_note.add_argument(
        "--notify-webhook",
        default=None,
        metavar="URL",
        help="POST JSON when --notify-on matches (Slack/Discord/custom HTTPS endpoint)",
    )
    g_note.add_argument(
        "--notify-on",
        choices=("never", "exploit", "any", "critical", "high"),
        default="exploit",
        help="Trigger for --notify-webhook (default: exploit = confirmed PoC only)",
    )
    g_note.add_argument(
        "--audit-log-jsonl",
        default=None,
        metavar="FILE",
        help="Append one JSON line per run (report path, SHA-256, exit policy) for SIEM or evidence chains",
    )
    g_note.add_argument(
        "--hmac-sign-report",
        action="store_true",
        help="Write <report>.json.hmac next to JSON (HMAC-SHA256); use env SECURITY_SCAN_REPORT_HMAC_KEY or --report-hmac-key-file",
    )
    g_note.add_argument(
        "--report-hmac-key-file",
        default=None,
        metavar="FILE",
        help="File containing shared secret for --hmac-sign-report",
    )

    g_cfg = parser.add_argument_group("Config & logging")
    g_cfg.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help="Optional TOML (defaults, paths); auto-loads security_scan.toml or secscan.toml in cwd if omitted",
    )
    g_cfg.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help=(
            "Suppress [OK]/[INFO] lines and phase headers; failures/warnings go to stderr; "
            "short final summary on stderr (see CLI_ROADMAP.md)"
        ),
    )
    g_cfg.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose diagnostics; mirror [OK]/[INFO]/… lines to stderr log",
    )
    g_cfg.add_argument(
        "--log-json",
        action="store_true",
        dest="log_json",
        help="Emit secscan logger lines as JSON on stderr (for CI log aggregators)",
    )
    g_cfg.add_argument(
        "--log-file",
        default=None,
        metavar="FILE",
        help="Append UTF-8 log lines to this file",
    )

    g_exp = parser.add_argument_group("Expert productivity (Phase 4)")
    g_exp.add_argument(
        "--print-completion",
        choices=("bash", "zsh", "pwsh"),
        metavar="SHELL",
        default=None,
        help=(
            "Print a shell completion script to stdout and exit 0. "
            "Example: eval \"$(security-scan --print-completion bash)\""
        ),
    )
    g_exp.add_argument(
        "--config-dry-run",
        action="store_true",
        help="Load TOML/env, merge CLI, print effective settings, exit 0 without scanning",
    )

    g_diag = parser.add_argument_group("Diagnostics (Phase 5)")
    g_diag.add_argument(
        "--doctor",
        action="store_true",
        help=(
            "Run tool matrix check with profile ci-minimal and exit (no scan). "
            "For other profiles use: security-scan doctor --profile …"
        ),
    )

    return parser


# Keys accepted from merged TOML/env defaults (keep in sync with security_scan consumers)
MERGED_CONFIG_KEYS = frozenset({
    "path", "url", "output", "html", "pdf", "ai_model", "workspace", "fail_on",
    "auth_config", "chain_config", "sarif_output", "baseline", "verbose", "log_json",
    "log_file", "notify_webhook", "notify_on", "resume", "run_id", "skip",
    "sanitize_exports", "junit_output", "emit_baseline_suggestions",
    "replay_bundle_output", "replay_include_pip_freeze", "wipe_run_dir", "wipe_temp",
    "report_tier", "audit_log_jsonl", "hmac_sign_report", "report_hmac_key_file",
    "ci_profile", "sarif_source",
    "network_mode", "include_globs", "exclude_globs",
    "quiet",
})
