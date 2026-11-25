"""
Verify optional security CLIs (profiles from secscan/ci_tool_profiles.py).

Used by `check_security_tools.py` and `security-scan doctor` — CLI_ROADMAP.md Phase 5.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Sequence

from secscan.ci_tool_profiles import (
    PROFILE_CHOICES,
    PROFILE_FULL,
    tool_specs_for_profile,
)
from secscan.cli_output import ansi_color_enabled
from secscan.constants import ORCHESTRATOR_VERSION


def check_tool(name: str, cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        output = (result.stdout + result.stderr).decode(errors="ignore").strip().splitlines()
        version_line = output[0] if output else "unknown version"
        return True, version_line
    except FileNotFoundError:
        return False, ""
    except subprocess.TimeoutExpired:
        return False, "timeout"


def _ansi() -> tuple[str, str, str, str]:
    if ansi_color_enabled():
        return "\033[92m", "\033[91m", "\033[93m", "\033[0m"
    return "", "", "", ""


def build_tool_doctor_parser(*, prog: str) -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog=prog,
        description=(
            "Verify installed security tools (optional orchestrator dependencies). "
            "Aligns with CI profiles in secscan/ci_tool_profiles.py and CI_AND_GATES.md."
        ),
    )


def run_tool_doctor(
    argv: Sequence[str] | None,
    *,
    prog: str = "check-security-tools",
    entry_label: str | None = None,
) -> int:
    """
    argv: forwarded to argparse (None = sys.argv).
    entry_label: e.g. 'security-scan doctor' for JSON metadata.
    """
    parser = build_tool_doctor_parser(prog=prog)
    parser.add_argument(
        "--profile",
        choices=PROFILE_CHOICES,
        default=PROFILE_FULL,
        help=(
            "ci-minimal: pip-style tools for typical --ci-profile PR gates; "
            "ci-extended: + safety/schemathesis/gitleaks/nuclei; "
            "full: entire matrix (lab/pentest)."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any tool in the profile is missing (for CI gates).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON to stdout (no ANSI).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    GREEN, RED, YELLOW, RESET = _ansi()
    label = entry_label or prog
    specs = tool_specs_for_profile(args.profile)
    results: list[dict[str, object]] = []
    missing = 0

    if not args.json:
        print("\n====================================")
        print("   Security Tools Verification")
        print(f"   {label}")
        print(f"   profile={args.profile}")
        print("====================================\n")

    for spec in specs:
        ok_flag, ver = check_tool(spec.key, spec.cmd)
        results.append(
            {
                "name": spec.key,
                "present": ok_flag,
                "version_line": ver if ok_flag else None,
            }
        )
        if not ok_flag:
            missing += 1

        if args.json:
            continue
        if ok_flag:
            print(f"  {GREEN}[OK]{RESET}      {spec.key:<20} {YELLOW}{ver}{RESET}")
        else:
            print(f"  {RED}[MISSING]{RESET}  {spec.key}")

    present = len(specs) - missing

    if args.json:
        payload: dict[str, object] = {
            "orchestrator_version": ORCHESTRATOR_VERSION,
            "cli_entry": label,
            "profile": args.profile,
            "present": present,
            "missing": missing,
            "total": len(specs),
            "strict_would_fail": missing > 0,
            "tools": results,
        }
        print(json.dumps(payload, indent=2))
    else:
        print("\n------------------------------------")
        print(f"  {GREEN}Installed: {present}{RESET}  |  {RED}Missing: {missing}{RESET}")
        print("------------------------------------\n")
        if missing > 0:
            print(f"{YELLOW}Tip:{RESET} For profile {args.profile!r}, install missing tools.")
            if args.profile == "ci-minimal":
                print("  pip install semgrep bandit pip-audit detect-secrets\n")
            elif args.profile == "ci-extended":
                print(
                    "  pip install safety schemathesis; "
                    "install gitleaks/nuclei binaries per vendor docs.\n"
                )
            else:
                print("  pip install semgrep bandit pip-audit safety detect-secrets schemathesis\n")
                print("Binary tools (gitleaks, nuclei): download and place on PATH.\n")

    if args.strict and missing > 0:
        return 1
    return 0


def run_doctor_subcommand(argv: list[str]) -> int:
    """`security-scan doctor …` — thin wrapper with stable JSON metadata."""
    return run_tool_doctor(
        argv,
        prog="security-scan doctor",
        entry_label="security-scan doctor",
    )
