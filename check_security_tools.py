#!/usr/bin/env python3
"""Verify optional security CLIs; supports CI profiles aligned with secscan/ci_tool_profiles.py."""

from __future__ import annotations

import os
import sys

from secscan.tool_doctor import run_tool_doctor


def main() -> int:
    return run_tool_doctor(
        None,
        prog="check-security-tools",
        entry_label="check_security_tools.py",
    )


if __name__ == "__main__":
    if sys.platform == "win32" and not os.environ.get("CI"):
        os.system("color")
    raise SystemExit(main())
