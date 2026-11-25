"""Subprocess wrapper for external security tools."""

from __future__ import annotations

import os
import subprocess
from typing import Tuple


def run(cmd: list[str], timeout: int = 120) -> Tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
        return (
            proc.returncode,
            proc.stdout.decode(errors="ignore"),
            proc.stderr.decode(errors="ignore"),
        )
    except FileNotFoundError:
        return (-1, "", f"Command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return (-2, "", f"Timeout after {timeout}s")
