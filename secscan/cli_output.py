"""Console [OK]/[FAIL] helpers and ANSI colors (shared by all phases).

Color policy (https://no-color.org/):
  NO_COLOR (any non-empty value) — disable ANSI.
  CLICOLOR=0 — disable; CLICOLOR=1 — force enable even without a TTY.
  Otherwise — color when stdout is a TTY.

Quiet mode (--quiet / SECURITY_SCAN_QUIET):
  Suppresses ok/info/header and most [OK] chatter; fail/warn go to stderr.
  Final scan summary uses a compact stderr block (see print_final_summary).
"""

from __future__ import annotations

import logging
import os
import sys

from secscan.logging_config import strip_ansi_for_log

GREEN = ""
RED = ""
YELLOW = ""
BLUE = ""
BOLD = ""
RESET = ""

_SECSCAN_LOG: logging.Logger | None = None
_QUIET: bool = False


def ansi_color_enabled() -> bool:
    """Whether ANSI color sequences are applied (NO_COLOR / CLICOLOR / TTY)."""
    if os.environ.get("NO_COLOR", "").strip():
        return False
    cl = os.environ.get("CLICOLOR", "").strip().lower()
    if cl == "0":
        return False
    if cl == "1":
        return True
    return sys.stdout.isatty()


def _apply_color_globals() -> None:
    global GREEN, RED, YELLOW, BLUE, BOLD, RESET
    if ansi_color_enabled():
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        BLUE = "\033[94m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
    else:
        GREEN = RED = YELLOW = BLUE = BOLD = RESET = ""


_apply_color_globals()


def refresh_cli_ansi() -> None:
    """Re-apply NO_COLOR / CLICOLOR after environment changes (e.g. tests)."""
    _apply_color_globals()


def configure_cli_output(*, quiet: bool | None = None) -> None:
    """Call from CLI entry after parsing args. Enables quiet (suppressed chatter)."""
    global _QUIET
    if quiet is not None:
        _QUIET = bool(quiet)


def is_quiet() -> bool:
    return _QUIET


def configure_secscan_logger(log: logging.Logger | None) -> None:
    global _SECSCAN_LOG
    _SECSCAN_LOG = log


def _out_stream() -> object:
    return sys.stderr if _QUIET else sys.stdout


def ok(msg: str) -> None:
    if _QUIET:
        if _SECSCAN_LOG:
            _SECSCAN_LOG.info(strip_ansi_for_log(f"[OK] {msg}"))
        return
    print(f"  {GREEN}[OK]{RESET}      {msg}", file=sys.stdout)
    if _SECSCAN_LOG:
        _SECSCAN_LOG.info(strip_ansi_for_log(f"[OK] {msg}"))


def fail(msg: str) -> None:
    print(f"  {RED}[FAIL]{RESET}    {msg}", file=_out_stream())
    if _SECSCAN_LOG:
        _SECSCAN_LOG.error(strip_ansi_for_log(f"[FAIL] {msg}"))


def warn(msg: str) -> None:
    print(f"  {YELLOW}[WARN]{RESET}    {msg}", file=_out_stream())
    if _SECSCAN_LOG:
        _SECSCAN_LOG.warning(strip_ansi_for_log(f"[WARN] {msg}"))


def info(msg: str) -> None:
    if _QUIET:
        if _SECSCAN_LOG:
            _SECSCAN_LOG.info(strip_ansi_for_log(f"[INFO] {msg}"))
        return
    print(f"  {BLUE}[INFO]{RESET}    {msg}", file=sys.stdout)
    if _SECSCAN_LOG:
        _SECSCAN_LOG.info(strip_ansi_for_log(f"[INFO] {msg}"))


def header(msg: str) -> None:
    if _QUIET:
        return
    print(f"\n{BOLD}{'='*50}\n  {msg}\n{'='*50}{RESET}", file=sys.stdout)
