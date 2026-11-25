"""Resolve optional external tool paths (ZAP, Nmap) with OS-aware defaults."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

# Typical install locations
_WIN_ZAP = Path(r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat")
_WIN_NMAP = Path(r"C:\Program Files\Nmap\nmap.exe")


def resolve_zap_bat() -> tuple[Path | None, str]:
    """Return (path, hint) for ZAP launcher. hint is empty if found."""
    env = os.environ.get("SECURITY_SCAN_ZAP_BAT") or os.environ.get("ZAP_BAT")
    if env:
        p = Path(env).expanduser()
        if p.is_file():
            return p, ""
        return None, f"SECURITY_SCAN_ZAP_BAT points to missing file: {p}"
    if _WIN_ZAP.is_file():
        return _WIN_ZAP, ""
    if sys.platform != "win32":
        zap = shutil.which("zap.sh") or shutil.which("zap")
        if zap:
            return Path(zap), ""
    return None, (
        "ZAP not found. Set SECURITY_SCAN_ZAP_BAT to zap.bat (Windows) or install ZAP on PATH (Linux/macOS)."
    )


def resolve_nmap() -> tuple[str, str]:
    """Return (argv0, hint) — argv0 is executable name or full path for subprocess."""
    env = os.environ.get("SECURITY_SCAN_NMAP") or os.environ.get("NMAP_PATH")
    if env:
        p = Path(env).expanduser()
        if p.is_file():
            return str(p), ""
        return "nmap", f"SECURITY_SCAN_NMAP points to missing file: {p} — falling back to 'nmap' on PATH"
    if _WIN_NMAP.is_file():
        return str(_WIN_NMAP), ""
    if shutil.which("nmap"):
        return "nmap", ""
    return "nmap", (
        "nmap not on PATH. Install Nmap or set SECURITY_SCAN_NMAP to the nmap executable "
        f"(e.g. {_WIN_NMAP})."
    )
