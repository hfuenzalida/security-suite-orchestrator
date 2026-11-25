"""Resolve scan timeouts from SECURITY_SCAN_TIMEOUT_* (set via TOML [timeouts] or env)."""

from __future__ import annotations

import os


def scan_timeout_sec(key: str, default: int) -> int:
    """e.g. key 'nuclei' -> SECURITY_SCAN_TIMEOUT_NUCLEI."""
    env_key = f"SECURITY_SCAN_TIMEOUT_{key.upper().replace('-', '_')}"
    v = os.environ.get(env_key)
    if v is not None and str(v).strip().isdigit():
        return max(1, int(str(v).strip()))
    return default
