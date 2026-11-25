"""Print merged effective CLI config without running a scan — CLI_ROADMAP.md Phase 4."""

from __future__ import annotations

import os
from argparse import Namespace
from pathlib import Path

from secscan.constants import ENV_PREFIX
from secscan.user_config import discover_config_file, load_toml_defaults


def print_effective_config(args: Namespace, *, explicit_config: str | None) -> None:
    """Write human-readable effective settings to stdout."""
    print("security-scan — config dry-run (no scan executed)")
    print("=" * 52)

    disc = discover_config_file(explicit_config)
    if disc and disc.is_file():
        print(f"Resolved config file: {disc.resolve()}")
        td = load_toml_defaults(disc)
        if td:
            keys = ", ".join(sorted(td.keys()))
            print(f"  Merged keys from TOML + env bootstrap: {keys}")
    elif explicit_config:
        print(f"Explicit --config not found: {explicit_config!r}")
    else:
        print("Resolved config file: (none — no security_scan.toml / secscan.toml in cwd)")

    env_keys = sorted(k for k in os.environ if k.startswith(ENV_PREFIX))
    if env_keys:
        print(f"SECURITY_SCAN_* variables: {len(env_keys)} set (merged before CLI parse)")
        for k in env_keys[:24]:
            val = os.environ.get(k, "")
            if "KEY" in k.upper() or "SECRET" in k.upper() or "PASSWORD" in k.upper() or "WEBHOOK" in k.upper():
                show = "<redacted>" if val else ""
            else:
                show = val[:72] + ("…" if len(val) > 72 else "")
            print(f"  {k}={show}")
        if len(env_keys) > 24:
            print(f"  … (+{len(env_keys) - 24} more)")
    else:
        print("SECURITY_SCAN_* variables: (none)")

    print()
    print("Effective namespace (post-parse; CI/network transforms applied if flags were set):")
    for k in sorted(vars(args)):
        if k.startswith("_"):
            continue
        v = getattr(args, k)
        if k == "notify_webhook" and v:
            v = "<set>"
        if k in ("report_hmac_key_file", "auth_config", "chain_config", "baseline") and v:
            v = f"<path: {Path(str(v)).name}>"
        print(f"  {k}: {v!r}")
