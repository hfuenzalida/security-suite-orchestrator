"""Safe-operations metadata: network posture, path scope, redaction version, temp registry snapshot."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from secscan.constants import REDACTION_RULESET_VERSION
from secscan.temp_registry import registry_snapshot


def build_safe_operations_embed(args: argparse.Namespace, scan_path: str) -> dict[str, Any]:
    """Structured block for JSON reports + compliance (see SAFE_OPERATIONS.md)."""
    inc = tuple(getattr(args, "include_globs", None) or ())
    exc = tuple(getattr(args, "exclude_globs", None) or ())
    return {
        "schema_version": 1,
        "doc": "SAFE_OPERATIONS.md",
        "network_mode": getattr(args, "network_mode", "default") or "default",
        "path_scope": {
            "include_globs": list(inc),
            "exclude_globs": list(exc),
            "scan_path_resolved": str(Path(scan_path).resolve()),
            "note": (
                "Globs apply to file-backed unified finding paths (fnmatch on path relative to --path). "
                "URL/DAST rows are not filtered by path scope when includes are set."
            ),
        },
        "exports": {
            "sanitize_exports": bool(getattr(args, "sanitize_exports", False)),
            "wipe_temp_requested": bool(getattr(args, "wipe_temp", False)),
            "wipe_run_dir_requested": bool(getattr(args, "wipe_run_dir", False)),
        },
        "redaction": {
            "ruleset_version": REDACTION_RULESET_VERSION,
            "note": "Pattern redaction is best-effort; see OPERATING_GUARANTEES.md",
        },
        "temp_artifacts": registry_snapshot(),
        "operator_reminders": {
            "firewall": "Kernel/container firewall is outside the CLI; see NETWORK_MODE.md",
            "wipe_temp_scope": "Only paths registered via register_temp_path are removed by --wipe-temp",
        },
    }
