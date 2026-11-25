"""Run manifest: git, tool versions, argv redaction, replay bundle."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

from secscan.constants import (
    CORRELATION_JOIN_RULES_VERSION,
    ORCHESTRATOR_VERSION,
    REDACTION_RULESET_VERSION,
    REPORT_SCHEMA_COMPAT_VERSION,
)
from secscan.reproducibility import (
    pip_freeze_sha256,
    replay_non_determinism_note,
    runtime_environment,
    scan_path_relative_to_git,
    supply_chain_file_hashes,
)
from secscan.user_config import discover_config_file


def _git_probe(scan_path: str) -> dict:
    root = Path(scan_path)
    try:
        for base in [root, *root.parents]:
            if (base / ".git").exists():
                def _g(args: list[str]) -> str:
                    p = subprocess.run(
                        ["git", "-C", str(base), *args],
                        capture_output=True,
                        text=True,
                        timeout=8,
                        errors="ignore",
                    )
                    return (p.stdout or "").strip()

                return {
                    "git_root": str(base.resolve()),
                    "commit": _g(["rev-parse", "HEAD"]) or None,
                    "branch": _g(["rev-parse", "--abbrev-ref", "HEAD"]) or None,
                }
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return {"git_root": None, "commit": None, "branch": None}


def snapshot_tool_versions() -> dict[str, str | None]:
    tools: list[tuple[str, list[str]]] = [
        ("python", [sys.executable, "-V"]),
        ("semgrep", ["semgrep", "--version"]),
        ("bandit", ["bandit", "--version"]),
        ("gitleaks", ["gitleaks", "version"]),
        ("nuclei", ["nuclei", "-version"]),
        ("pip_audit", ["pip-audit", "--version"]),
        ("detect_secrets", ["detect-secrets", "--version"]),
        ("safety", ["safety", "--version"]),
        ("schemathesis", ["schemathesis", "--version"]),
    ]
    out: dict[str, str | None] = {}
    for name, cmd in tools:
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=12,
                errors="ignore",
            )
            line = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
            out[name] = line[0][:200] if line else None
        except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
            out[name] = None
    return out


def redact_argv_for_manifest(argv: list[str]) -> list[str]:
    hide_next = False
    redacted: list[str] = []
    sensitive_flags = {"--auth-config", "--chain-config", "--notify-webhook"}
    for a in argv:
        if hide_next:
            redacted.append("[REDACTED]")
            hide_next = False
            continue
        if a in sensitive_flags:
            redacted.append(a)
            hide_next = True
            continue
        if a.startswith("--notify-webhook="):
            redacted.append("--notify-webhook=[REDACTED]")
            continue
        redacted.append(a)
    return redacted


def sha256_file_bytes(path: Path) -> str | None:
    """SHA-256 of file bytes for config replay; None if missing or unreadable."""
    try:
        if not path.is_file():
            return None
        h = hashlib.sha256()
        h.update(path.read_bytes())
        return h.hexdigest()
    except OSError:
        return None


def build_replay_bundle(
    scan_path: str,
    args: argparse.Namespace,
    *,
    workspace: Path | None,
    run_id: str | None,
    git_info: dict | None = None,
) -> dict[str, object]:
    """
    Structured reproducibility metadata: pinned tool versions, config hash, environment,
    supply-chain manifest hashes, workspace layout. See CORRELATION_JOIN_RULES.md,
    WORKSPACE_CONTRACT.md, REPRODUCIBILITY.md.
    """
    gi = git_info if git_info is not None else _git_probe(scan_path)
    cfg = getattr(args, "config", None)
    discovered = discover_config_file(cfg)
    cfg_resolved = str(discovered.resolve()) if discovered else None
    cfg_hash = sha256_file_bytes(discovered) if discovered else None
    ws = str(workspace.resolve()) if workspace else None
    ck = None
    if workspace is not None and run_id:
        ck = str((workspace / run_id / "checkpoint.json").resolve())
    include_pf = bool(getattr(args, "replay_include_pip_freeze", False))
    bundle: dict[str, object] = {
        "spec_version": 2,
        "join_rules_version": CORRELATION_JOIN_RULES_VERSION,
        "join_rules_doc": "CORRELATION_JOIN_RULES.md",
        "workspace_contract_doc": "WORKSPACE_CONTRACT.md",
        "config_path_effective": cfg_resolved,
        "config_sha256": cfg_hash,
        "scan_path_resolved": str(Path(scan_path).resolve()),
        "scan_path_git_relative": scan_path_relative_to_git(scan_path, gi),
        "environment": runtime_environment(),
        "supply_chain": supply_chain_file_hashes(scan_path),
        "determinism_note": replay_non_determinism_note(),
        "tool_versions": snapshot_tool_versions(),
        "workspace": {
            "root": ws,
            "run_id": run_id,
            "checkpoint_json": ck,
        },
    }
    if include_pf:
        bundle["pip_freeze_sha256"] = pip_freeze_sha256()
    return bundle


def build_run_manifest(
    scan_path: str,
    args: argparse.Namespace,
    *,
    workspace: Path | None = None,
    run_id: str | None = None,
) -> dict:
    cfg = getattr(args, "config", None)
    lf = getattr(args, "log_file", None)
    git = _git_probe(scan_path)
    return {
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "report_schema_compat_version": REPORT_SCHEMA_COMPAT_VERSION,
        "argv_redacted": redact_argv_for_manifest(sys.argv[1:]),
        "scan_path": scan_path,
        "tool_versions": snapshot_tool_versions(),
        "git": git,
        "python_version": sys.version.split()[0],
        "config_file": str(Path(cfg).resolve()) if cfg else None,
        "replay_bundle": build_replay_bundle(
            scan_path, args, workspace=workspace, run_id=run_id, git_info=git
        ),
        "ci_profile": bool(getattr(args, "ci_profile", False)),
        "sarif_source": getattr(args, "sarif_source", "tool_native"),
        "network_mode": getattr(args, "network_mode", "default") or "default",
        "path_scope": {
            "include_globs": list(getattr(args, "include_globs", None) or []),
            "exclude_globs": list(getattr(args, "exclude_globs", None) or []),
        },
        "redaction_ruleset_version": REDACTION_RULESET_VERSION,
        "logging": {
            "verbose": bool(getattr(args, "verbose", False)),
            "log_json": bool(getattr(args, "log_json", False)),
            "log_file": str(Path(lf).resolve()) if lf else None,
        },
    }
