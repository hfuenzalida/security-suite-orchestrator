"""
Reproducibility helpers: runtime fingerprint, dependency file hashes, git-relative paths, optional pip freeze.

Used by `run_manifest.replay_bundle` (see CORRELATION_JOIN_RULES.md, REPRODUCIBILITY.md).
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

# Well-known dependency manifests at repo root (scan path). Keys are stable JSON field names.
DEPENDENCY_MANIFEST_FILES: tuple[tuple[str, str], ...] = (
    ("requirements_txt", "requirements.txt"),
    ("requirements_dev_txt", "requirements-dev.txt"),
    ("pyproject_toml", "pyproject.toml"),
    ("pipfile_lock", "Pipfile.lock"),
    ("poetry_lock", "poetry.lock"),
)


def _sha256_file(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        h = hashlib.sha256()
        h.update(path.read_bytes())
        return h.hexdigest()
    except OSError:
        return None


def runtime_environment() -> dict[str, Any]:
    """Non-secret runtime facts for comparing runs across machines."""
    return {
        "platform": sys.platform,
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "python_version": sys.version.split()[0],
        "python_full": sys.version.replace("\n", " ")[:500],
        "python_implementation": platform.python_implementation(),
    }


def supply_chain_file_hashes(scan_path: str) -> dict[str, Any]:
    """
    SHA-256 of common lock/manifest files under the scan directory (if present).
    Does not include arbitrary paths — only DEPENDENCY_MANIFEST_FILES.
    """
    base = Path(scan_path).resolve()
    files: dict[str, str | None] = {}
    for key, name in DEPENDENCY_MANIFEST_FILES:
        files[key] = _sha256_file(base / name)
    present = {k: v for k, v in files.items() if v}
    return {"files": files, "files_present_count": len(present)}


def scan_path_relative_to_git(scan_path: str, git: dict[str, Any]) -> str | None:
    """
    If scan_path lies under git_root, return a POSIX relative path for stable correlation diffs.
    Does not change correlation_id generation — advisory for humans and replay tooling.
    """
    root = git.get("git_root")
    if not root or not isinstance(root, str):
        return None
    try:
        sp = Path(scan_path).resolve()
        gr = Path(root).resolve()
        rel = sp.relative_to(gr)
        return rel.as_posix()
    except ValueError:
        return None


def pip_freeze_sha256(*, timeout: float = 60.0) -> str | None:
    """
    SHA-256 of `pip freeze` stdout for the current interpreter environment.
    Optional — can be slow; use only when you need a full env pin (see --replay-include-pip-freeze).
    """
    try:
        p = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        if p.returncode != 0:
            return None
        body = (p.stdout or "").encode("utf-8")
        return hashlib.sha256(body).hexdigest()
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


def replay_non_determinism_note() -> str:
    return (
        "Third-party tools, network, targets, and timing are not fully deterministic; "
        "use replay_bundle + git commit + supply_chain + tool_versions to explain diffs."
    )
