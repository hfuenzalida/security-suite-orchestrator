"""Checkpoint persistence for resume support."""

from __future__ import annotations

import hashlib
import json
import re as _re
import urllib.parse
from pathlib import Path

from secscan.http_session import auth_apply
from secscan.session_sanitize import strip_session_secrets

CHECKPOINT_VERSION = 1
DEFAULT_WORKSPACE_DIR = "scan_workspace"

# Opaque run ids only: no path separators, no absolute/drive forms, no traversal.
_RUN_ID_RE = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")


def default_run_id(scan_path: str, url: str | None) -> str:
    short = hashlib.sha256(scan_path.encode()).hexdigest()[:10]
    if url:
        host = urllib.parse.urlparse(url).hostname or "nohost"
        safe = _re.sub(r"[^\w.-]+", "_", host)[:60]
        return f"{safe}_{short}"
    return f"local_{short}"


def validate_run_id(run_id: str) -> str:
    """Reject path-like or empty run identifiers."""
    if not isinstance(run_id, str):
        raise ValueError("run_id must be a string")
    rid = run_id.strip()
    if not rid or rid in (".", ".."):
        raise ValueError("invalid run_id")
    if "/" in rid or "\\" in rid or ":" in rid:
        raise ValueError(f"run_id must be opaque (no path separators): {run_id!r}")
    if ".." in rid:
        raise ValueError(f"run_id must not contain '..': {run_id!r}")
    if not _RUN_ID_RE.fullmatch(rid):
        raise ValueError(f"invalid run_id characters: {run_id!r}")
    return rid


def resolve_run_dir(workspace: Path, run_id: str) -> Path:
    """Return workspace/run_id only when the resolved path stays under workspace."""
    rid = validate_run_id(run_id)
    ws = workspace.resolve()
    run_dir = (ws / rid).resolve()
    try:
        run_dir.relative_to(ws)
    except ValueError as e:
        raise ValueError(f"run directory escapes workspace: {run_id!r}") from e
    return run_dir


def checkpoint_path(workspace: Path, run_id: str) -> Path:
    return resolve_run_dir(workspace, run_id) / "checkpoint.json"


def checkpoint_write(workspace: Path, run_id: str, meta: dict) -> Path:
    d = resolve_run_dir(workspace, run_id)
    d.mkdir(parents=True, exist_ok=True)
    p = checkpoint_path(workspace, run_id)
    safe_meta = strip_session_secrets(meta) if isinstance(meta, dict) else meta
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(safe_meta, indent=2, default=str), encoding="utf-8")
    tmp.replace(p)
    return p


def checkpoint_read(path: Path) -> dict:
    """Load checkpoint JSON; raises ``ValueError`` if corrupt or not an object."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"Cannot read checkpoint {path}: {e}") from e
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Checkpoint is not valid JSON ({path}): {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"Checkpoint root must be a JSON object ({path})")
    return data


def validate_resume(
    ck: dict,
    scan_path: str,
    url: str | None,
    auth_config: str | None,
    chain_config: str | None,
) -> str | None:
    if ck.get("scan_path") != scan_path:
        return f"scan_path mismatch (checkpoint {ck.get('scan_path')!r} vs {scan_path!r})"
    if ck.get("target_url") != url:
        return f"target_url mismatch (checkpoint {ck.get('target_url')!r} vs {url!r})"
    if ck.get("auth_config") != auth_config:
        return "auth_config path mismatch vs checkpoint"
    if ck.get("chain_config") != chain_config:
        return "chain_config path mismatch vs checkpoint"
    return None


def restore_session_from_phases(phases: dict) -> None:
    """
    Legacy no-op for credential restore.

    Checkpoints no longer persist live cookies/headers. Resume re-runs auth/chain
    when session material is required (see security_scan resume handling).
    """
    sess = phases.get("auth", {}).get("session", {})
    if not isinstance(sess, dict):
        return
    c = sess.get("cookies")
    h = sess.get("headers")
    # Only restore if a legacy checkpoint still carries values (pre-hardening).
    if isinstance(c, dict) and c:
        hosts = sess.get("allowed_hosts")
        host_list = [str(x) for x in hosts] if isinstance(hosts, list) else None
        auth_apply(c, h if isinstance(h, dict) else None, allowed_hosts=host_list)
