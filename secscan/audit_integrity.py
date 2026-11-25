"""Optional audit JSONL append and HMAC sidecar for report integrity (compliance hooks)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def append_audit_jsonl(log_path: Path, event: dict[str, Any]) -> None:
    """Append one JSON object per line (common SIEM / pipeline ingest)."""
    ev = dict(event)
    ev.setdefault("ts", datetime.now(timezone.utc).isoformat())
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(ev, default=str) + "\n")


def load_hmac_key_from_env_or_file(key_file: str | None) -> bytes | None:
    p = os.environ.get("SECURITY_SCAN_REPORT_HMAC_KEY")
    if p:
        return p.encode("utf-8")
    if key_file:
        kp = Path(key_file).expanduser()
        if kp.is_file():
            return kp.read_bytes().strip()
    return None


def write_hmac_sidecar(report_path: Path, key: bytes) -> Path:
    """Write report.json.hmac next to report with hex HMAC-SHA256 of file bytes."""
    data = report_path.read_bytes()
    digest = hmac.new(key, data, hashlib.sha256).hexdigest()
    sidecar = report_path.with_name(report_path.name + ".hmac")
    sidecar.write_text(digest + "\n", encoding="utf-8")
    return sidecar
