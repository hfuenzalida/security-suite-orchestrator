"""Best-effort secret stripping for logs and export artifacts."""

from __future__ import annotations

import re

_REDACT_PATTERNS = (
    (re.compile(r"(?i)bearer\s+\S{8,}"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization)\s*:\s*\S+"), "[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*=\s*\S+"), "[REDACTED]"),
    (re.compile(r"(AKIA[0-9A-Z]{16})"), "AKIA[REDACTED]"),
    (re.compile(r"(sk-[a-zA-Z0-9]{10,})"), "sk-[REDACTED]"),
    # JWT (three base64url segments)
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"), "[JWT_REDACTED]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "ghp_[REDACTED]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github_pat_[REDACTED]"),
    # PEM blocks (never embed in exports)
    (re.compile(r"-----BEGIN [A-Z ]+-----[\s\S]{20,}?-----END [A-Z ]+-----"), "[PEM_REDACTED]"),
    # Long hex blobs (likely keys / hashes in tool output) — 64+ chars to avoid git SHAs
    (re.compile(r"\b[0-9a-f]{64,}\b", re.I), "[HEX_REDACTED]"),
    # Base64 with padding only (reduces false positives in code)
    (re.compile(r"\b[A-Za-z0-9+/]{80,}={1,2}\b"), "[B64_REDACTED]"),
)


def redact_sensitive_text(text: str) -> str:
    if not text:
        return text
    out = text
    for rx, repl in _REDACT_PATTERNS:
        out = rx.sub(repl, out)
    return out


def redact_sensitive_obj(obj: object) -> object:
    """Deep-walk JSON-like structures and redact string values."""
    if isinstance(obj, str):
        return redact_sensitive_text(obj)
    if isinstance(obj, dict):
        return {k: redact_sensitive_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_sensitive_obj(x) for x in obj]
    return obj
