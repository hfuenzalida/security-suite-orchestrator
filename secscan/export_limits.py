"""Length limits for human-readable exports (HTML/PDF) — not applied to in-memory JSON."""

from secscan.redaction import redact_sensitive_text

MAX_HTML_EVIDENCE_CHARS = 2000
MAX_HTML_LOCATION_CHARS = 600
MAX_HTML_TYPE_CHARS = 240
MAX_PDF_EVIDENCE_CHARS = 320
MAX_PDF_TYPE_CHARS = 90
MAX_PDF_LOCATION_CHARS = 150


def clip_redacted_text(s: str, max_len: int) -> str:
    """Pattern-redact then cap length for HTML/PDF surfaces."""
    t = redact_sensitive_text(str(s))
    if len(t) > max_len:
        return t[:max_len] + "… [truncated for export]"
    return t
