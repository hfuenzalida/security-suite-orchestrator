"""Deep redaction for report artifacts (JSON/HTML) when sharing outside trusted zones."""

from __future__ import annotations

import copy
from typing import Any

# Cap huge tool stdout/stderr blobs in shared JSON (full report in memory may still be large).
_DEFAULT_MAX_STR = 4000


def _truncate_strings(obj: object, max_len: int) -> object:
    if isinstance(obj, str):
        if len(obj) > max_len:
            return obj[:max_len] + "...[truncated]"
        return obj
    if isinstance(obj, dict):
        return {k: _truncate_strings(v, max_len) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_truncate_strings(x, max_len) for x in obj]
    return obj


def sanitize_report_copy(
    report: dict[str, Any],
    *,
    max_string_len: int = _DEFAULT_MAX_STR,
) -> dict[str, Any]:
    """
    Deep copy: pattern redaction, then cap string length so raw tool blobs
    are less likely to leak secrets at length when exported.
    """
    from secscan.redaction import redact_sensitive_obj

    redacted = redact_sensitive_obj(copy.deepcopy(report))
    return _truncate_strings(redacted, max_string_len)
