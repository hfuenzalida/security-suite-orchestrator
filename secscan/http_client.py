"""Minimal urllib GET/POST with session headers from http_session."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from secscan.http_session import merge_req_headers, stealth_jitter


def http_get(url: str, timeout: int = 10, stealth: bool = False) -> tuple[int, str, dict]:
    if stealth:
        stealth_jitter()
    try:
        req = urllib.request.Request(url, headers=merge_req_headers(url=url))
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore"), {}
    except Exception:
        return -1, "", {}


def http_post(url: str, data: dict, timeout: int = 10, stealth: bool = False) -> tuple[int, str]:
    if stealth:
        stealth_jitter()
    try:
        encoded = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            url,
            data=encoded,
            headers=merge_req_headers(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                url=url,
            ),
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore")
    except Exception:
        return -1, ""
