"""Optional Phase-2 session cookies/headers for urllib-based probes and nuclei."""

from __future__ import annotations

import random
import time
import urllib.parse
from typing import Dict, Iterable, Optional, Set

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# Playwright / legacy phase code uses random.choice(USER_AGENTS)
USER_AGENTS = _USER_AGENTS

_HTTP_AUTH_COOKIES: Optional[Dict[str, str]] = None
_HTTP_AUTH_HEADERS: Optional[Dict[str, str]] = None
_HTTP_AUTH_ALLOWED_HOSTS: Optional[Set[str]] = None


def stealth_jitter(min_sec: float = 0.3, max_sec: float = 1.2) -> None:
    time.sleep(random.uniform(min_sec, max_sec))


def auth_clear() -> None:
    global _HTTP_AUTH_COOKIES, _HTTP_AUTH_HEADERS, _HTTP_AUTH_ALLOWED_HOSTS
    _HTTP_AUTH_COOKIES = None
    _HTTP_AUTH_HEADERS = None
    _HTTP_AUTH_ALLOWED_HOSTS = None


def _normalize_host(host: str) -> str:
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        return h
    # Drop port if present (hostname:port)
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h


def hosts_from_url(url: str) -> list[str]:
    host = urllib.parse.urlparse(url).hostname
    if not host:
        return []
    return [_normalize_host(host)]


def auth_apply(
    cookies: Optional[Dict[str, str]],
    headers: Optional[Dict[str, str]] = None,
    *,
    allowed_hosts: Optional[Iterable[str]] = None,
) -> None:
    """
    Install session cookies/headers for later HTTP probes.

    ``allowed_hosts`` restricts where credentials are attached. When credentials
    are present and no hosts are provided, credentials are stored but never sent
    (fail closed) until hosts are set.
    """
    global _HTTP_AUTH_COOKIES, _HTTP_AUTH_HEADERS, _HTTP_AUTH_ALLOWED_HOSTS
    _HTTP_AUTH_COOKIES = dict(cookies) if cookies else None
    _HTTP_AUTH_HEADERS = dict(headers) if headers else None
    if allowed_hosts is None:
        _HTTP_AUTH_ALLOWED_HOSTS = set() if (_HTTP_AUTH_COOKIES or _HTTP_AUTH_HEADERS) else None
    else:
        _HTTP_AUTH_ALLOWED_HOSTS = {_normalize_host(h) for h in allowed_hosts if h}


def get_allowed_hosts() -> Optional[Set[str]]:
    if _HTTP_AUTH_ALLOWED_HOSTS is None:
        return None
    return set(_HTTP_AUTH_ALLOWED_HOSTS)


def host_in_session_scope(url: str) -> bool:
    """True when URL host is on the session allowlist (or no credentials are set)."""
    if not (_HTTP_AUTH_COOKIES or _HTTP_AUTH_HEADERS):
        return True
    if not _HTTP_AUTH_ALLOWED_HOSTS:
        return False
    host = urllib.parse.urlparse(url).hostname
    if not host:
        return False
    return _normalize_host(host) in _HTTP_AUTH_ALLOWED_HOSTS


def cookie_header(cookies: Dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def cookie_header_for_url(url: str) -> str:
    """Cookie header for ``url`` only when the host is in session scope."""
    if not _HTTP_AUTH_COOKIES or not host_in_session_scope(url):
        return ""
    return cookie_header(_HTTP_AUTH_COOKIES)


def get_session_cookies() -> Optional[Dict[str, str]]:
    return _HTTP_AUTH_COOKIES


def get_session_headers() -> Optional[Dict[str, str]]:
    return _HTTP_AUTH_HEADERS


def has_session_credentials() -> bool:
    return bool(_HTTP_AUTH_COOKIES or _HTTP_AUTH_HEADERS)


def merge_req_headers(
    extra: Optional[Dict[str, str]] = None,
    *,
    url: Optional[str] = None,
) -> Dict[str, str]:
    """
    Build request headers. Session cookies/auth headers are attached only when
    ``url`` is provided and its host is on the allowlist.
    """
    h: Dict[str, str] = {"User-Agent": random.choice(_USER_AGENTS)}
    scoped = bool(url) and host_in_session_scope(url)
    if scoped and _HTTP_AUTH_COOKIES:
        h["Cookie"] = cookie_header(_HTTP_AUTH_COOKIES)
    if scoped and _HTTP_AUTH_HEADERS:
        for k, v in _HTTP_AUTH_HEADERS.items():
            if k.lower() != "cookie":
                h[k] = v
    if extra:
        h.update(extra)
    return h
