"""Phase 3 — Multi-step request chain (CSRF, session handoff)."""
import re

from secscan.http_session import (
    USER_AGENTS,
    cookie_header,
    get_allowed_hosts,
    host_in_session_scope,
    hosts_from_url,
)
from secscan.phases._imports import *  # noqa: F403, E402

# ── Phase 3 — Multi-step request chain (CSRF, session handoff) ─────────────────
# ``from _imports import *`` does not import leading-underscore aliases (e.g. USER_AGENTS as _USER_AGENTS).


def _parse_step_timeout(step: dict, default: int = 45) -> int:
    """Parse step timeout; invalid values fall back to default (clamped 1..600 s)."""
    raw = step.get("timeout", default)
    if raw is None or raw is False or raw == "":
        return default
    if isinstance(raw, bool):
        return default
    try:
        t = int(raw)
    except (TypeError, ValueError):
        warn(f"Chain — invalid timeout {raw!r}; using {default}s")
        return default
    return max(1, min(t, 600))


def _substitute_chain_vars(template: str, ctx: dict[str, str]) -> str:
    """Replace {{var}} placeholders using context + captured variables."""

    def repl(m: re.Match[str]) -> str:
        key = m.group(1).strip()
        if key in ctx:
            return str(ctx[key])
        return m.group(0)

    return re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", repl, template)


def format_capture_log(var: str, value: str) -> str:
    """
    Format a capture log line.

    By default only the variable name and length are logged. Set
    ``SECSCAN_UNSAFE_CHAIN_DEBUG=1`` to include the captured value (CI logs).
    """
    import os

    unsafe = os.environ.get("SECSCAN_UNSAFE_CHAIN_DEBUG", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if unsafe:
        clip = value[:72] + ("..." if len(value) > 72 else "")
        return f"Chain — captured {var} ← {clip}"
    return f"Chain — captured {var} (len={len(value)})"


def _chain_merge_set_cookie(cookies: dict[str, str], headers_obj: object) -> None:
    """Parse Set-Cookie headers into a flat name->value map (first segment only)."""
    raw_list: list[str] = []
    if headers_obj is not None and hasattr(headers_obj, "get_all"):
        raw = headers_obj.get_all("Set-Cookie") or []
        raw_list = list(raw) if isinstance(raw, (list, tuple)) else []
    for line in raw_list:
        part = line.split(";")[0].strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()


def phase_request_chain(base_url: str, cfg: dict) -> dict:
    """
    Execute ordered HTTP steps with {{variable}} substitution and regex captures.
    Updates global session cookies for later phases (merged with Phase 2 headers if any).
    """
    header("Phase 3 — Request Chain")

    steps = cfg.get("steps")
    if not isinstance(steps, list) or not steps:
        warn("Chain — no 'steps' array in config")
        return {"status": "skipped", "count": 0, "error": "no steps"}

    ctx: dict[str, str] = {}
    for k, v in (cfg.get("context") or {}).items():
        ctx[k] = str(v)

    parsed = urllib.parse.urlparse(base_url)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or "localhost"
    origin = f"{scheme}://{netloc}"
    ctx["base"] = origin.rstrip("/")
    ctx["origin"] = origin

    cookies: dict[str, str] = {}
    if cfg.get("seed_from_auth"):
        _sc = get_session_cookies()
        if _sc:
            cookies.update(_sc)
            info("Chain — seeding Cookie jar from Phase 2 session")
        else:
            warn("Chain — seed_from_auth set but no Phase 2 cookies (optional)")

    captured: dict[str, str] = {}
    step_logs: list[dict] = []

    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        sid = step.get("id", f"step_{i + 1}")
        method = (step.get("method") or "GET").upper()

        url_t = (step.get("url") or "").strip()
        if not url_t and step.get("path"):
            url_t = ctx["base"].rstrip("/") + "/" + str(step.get("path")).lstrip("/")
        if not url_t:
            fail(f"Chain — step {sid}: missing url or path")
            return {"status": "error", "count": i, "steps": step_logs, "error": "missing url"}

        merge = {**ctx, **captured}
        url_final = _substitute_chain_vars(url_t, merge)

        body: bytes | None = None
        ctype = step.get("content_type") or "application/x-www-form-urlencoded"
        if "json" in step:
            raw_j = json.dumps(step["json"])
            body = _substitute_chain_vars(raw_j, merge).encode("utf-8")
            ctype = "application/json"
        elif "body" in step:
            b = step["body"]
            if isinstance(b, dict):
                b2 = {k: _substitute_chain_vars(str(v), merge) for k, v in b.items()}
                body = urllib.parse.urlencode(b2).encode("utf-8")
            else:
                body = _substitute_chain_vars(str(b), merge).encode("utf-8")

        hdrs: dict[str, str] = {"User-Agent": random.choice(USER_AGENTS)}
        # Never replay seeded/auth cookies to hosts outside the session allowlist.
        if cookies and host_in_session_scope(url_final):
            hdrs["Cookie"] = cookie_header(cookies)
        elif cookies and has_session_credentials() and not host_in_session_scope(url_final):
            warn(f"Chain — step {sid}: omitting cookies for out-of-scope host")
        elif cookies and not has_session_credentials():
            # Chain-local jar (no Phase-2 session): keep legacy same-run jar behavior.
            hdrs["Cookie"] = cookie_header(cookies)
        allow_step_auth = host_in_session_scope(url_final) or not has_session_credentials()
        for hk, hv in (step.get("headers") or {}).items():
            if not allow_step_auth and hk.lower() in ("authorization", "cookie", "proxy-authorization"):
                warn(f"Chain — step {sid}: omitting auth header {hk!r} for out-of-scope host")
                continue
            hdrs[hk] = _substitute_chain_vars(str(hv), merge)
        if body is not None:
            hdrs["Content-Type"] = ctype

        timeout = _parse_step_timeout(step, 45)
        req = urllib.request.Request(url_final, data=body, method=method, headers=hdrs)

        resp_headers_dict: dict[str, str] = {}
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                text = resp.read().decode(errors="ignore")
                if host_in_session_scope(url_final) or not has_session_credentials():
                    _chain_merge_set_cookie(cookies, resp.headers)
                resp_headers_dict = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            status = e.code
            text = e.read().decode(errors="ignore")
            if host_in_session_scope(url_final) or not has_session_credentials():
                _chain_merge_set_cookie(cookies, e.headers)
            resp_headers_dict = {k.lower(): v for k, v in e.headers.items()}
        except Exception as ex:
            fail(f"Chain — step {sid}: {ex}")
            return {"status": "error", "count": i, "steps": step_logs, "error": str(ex)}

        expect = step.get("expect_status")
        if expect is None:
            ok_status = 200 <= status < 500
        else:
            exp_list = expect if isinstance(expect, list) else [expect]
            ok_status = status in exp_list
        if not ok_status and step.get("fail_on_status", True):
            fail(f"Chain — step {sid}: HTTP {status}")
            step_logs.append({"id": sid, "url": url_final, "status": status, "ok": False})
            return {"status": "error", "count": i + 1, "steps": step_logs, "error": f"HTTP {status}"}

        for cap in step.get("capture") or []:
            if not isinstance(cap, dict):
                continue
            var = cap.get("var")
            regex = cap.get("regex")
            if not var or not regex:
                continue
            src = (cap.get("from") or "body").lower()
            if src == "body":
                hay = text
            elif src == "headers":
                hay = "\n".join(f"{k}: {v}" for k, v in resp_headers_dict.items())
            else:
                hay = (
                    resp_headers_dict.get(src.lower())
                    or resp_headers_dict.get(src.replace("-", "_").lower())
                    or ""
                )
            try:
                m = re.search(regex, hay, re.DOTALL | re.IGNORECASE)
            except re.error as rex:
                warn(f"Chain — step {sid}: invalid capture regex for {var!r}: {rex}")
                continue
            if m:
                captured[var] = m.group(1) if m.lastindex else m.group(0)
                info(format_capture_log(var, captured[var]))

        step_logs.append({"id": sid, "url": url_final, "status": status, "ok": True})

    _sh = get_session_headers()
    hdr_keep = dict(_sh) if _sh else None
    hosts = get_allowed_hosts()
    end_hosts = sorted(hosts) if hosts is not None else hosts_from_url(base_url)
    auth_apply(cookies, hdr_keep, allowed_hosts=end_hosts)
    ok(f"Chain — completed {len(step_logs)} step(s); session cookies updated")

    return {
        "status": "success",
        "count": len(step_logs),
        "steps": step_logs,
        "captured": {},
        "captured_vars": sorted(captured.keys()),
        "cookies_applied": len(cookies),
    }

