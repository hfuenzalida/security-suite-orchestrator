"""Phase 2 — Authenticated session (config + shared cookies)."""
from secscan.http_session import USER_AGENTS, hosts_from_url, merge_req_headers
from secscan.phases._imports import *  # noqa: F403

from secscan.temp_registry import register_temp_path

# ── Phase 2 — Authenticated session (config file + shared cookies) ────────────


def _auth_form_post_login(cfg: dict) -> tuple[dict[str, str], str | None]:
    """Traditional form POST with cookie jar (no JavaScript)."""
    login_url = cfg["login_url"]
    ufield = cfg.get("username_field", "username")
    pfield = cfg.get("password_field", "password")
    data: dict[str, str] = {
        ufield: cfg["username"],
        pfield: cfg["password"],
    }
    if cfg.get("totp_secret"):
        try:
            import pyotp
            tfield = cfg.get("totp_field", "otp")
            data[tfield] = pyotp.TOTP(cfg["totp_secret"]).now()
        except ImportError:
            warn("pyotp not installed — pip install pyotp — skipping TOTP field")
        except Exception as e:
            return {}, f"TOTP error: {e}"

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    req = urllib.request.Request(
        login_url,
        data=urllib.parse.urlencode(data).encode(),
        method="POST",
        headers=merge_req_headers(
            {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            url=login_url,
        ),
    )
    try:
        resp = opener.open(req, timeout=45)
        resp.read()
    except Exception as e:
        return {}, str(e)

    cookies: dict[str, str] = {}
    for c in cj:
        cookies[c.name] = c.value
    return cookies, None


def _auth_playwright_login(cfg: dict) -> tuple[dict[str, str], str | None, str | None]:
    """Login via headless Chromium; returns cookies dict, storage_state path, optional warning."""
    import asyncio
    import tempfile as _tf

    async def _go() -> tuple[dict[str, str], str | None, str | None]:
        from playwright.async_api import async_playwright

        login_url = cfg["login_url"]
        success = (cfg.get("success_url_contains") or "").strip()
        u_sel = cfg.get(
            "username_selector",
            'input[type="email"], input[name="email"], input[name="username"], #username, #email',
        )
        p_sel = cfg.get("password_selector", 'input[type="password"]')
        totp_sel = cfg.get(
            "totp_selector",
            'input[name="otp"], input[name="totp"], input[name="code"], input[autocomplete="one-time-code"]',
        )
        sub_sel = cfg.get("submit_selector", 'button[type="submit"], input[type="submit"]')

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context(user_agent=random.choice(USER_AGENTS))
                page = await context.new_page()
                await page.goto(login_url, wait_until="domcontentloaded", timeout=60_000)
                await page.locator(u_sel).first.fill(cfg["username"], timeout=20_000)
                await page.locator(p_sel).first.fill(cfg["password"], timeout=20_000)
                if cfg.get("totp_secret"):
                    try:
                        import pyotp
                        code = pyotp.TOTP(cfg["totp_secret"]).now()
                        await page.locator(totp_sel).first.fill(code, timeout=15_000)
                    except ImportError:
                        raise ImportError("pyotp required for TOTP — pip install pyotp") from None
                    except Exception as e:
                        return {}, None, f"TOTP fill failed: {e}"

                await page.locator(sub_sel).first.click(timeout=15_000)
                await page.wait_for_load_state("networkidle", timeout=60_000)

                warn_url = None
                if success and success not in page.url:
                    warn_url = f"URL does not contain {success!r} (current: {page.url})"

                cookies_list = await context.cookies()
                cdict = {c["name"]: c["value"] for c in cookies_list}

                fd, path = _tf.mkstemp(prefix="auth_state_", suffix=".json")
                os.close(fd)
                register_temp_path(path)
                await context.storage_state(path=path)
                return cdict, path, warn_url
            finally:
                await browser.close()

    return asyncio.run(_go())


def phase_auth_session(_base_url: str, cfg: dict) -> dict:
    """
    Establish a shared session: cookies + optional Playwright storage for Phase 4b.
    Sets global auth for _get/_post and nuclei. Config: login_url, username, password;
    optional method 'playwright' | 'form_post', selectors, totp_secret, headers, success_url_contains.
    """
    header("Phase 2 — Authenticated Session")
    auth_clear()

    method = (cfg.get("method") or "playwright").lower().strip()
    cookies: dict[str, str] = {}
    storage_path: str | None = None
    warning: str | None = None
    err: str | None = None

    try:
        if method == "form_post":
            cookies, err = _auth_form_post_login(cfg)
            if err:
                fail(f"Auth — form POST failed: {err}")
                return {
                    "status": "error", "count": 0, "error": err,
                    "cookies": {}, "storage_state": None,
                }
            if not cookies:
                fail("Auth — form POST returned no cookies (check credentials or field names)")
                return {
                    "status": "error", "count": 0, "error": "no cookies from server",
                    "cookies": {}, "storage_state": None,
                }
        else:
            cookies, storage_path, warning = _auth_playwright_login(cfg)
            if warning:
                warn(f"Auth — {warning}")
    except ImportError as e:
        warn(f"Auth — {e}")
        return {"status": "error", "count": 0, "error": str(e), "cookies": {}, "storage_state": None}
    except Exception as e:
        fail(f"Auth — {e}")
        return {"status": "error", "count": 0, "error": str(e), "cookies": {}, "storage_state": None}

    extra_h = cfg.get("headers")
    allowed: list[str] = []
    login_url = str(cfg.get("login_url") or "")
    allowed.extend(hosts_from_url(login_url))
    if _base_url:
        allowed.extend(hosts_from_url(_base_url))
    cfg_hosts = cfg.get("allowed_hosts") or cfg.get("cookie_hosts")
    if isinstance(cfg_hosts, list):
        allowed.extend(str(h) for h in cfg_hosts if h)
    # de-dupe preserve order
    seen: set[str] = set()
    allowed_hosts = []
    for h in allowed:
        key = h.lower()
        if key and key not in seen:
            seen.add(key)
            allowed_hosts.append(h)

    if isinstance(extra_h, dict):
        auth_apply(cookies if cookies else None, extra_h, allowed_hosts=allowed_hosts)
    else:
        auth_apply(cookies if cookies else None, None, allowed_hosts=allowed_hosts)

    has_cookies = bool(cookies)
    if not storage_path and not has_cookies:
        warn("Auth — no cookies and no storage state")
        return {
            "status": "failed",
            "count": 0,
            "cookies": {},
            "headers": {},
            "storage_state": None,
            "allowed_hosts": allowed_hosts,
            "error": "no session data",
        }

    if has_cookies:
        ok(
            f"Auth — {len(cookies)} cookie(s); scoped to host(s): "
            f"{', '.join(allowed_hosts) or '(none — credentials will not be sent)'}"
        )
    elif storage_path:
        ok("Auth — Playwright storage state saved for browser phase")

    # Persist only non-secret metadata; live cookies/headers stay in process memory.
    return {
        "status": "success",
        "cookies": {},
        "cookie_names": sorted(cookies.keys()),
        "storage_state": storage_path,
        "headers": {},
        "header_names": sorted(extra_h.keys()) if isinstance(extra_h, dict) else [],
        "allowed_hosts": allowed_hosts,
        "count": len(cookies),
        "warning": warning,
    }

