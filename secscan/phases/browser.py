"""Phase 4b — Browser automation (Playwright)."""
from secscan.http_session import USER_AGENTS
from secscan.phases._imports import *  # noqa: F403

from secscan.temp_registry import register_temp_path

# ── Browser Automation ─────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "content-security-policy":     "CSP — prevents XSS and data injection",
    "strict-transport-security":   "HSTS — enforces HTTPS",
    "x-frame-options":             "Clickjacking protection",
    "x-content-type-options":      "MIME sniffing protection",
    "referrer-policy":             "Controls referrer information leakage",
    "permissions-policy":          "Controls browser feature access",
    "cross-origin-opener-policy":  "Cross-origin isolation",
    "cross-origin-resource-policy":"Cross-origin resource sharing control",
}


def _run_browser_phase(
    url: str,
    screenshot_path: str,
    storage_state: str | None = None,
) -> dict:
    """Inner async logic — imported lazily so missing playwright doesn't crash."""
    import asyncio
    from playwright.async_api import async_playwright

    async def _run() -> dict:
        result: dict = {
            "security_headers": {"missing": [], "present": []},
            "cookies": {"findings": [], "count": 0},
            "attack_surface": {"forms": [], "api_endpoints": [], "input_count": 0},
            "xss_probes": {"findings": [], "count": 0},
            "tech_hints": [],
            "screenshot": None,
        }

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                ctx_kw: dict = {"user_agent": random.choice(USER_AGENTS)}
                if storage_state and Path(storage_state).is_file():
                    ctx_kw["storage_state"] = storage_state
                context = await browser.new_context(**ctx_kw)

                # ── Capture XHR / fetch requests for API discovery ────────────
                api_endpoints: list[str] = []

                def on_request(req):
                    rt = req.resource_type
                    if rt in ("xhr", "fetch") and req.url not in api_endpoints:
                        api_endpoints.append(req.url)

                page = await context.new_page()
                page.on("request", on_request)

                try:
                    response = await page.goto(url, wait_until="networkidle", timeout=30_000)
                except Exception as e:
                    return {"error": str(e)}

                # ── Security headers ──────────────────────────────────────────
                if response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    for hdr, description in SECURITY_HEADERS.items():
                        if hdr in headers:
                            result["security_headers"]["present"].append(hdr)
                        else:
                            result["security_headers"]["missing"].append(
                                {"header": hdr, "description": description}
                            )
                    server = headers.get("server", "")
                    powered_by = headers.get("x-powered-by", "")
                    if server:
                        result["tech_hints"].append(f"Server: {server}")
                    if powered_by:
                        result["tech_hints"].append(f"X-Powered-By: {powered_by}")

                # ── Cookie audit ──────────────────────────────────────────────
                cookies = await context.cookies()
                cookie_findings = []
                for c in cookies:
                    issues = []
                    if not c.get("httpOnly"):
                        issues.append("missing HttpOnly")
                    if not c.get("secure"):
                        issues.append("missing Secure flag")
                    samesite = c.get("sameSite", "").lower()
                    if samesite not in ("strict", "lax"):
                        issues.append(f"SameSite={samesite or 'None'}")
                    if issues:
                        cookie_findings.append({"name": c["name"], "issues": issues})
                result["cookies"]["findings"] = cookie_findings
                result["cookies"]["count"] = len(cookie_findings)

                # ── Attack surface: forms & inputs ────────────────────────────
                forms_data = await page.evaluate("""() => {
                    return Array.from(document.forms).map(f => ({
                        action: f.action,
                        method: f.method || 'GET',
                        inputs: Array.from(f.elements)
                            .filter(e => e.tagName !== 'BUTTON')
                            .map(e => ({ name: e.name, type: e.type, id: e.id }))
                            .filter(e => e.name || e.id)
                    }));
                }""")
                total_inputs = sum(len(f.get("inputs", [])) for f in forms_data)
                result["attack_surface"]["forms"] = forms_data
                result["attack_surface"]["api_endpoints"] = api_endpoints
                result["attack_surface"]["input_count"] = total_inputs

                # Tech hints from page meta
                gen_loc = page.locator('meta[name="generator"]')
                if await gen_loc.count() > 0:
                    meta_gen = await gen_loc.get_attribute("content")
                    if meta_gen:
                        result["tech_hints"].append(f"Generator: {meta_gen}")

                # ── XSS reflection probe ──────────────────────────────────────
                canary = "xsscanary8472"
                xss_findings = []
                for form in forms_data[:5]:
                    text_inputs = [i for i in form.get("inputs", [])
                                   if i.get("type") in ("text", "search", "email", "", None)]
                    if not text_inputs:
                        continue
                    try:
                        probe_page = await context.new_page()
                        await probe_page.goto(url, timeout=15_000)
                        for inp in text_inputs[:3]:
                            selector = (f'[name="{inp["name"]}"]' if inp.get("name")
                                        else f'[id="{inp["id"]}"]')
                            try:
                                await probe_page.fill(selector, canary, timeout=3_000)
                            except Exception:
                                pass
                        try:
                            await probe_page.keyboard.press("Enter")
                            await probe_page.wait_for_load_state("networkidle", timeout=8_000)
                        except Exception:
                            pass
                        content = await probe_page.content()
                        if canary in content:
                            xss_findings.append({
                                "form_action": form.get("action", url),
                                "finding": f"Canary '{canary}' reflected unencoded in response",
                                "severity": "MEDIUM",
                            })
                        await probe_page.close()
                    except Exception:
                        pass

                result["xss_probes"]["findings"] = xss_findings
                result["xss_probes"]["count"] = len(xss_findings)

                # ── Screenshot ────────────────────────────────────────────────
                try:
                    await page.screenshot(path=screenshot_path, full_page=True)
                    result["screenshot"] = screenshot_path
                except Exception:
                    pass

            finally:
                await browser.close()

        return result

    return asyncio.run(_run())


def phase_browser(url: str, phases: dict | None = None) -> dict:
    header("Phase 4b — Browser Automation (Playwright)")
    results = {}

    storage: str | None = None
    if phases:
        sess = phases.get("auth", {}).get("session", {})
        storage = sess.get("storage_state")
        if storage and Path(storage).is_file():
            info(f"Browser — reusing Phase 2 session ({Path(storage).name})")

    try:
        info(f"Launching headless Chromium → {url}")
        data = _run_browser_phase(
            url,
            screenshot_path="browser_screenshot.png",
            storage_state=storage,
        )
    except ImportError:
        warn("Playwright not installed. Run: pip install playwright && playwright install chromium")
        return {"error": "playwright not installed"}
    except Exception as e:
        warn(f"Browser phase failed: {e}")
        return {"error": str(e)}

    if "error" in data:
        warn(f"Browser navigation failed: {data['error']}")
        return data

    if Path("browser_screenshot.png").is_file():
        register_temp_path("browser_screenshot.png")

    # ── Print results ─────────────────────────────────────────────────────────
    missing_hdrs = data["security_headers"]["missing"]
    present_hdrs = data["security_headers"]["present"]
    if missing_hdrs:
        fail(f"Security headers — {len(missing_hdrs)} missing")
        for h in missing_hdrs:
            print(f"           {RED}→{RESET} {h['header']}  ({h['description']})")
    else:
        ok(f"Security headers — all {len(present_hdrs)} present")

    cookie_findings = data["cookies"]["findings"]
    if cookie_findings:
        fail(f"Cookies — {len(cookie_findings)} insecure cookie(s)")
        for c in cookie_findings:
            print(f"           {RED}→{RESET} {c['name']}: {', '.join(c['issues'])}")
    else:
        ok("Cookies — all flags set correctly")

    forms = data["attack_surface"]["forms"]
    apis = data["attack_surface"]["api_endpoints"]
    inputs = data["attack_surface"]["input_count"]
    info(f"Attack surface — {len(forms)} form(s), {inputs} input(s), {len(apis)} API endpoint(s) discovered")
    for ep in apis[:5]:
        print(f"           {BLUE}→{RESET} {ep}")

    xss = data["xss_probes"]
    if xss["count"]:
        fail(f"XSS probe — {xss['count']} potential reflection(s) found")
        for f in xss["findings"]:
            print(f"           {RED}→{RESET} {f['form_action']} — {f['finding']}")
    else:
        ok("XSS probe — no canary reflection detected")

    tech = data["tech_hints"]
    if tech:
        info(f"Tech fingerprint — {', '.join(tech)}")

    if data.get("screenshot"):
        ok(f"Screenshot saved → {data['screenshot']}")

    # Build unified count for summary
    count = len(missing_hdrs) + len(cookie_findings) + xss["count"]
    results["browser"] = {**data, "count": count}
    return results
