"""Phase 4c — OWASP ZAP proxy DAST."""
from secscan.phases._imports import *  # noqa: F403

# ── Phase 4c — OWASP ZAP ────────────────────────────────────────────────────────

_ZAP_PORT = 8090


def _zap_api(endpoint: str, api_key: str, params: dict | None = None) -> dict:
    query = urllib.parse.urlencode({**(params or {}), "apikey": api_key})
    url   = f"http://localhost:{_ZAP_PORT}/JSON/{endpoint}/?{query}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"_error": str(e)}


def _zap_wait(label: str, fn, key: str, done_val: str, interval: int, max_iter: int) -> None:
    for i in range(max_iter):
        time.sleep(interval)
        resp = fn()
        val  = resp.get(key, "0")
        if val == done_val:
            ok(f"{label} complete")
            return
        info(f"{label}: {val}%")
    warn(f"{label} did not finish within time limit — continuing anyway")


def phase_zap(url: str) -> dict:
    header("Phase 4c — OWASP ZAP (Proxy DAST)")

    zap_bat, zap_hint = resolve_zap_bat()
    if zap_bat is None or not zap_bat.is_file():
        warn(zap_hint or "ZAP not found.")
        warn("Install via: winget install OWASP.ZAP (Windows) or set SECURITY_SCAN_ZAP_BAT.")
        return {
            "zap": {
                "count": 0,
                "error": "zap_not_installed",
                "alerts": [],
            },
        }

    api_key  = "zapscan_" + "".join(random.choices(string.ascii_lowercase, k=8))
    zap_proc = None
    results  = {}

    try:
        # ── Start daemon ──────────────────────────────────────────────────────
        info("Starting ZAP daemon (this takes ~30–60 s)...")
        zap_proc = subprocess.Popen(
            [
                str(zap_bat), "-daemon",
                "-port", str(_ZAP_PORT),
                "-config", f"api.key={api_key}",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Poll until ready (90 s max)
        ready = False
        for i in range(18):
            time.sleep(5)
            resp = _zap_api("core/view/version", api_key)
            if "version" in resp:
                ok(f"ZAP ready (v{resp['version']})")
                ready = True
                break
            info(f"Waiting for ZAP... ({(i + 1) * 5}s)")

        if not ready:
            fail("ZAP did not start within 90 s")
            return {"zap": {"count": 0, "error": "startup timeout"}}

        # ── Spider ────────────────────────────────────────────────────────────
        info(f"Spidering {url} ...")
        spider_resp = _zap_api("spider/action/scan", api_key, {"url": url, "maxChildren": "10"})
        spider_id   = spider_resp.get("scan", "0")
        _zap_wait(
            "Spider",
            lambda: _zap_api("spider/view/status", api_key, {"scanId": spider_id}),
            "status", "100", 3, 30,  # 3 s interval, 90 s max
        )

        # ── Active scan ───────────────────────────────────────────────────────
        info(f"Active scanning {url} ...")
        ascan_resp = _zap_api("ascan/action/scan", api_key, {"url": url, "recurse": "true"})
        ascan_id   = ascan_resp.get("scan", "0")
        _zap_wait(
            "Active scan",
            lambda: _zap_api("ascan/view/status", api_key, {"scanId": ascan_id}),
            "status", "100", 5, 60,  # 5 s interval, 5 min max
        )

        # ── Retrieve alerts ───────────────────────────────────────────────────
        info("Retrieving alerts...")
        alerts_resp = _zap_api("core/view/alerts", api_key, {"baseurl": url})
        alerts = alerts_resp.get("alerts", [])
        if not isinstance(alerts, list):
            warn("ZAP — alerts response was not a list; treating as empty")
            alerts = []

        high   = [a for a in alerts if a.get("risk") == "High"]
        medium = [a for a in alerts if a.get("risk") == "Medium"]
        low    = [a for a in alerts if a.get("risk") == "Low"]
        info_a = [a for a in alerts if a.get("risk") == "Informational"]

        count = len(high) + len(medium)
        if count == 0:
            ok(f"ZAP: 0 High/Medium ({len(low)} Low, {len(info_a)} Info)")
        else:
            fail(f"ZAP: {len(high)} High, {len(medium)} Medium, {len(low)} Low")
            for a in (high + medium):
                print(f"    [{a['risk']}] {a['alert']} @ {a.get('url','')[:70]}")

        results["zap"] = {
            "count"        : count,
            "high"         : len(high),
            "medium"       : len(medium),
            "low"          : len(low),
            "informational": len(info_a),
            "alerts"       : [
                {
                    "risk"       : a.get("risk"),
                    "alert"      : a.get("alert"),
                    "url"        : a.get("url"),
                    "description": a.get("description", "")[:300],
                    "solution"   : a.get("solution",    "")[:300],
                    "cwe"        : a.get("cweid"),
                    "wasc"       : a.get("wascid"),
                }
                for a in (high + medium + low)
            ],
        }

    except Exception as e:
        fail(f"ZAP phase error: {e}")
        results["zap"] = {"count": 0, "error": str(e)}

    finally:
        if zap_proc is not None:
            info("Shutting down ZAP...")
            try:
                _zap_api("core/action/shutdown", api_key)
            except Exception:
                pass
            time.sleep(2)
            try:
                zap_proc.terminate()
            except Exception:
                pass
            try:
                zap_proc.wait(timeout=25)
            except subprocess.TimeoutExpired:
                try:
                    zap_proc.kill()
                except Exception:
                    pass

    return results
