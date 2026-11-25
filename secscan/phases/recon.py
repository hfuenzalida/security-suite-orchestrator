"""Phase 0 — Reconnaissance (DNS, ports, paths, CORS)."""
from secscan.phases._imports import *  # noqa: F403

# ── Recon Phase ────────────────────────────────────────────────────────────────

_NMAP_RES: tuple[str, str] | None = None
_NMAP_HINT_WARNED = False


def _nmap_executable() -> str:
    """Resolved path or 'nmap'; warns once if resolver reports install hints."""
    global _NMAP_RES, _NMAP_HINT_WARNED
    if _NMAP_RES is None:
        _NMAP_RES = resolve_nmap()
    exe, hint = _NMAP_RES
    if hint and not _NMAP_HINT_WARNED:
        warn(hint)
        _NMAP_HINT_WARNED = True
    return exe


# High-value sensitive paths to probe
_SENSITIVE_PATHS = [
    # Secrets & config
    "/.env", "/.env.local", "/.env.production", "/config.json",
    "/config.yml", "/config.yaml", "/settings.json", "/secrets.json",
    "/web.config", "/.htaccess", "/.htpasswd",
    # Git exposure
    "/.git/", "/.git/config", "/.git/HEAD",
    # Admin & debug
    "/admin", "/admin/", "/administrator", "/dashboard",
    "/debug", "/__debug__/", "/console", "/shell",
    # API & docs
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/redoc",
    "/graphql", "/graphiql",
    # Frameworks
    "/actuator", "/actuator/health", "/actuator/env",  # Spring Boot
    "/server-status", "/server-info",                   # Apache
    "/metrics", "/prometheus",                           # monitoring
    "/.well-known/security.txt",
    "/health", "/healthz", "/ready", "/ping",
    # Backups & dumps
    "/backup", "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz",
    # CMS
    "/wp-admin/", "/wp-login.php", "/wp-config.php",
    "/phpmyadmin/", "/phpinfo.php",
    # Discovery
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
]

_CORS_CANARY = "https://evil-canary.example.com"


def _host_allows_subfinder(host: str) -> bool:
    """Subfinder needs a DNS name, not localhost or a bare IP."""
    if not host or host.lower() in ("localhost",):
        return False
    try:
        ipaddress.ip_address(host.split("%")[0])
        return False
    except ValueError:
        return True


def _recon_subfinder(domain: str) -> dict:
    """Passive subdomain enumeration via ProjectDiscovery subfinder."""
    info("Running subfinder (passive subdomains)...")
    code, out, err = run(
        ["subfinder", "-d", domain, "-silent", "-timeout", "20"],
        timeout=240,
    )
    if code == -1:
        warn("subfinder — not installed or not on PATH")
        return {"status": "missing", "hosts": [], "count": 0, "error": err or "not found"}

    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    # Cap stored hosts to keep JSON reasonable
    hosts = lines[:500]
    if hosts:
        fail(f"subfinder — {len(lines)} host(s) discovered")
        for h in hosts[:12]:
            print(f"           {BLUE}→{RESET} {h}")
        if len(lines) > 12:
            print(f"           {BLUE}→{RESET} ... and {len(lines) - 12} more")
    else:
        ok("subfinder — no extra subdomains (or none resolved)")

    return {
        "status": "ok",
        "hosts": hosts,
        "count": len(lines),
        "error": None if code == 0 else (err or "")[:200],
    }


def _recon_whatweb(url: str) -> dict:
    """Tech stack fingerprint via WhatWeb (JSON)."""
    info("Running whatweb (tech fingerprint)...")
    code, out, err = run(["whatweb", url, "--log-json=-"], timeout=120)
    if code == -1:
        warn("whatweb — not installed or not on PATH")
        return {"status": "missing", "fingerprints": [], "count": 0, "error": err or "not found"}

    raw = (out or err or "").strip()
    parsed: object | None = None
    if raw:
        parsed = safe_json_decode(raw)
    plugins: list[dict] = []
    if isinstance(parsed, list):
        plugins = [p for p in parsed if isinstance(p, dict)]
    elif isinstance(parsed, dict):
        plugins = [parsed]

    if plugins:
        ok(f"whatweb — {len(plugins)} fingerprint block(s)")
        for p in plugins[:8]:
            target = p.get("target", url)
            plug = p.get("plugins", p)
            if isinstance(plug, dict):
                names = list(plug.keys())[:6]
                print(f"           {BLUE}→{RESET} {target}: {', '.join(names)}")
            else:
                print(f"           {BLUE}→{RESET} {str(plug)[:100]}")
    else:
        ok("whatweb — scan complete (no structured plugins parsed)")

    return {
        "status": "ok",
        "fingerprints": plugins[:50],
        "count": len(plugins),
        "raw_excerpt": raw[:2000] if not plugins else "",
        "error": None if code == 0 else (err or "")[:200],
    }


def _recon_dns(host: str) -> dict:
    """Resolve host to IPs + reverse DNS."""
    result: dict = {"host": host, "ips": [], "reverse": []}
    try:
        infos = socket.getaddrinfo(host, None)
        ips = list({i[4][0] for i in infos})
        result["ips"] = ips
        for ip in ips[:3]:
            try:
                rev = socket.gethostbyaddr(ip)[0]
                result["reverse"].append(rev)
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result


def _recon_nmap(host: str, port: int | None) -> dict:
    """Run nmap service scan on the target host."""
    nmap_bin = _nmap_executable()
    # Scan top 1000 ports (fast) + the app port explicitly
    ports_arg = f"1-1024,{port},8080,8443,8888,9000,9090" if port else "1-1024,8080,8443"
    cmd = [
        nmap_bin, "-sV", "--open", "-T4",
        "-p", ports_arg,
        "--script", "banner,http-title",
        "-oX", "-",      # XML to stdout
        host,
    ]
    code, out, err = run(cmd, timeout=120)

    if code < 0 or not out.strip().startswith("<?xml"):
        return {"error": err.strip()[:200] or "nmap failed or not found"}

    # Parse XML
    try:
        root = ET.fromstring(out)
        open_ports = []
        for port_el in root.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            service_el = port_el.find("service")
            service = service_el.get("name", "?") if service_el is not None else "?"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            # Script output (banner / http-title)
            scripts = {}
            for sc in port_el.findall("script"):
                scripts[sc.get("id", "")] = sc.get("output", "")[:80]
            open_ports.append({
                "port": int(port_el.get("portid", 0)),
                "protocol": port_el.get("protocol", "tcp"),
                "service": service,
                "product": f"{product} {version}".strip(),
                "scripts": scripts,
            })
        return {"open_ports": open_ports, "count": len(open_ports)}
    except ET.ParseError as e:
        return {"error": f"XML parse error: {e}"}


def _recon_sensitive_paths(base_url: str) -> dict:
    """Probe common sensitive paths — flag anything that returns non-404."""
    found = []
    for path in _SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "SecurityAudit/1.0"}
            )
            with urllib.request.urlopen(req, timeout=6) as r:
                status = r.status
                length = len(r.read())
        except urllib.error.HTTPError as e:
            status = e.code
            length = 0
        except Exception:
            continue  # connection refused / timeout — skip

        if status not in (404, 410):
            severity = "HIGH" if status in (200, 301, 302) else "LOW"
            found.append({
                "path": path,
                "status": status,
                "length": length,
                "severity": severity,
            })
    return {"findings": found, "count": len(found)}


def _recon_http_methods(base_url: str, extra_paths: list[str]) -> dict:
    """Send HTTP OPTIONS to discover allowed methods."""
    findings = []
    risky_methods = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
    paths_to_check = ["/"] + [p for p in extra_paths[:5] if p.startswith("/")]

    for path in paths_to_check:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(url, method="OPTIONS",
                                         headers={"User-Agent": "SecurityAudit/1.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                allow = r.headers.get("Allow", "") or r.headers.get("Access-Control-Allow-Methods", "")
        except urllib.error.HTTPError as e:
            allow = e.headers.get("Allow", "") or e.headers.get("Access-Control-Allow-Methods", "")
        except Exception:
            continue

        if allow:
            methods = {m.strip().upper() for m in allow.split(",")}
            dangerous = methods & risky_methods
            if dangerous:
                findings.append({
                    "path": path,
                    "allowed_methods": list(methods),
                    "dangerous": list(dangerous),
                    "severity": "MEDIUM",
                })
    return {"findings": findings, "count": len(findings)}


def _recon_cors(base_url: str) -> dict:
    """Check for overly permissive CORS policy."""
    findings = []
    try:
        req = urllib.request.Request(
            base_url,
            headers={
                "User-Agent": "SecurityAudit/1.0",
                "Origin": _CORS_CANARY,
            },
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "") or ""
            acac = r.headers.get("Access-Control-Allow-Credentials", "") or ""
    except urllib.error.HTTPError as e:
        acao = e.headers.get("Access-Control-Allow-Origin", "") or ""
        acac = e.headers.get("Access-Control-Allow-Credentials", "") or ""
    except Exception:
        return {"findings": [], "count": 0}

    acao = str(acao)
    acac_s = str(acac or "")

    if acao == "*":
        findings.append({
            "issue": "Wildcard CORS — ACAO: *",
            "severity": "MEDIUM",
            "detail": "Any origin can read responses. Combine with ACAC:true for HIGH.",
        })
    elif _CORS_CANARY in acao:
        sev = "HIGH" if acac_s.lower() == "true" else "MEDIUM"
        findings.append({
            "issue": f"Canary origin reflected — ACAO: {acao}",
            "severity": sev,
            "detail": f"Access-Control-Allow-Credentials: {acac_s}",
        })

    return {"findings": findings, "count": len(findings)}


def phase_recon(url: str) -> dict:
    header("Phase 0 — Reconnaissance")

    parsed   = urllib.parse.urlparse(url)
    host     = parsed.hostname or "localhost"
    port     = parsed.port
    results  = {}

    # ── DNS ──────────────────────────────────────────────────────────────────
    info(f"DNS resolution → {host}")
    dns = _recon_dns(host)
    if dns.get("ips"):
        ok(f"DNS — {host} → {', '.join(dns['ips'])}")
    else:
        warn(f"DNS — could not resolve {host}")
    results["dns"] = dns

    # ── Subfinder + WhatWeb (parallel) ─────────────────────────────────────────
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {}
        if _host_allows_subfinder(host):
            futures["subfinder"] = pool.submit(_recon_subfinder, host)
        futures["whatweb"] = pool.submit(_recon_whatweb, url)
        for name, fut in futures.items():
            results[name] = fut.result()

    if "subfinder" not in results:
        info("subfinder — skipped (localhost / IP-only target)")
        results["subfinder"] = {"status": "skipped", "hosts": [], "count": 0}

    # ── Nmap port scan ───────────────────────────────────────────────────────
    info(f"Nmap port scan → {host} (top ports + app port)...")
    nmap = _recon_nmap(host, port)
    if "error" in nmap:
        warn(f"Nmap — {nmap['error']}")
    elif nmap.get("open_ports"):
        open_ports = nmap["open_ports"]
        count = nmap["count"]
        if count > 1:
            fail(f"Nmap — {count} open port(s) found (check for unintended exposure)")
        else:
            ok(f"Nmap — {count} open port(s)")
        for p in open_ports:
            flag = RED if p["port"] not in (port, 80, 443) else BLUE
            svc  = f"{p['service']} {p['product']}".strip()
            print(f"           {flag}→{RESET} {p['port']}/{p['protocol']}  {svc}")
            for sid, sout in p["scripts"].items():
                print(f"              [{sid}] {sout[:70]}")
    else:
        ok("Nmap — no unexpected open ports")
    results["nmap"] = nmap

    # ── Sensitive paths ──────────────────────────────────────────────────────
    info(f"Probing {len(_SENSITIVE_PATHS)} sensitive paths...")
    paths = _recon_sensitive_paths(url)
    discovered = [f for f in paths["findings"] if f["status"] in (200, 301, 302)]
    if paths["findings"]:
        fail(f"Sensitive paths — {paths['count']} accessible path(s)")
        for f in paths["findings"]:
            col = RED if f["severity"] == "HIGH" else YELLOW
            print(f"           {col}→{RESET} HTTP {f['status']}  {f['path']}  ({f['length']} bytes)")
    else:
        ok("Sensitive paths — nothing exposed")
    results["sensitive_paths"] = paths

    # ── HTTP methods ─────────────────────────────────────────────────────────
    info("Checking allowed HTTP methods (OPTIONS)...")
    discovered_paths = [f["path"] for f in paths["findings"]]
    methods = _recon_http_methods(url, discovered_paths)
    if methods["findings"]:
        fail(f"HTTP methods — {methods['count']} endpoint(s) with dangerous methods")
        for f in methods["findings"]:
            print(f"           {RED}→{RESET} {f['path']}  dangerous: {', '.join(f['dangerous'])}")
            print(f"              all allowed: {', '.join(f['allowed_methods'])}")
    else:
        ok("HTTP methods — no dangerous methods exposed")
    results["http_methods"] = methods

    # ── CORS ─────────────────────────────────────────────────────────────────
    info("Checking CORS policy...")
    cors = _recon_cors(url)
    if cors["findings"]:
        for f in cors["findings"]:
            col = RED if f["severity"] == "HIGH" else YELLOW
            fail(f"CORS — [{f['severity']}] {f['issue']}")
            print(f"           {col}→{RESET} {f['detail']}")
    else:
        ok("CORS — policy looks sane")
    results["cors"] = cors

    # Unified count for summary (paths/methods/cors + capped intel from subfinder/whatweb)
    intel = 0
    sf = results.get("subfinder", {})
    if sf.get("status") == "ok":
        intel += min(sf.get("count", 0), 150)
    ww = results.get("whatweb", {})
    if ww.get("status") == "ok":
        intel += min(ww.get("count", 0), 30)
    total = (
        len(paths["findings"]) +
        methods["count"] +
        cors["count"] +
        intel
    )
    results["count"] = total
    return {"recon": results}

