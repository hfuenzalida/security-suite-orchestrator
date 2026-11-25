"""Phase 4 — DAST (nuclei, schemathesis)."""
from secscan.http_session import cookie_header, host_in_session_scope
from secscan.phases._imports import *  # noqa: F403

from secscan.tool_adapters.dast_parsers import (
    NUCLEI_JSONL_ADAPTER,
    SCHEMATHESIS_ADAPTER,
    parse_nuclei_jsonl,
)
from secscan.temp_registry import register_temp_path
from secscan.tool_run_result import (
    attach_run_payload,
    outcome_from_exit_code,
    outcome_setup_failed,
)
from secscan.tool_adapters.runner import run_with_retries


def _nuclei_target_urls(primary_url: str, phases: dict | None) -> tuple[list[str], dict]:
    """
    Build nuclei target list: primary URL plus unique subfinder hosts (same scheme/port).
    Caps at _MAX_NUCLEI_TARGETS total.
    """
    meta: dict = {"primary": primary_url, "subfinder_added": 0, "total_targets": 1}
    parsed = urllib.parse.urlparse(primary_url)
    scheme = (parsed.scheme or "https").lower()
    if scheme not in ("http", "https"):
        scheme = "https"
    port = parsed.port
    primary_host = (parsed.hostname or "").lower()
    port_suffix = ""
    if port:
        port_suffix = f":{port}"

    first = primary_url.rstrip("/") + "/"
    urls: list[str] = [first]
    seen_netloc = {parsed.netloc.lower()}

    if not phases:
        meta["total_targets"] = len(urls)
        meta["urls"] = urls
        return urls, meta

    rdata = phases.get("recon", {}).get("recon", {})
    sf = rdata.get("subfinder", {})
    if sf.get("status") != "ok":
        meta["total_targets"] = len(urls)
        meta["urls"] = urls
        return urls, meta

    for h in sf.get("hosts") or []:
        if len(urls) >= _MAX_NUCLEI_TARGETS:
            break
        h = h.strip().lower()
        if not h or h == primary_host:
            continue
        netloc = f"{h}{port_suffix}"
        if netloc.lower() in seen_netloc:
            continue
        seen_netloc.add(netloc.lower())
        u = urllib.parse.urlunparse((scheme, netloc, "/", "", "", "")).rstrip("/") + "/"
        urls.append(u)
        meta["subfinder_added"] += 1

    meta["total_targets"] = len(urls)
    meta["urls"] = urls
    return urls, meta


def _nuclei_cmd_add_session_headers(cmd: list[str], target_urls: list[str] | None = None) -> list[str]:
    """Append -H Cookie / custom headers when Phase 2 auth is active and in-scope."""
    out = list(cmd)
    _ck = get_session_cookies()
    _hk = get_session_headers()
    if not (_ck or _hk):
        return out
    targets = target_urls or []
    if targets and not all(host_in_session_scope(u) for u in targets):
        warn("Nuclei — omitting session cookies/headers: one or more targets are out of auth scope")
        return out
    if not targets:
        warn("Nuclei — omitting session cookies/headers: no target URL for scope check")
        return out
    if _ck:
        out.extend(["-H", f"Cookie: {cookie_header(_ck)}"])
    if _hk:
        for hk, hv in _hk.items():
            if hk.lower() != "cookie":
                out.extend(["-H", f"{hk}: {hv}"])
    return out


def _task_nuclei(url: str, phases: dict | None = None) -> dict:
    targets, meta = _nuclei_target_urls(url, phases)
    results: dict = {}
    list_path: str | None = None
    out = ""
    run_meta = None
    try:
        if len(targets) == 1:
            info(f"Running nuclei against {targets[0]}...")
            cmd = [
                "nuclei", "-u", targets[0],
                "-t", "http/",
                "-severity", "medium,high,critical",
                "-json",
                "-silent",
            ]
            timeout = scan_timeout_sec("nuclei", 300)
        else:
            info(
                f"Running nuclei against {len(targets)} URL(s) "
                f"(primary + {meta.get('subfinder_added', 0)} from subfinder)..."
            )
            fd, list_path = tempfile.mkstemp(prefix="nuclei_targets_", suffix=".txt", text=True)
            os.close(fd)
            register_temp_path(list_path)
            Path(list_path).write_text("\n".join(targets), encoding="utf-8")
            cmd = [
                "nuclei", "-list", list_path,
                "-t", "http/",
                "-severity", "medium,high,critical",
                "-json",
                "-silent",
            ]
            cap = scan_timeout_sec("nuclei_multi_cap", 900)
            timeout = min(cap, 180 + 45 * len(targets))

        cmd = _nuclei_cmd_add_session_headers(cmd, targets)
        if has_session_credentials() and all(host_in_session_scope(u) for u in targets):
            info("nuclei — sending Phase 2 session Cookie / headers (in-scope targets only)")

        code, out, err, run_meta = run_with_retries(cmd, timeout=timeout)
    finally:
        if list_path:
            try:
                os.unlink(list_path)
            except OSError:
                pass

    if run_meta is None:
        warn("nuclei — could not prepare target list or run (check temp file permissions)")
        results["nuclei"] = {
            "count": 0,
            "findings": [],
            "targets": targets,
            "subfinder_extra_hosts": meta.get("subfinder_added", 0),
        }
        attach_run_payload(results["nuclei"], outcome_setup_failed("setup failed"))
        return results

    findings, ndjson_skipped = parse_nuclei_jsonl(out or "")
    integ = run_meta.as_integration_dict(NUCLEI_JSONL_ADAPTER)
    integ["ndjson_skipped_lines"] = ndjson_skipped

    nuc = {
        "findings": findings,
        "count": len(findings),
        "targets": targets,
        "subfinder_extra_hosts": meta.get("subfinder_added", 0),
        "integration": integ,
    }
    outcome = outcome_from_exit_code(code, stderr_hint=(err or "")[:500])
    attach_run_payload(
        nuc,
        outcome,
        propagate_legacy_error=(len(findings) == 0),
    )
    if findings:
        nuc["ok"] = True
    results["nuclei"] = nuc
    if findings:
        fail(f"nuclei — {len(findings)} finding(s) across {len(targets)} target(s)")
        for f in findings[:5]:
            info_data = f.get("info", {})
            print(f"           {RED}→{RESET} [{info_data.get('severity','?').upper()}] {f.get('template-id','?')} — {f.get('matched-at','?')}")
    else:
        ok(f"nuclei — no findings ({len(targets)} target(s))")
    return results


def _schemathesis_openapi_candidates(base_url: str) -> list[str]:
    root = base_url.rstrip("/")
    return [
        f"{root}/openapi.json",
        f"{root}/v1/openapi.json",
        f"{root}/api/openapi.json",
    ]


def _task_schemathesis(url: str) -> dict:
    candidates = _schemathesis_openapi_candidates(url)
    openapi_url = candidates[0]
    info(f"Running schemathesis (trying {len(candidates)} OpenAPI path(s), first {openapi_url})...")
    results: dict = {}
    auth_hdr = os.environ.get("MET_API_TOKEN") or os.environ.get("SECSCAN_OPENAPI_BEARER", "")
    headers: list[str] = []
    if auth_hdr.strip():
        headers = ["-H", f"Authorization: Bearer {auth_hdr.strip()}"]
    code, out, err, run_meta = -1, "", "", None
    for candidate in candidates:
        openapi_url = candidate
        code, out, err, run_meta = run_with_retries(
            [
                "schemathesis", "run", openapi_url,
                "--checks", "all",
                "--max-examples", "25",
                *headers,
            ],
            timeout=scan_timeout_sec("schemathesis", 180),
        )
        combined_try = (out + err).strip()
        if code == 0:
            break
        if code == -1:
            break
        unreachable = "404" in combined_try or "Connection refused" in combined_try or "Failed to load schema" in combined_try
        if not unreachable:
            break
    assert run_meta is not None
    combined = (out + err).strip()
    integration = run_meta.as_integration_dict(SCHEMATHESIS_ADAPTER)
    if code == 0:
        ok("schemathesis — no issues found")
        results["schemathesis"] = {
            "status": "passed",
            "output": combined[-500:],
            "integration": integration,
        }
        attach_run_payload(results["schemathesis"], outcome_from_exit_code(0))
    elif code == -1:
        warn("schemathesis — not found")
        results["schemathesis"] = {
            "integration": integration,
        }
        attach_run_payload(
            results["schemathesis"],
            outcome_from_exit_code(code, stderr_hint="not installed"),
        )
    else:
        fail("schemathesis — issues found or spec unreachable")
        results["schemathesis"] = {
            "status": "failed",
            "output": combined[-500:],
            "integration": integration,
        }
        attach_run_payload(results["schemathesis"], outcome_from_exit_code(code, stderr_hint=combined[:300]))
    return results


def phase_dast(url: str, phases: dict | None = None) -> dict:
    header("Phase 4 — Dynamic Analysis (DAST) (Parallel)")
    results: dict = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        fn = pool.submit(_task_nuclei, url, phases)
        fs = pool.submit(_task_schemathesis, url)
        results.update(fn.result())
        results.update(fs.result())
    return results
