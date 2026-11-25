"""Parallel secret detection, SAST, and dependency audit."""
from secscan.phases._imports import *  # noqa: F403

from secscan.tool_adapters.dependency_parsers import (
    PIP_AUDIT_JSON_ADAPTER,
    SAFETY_JSON_ADAPTER,
    parse_pip_audit_json,
    parse_safety_json,
)
from secscan.tool_adapters.runner import run_with_retries
from secscan.tool_adapters.sast import (
    BANDIT_JSON_ADAPTER,
    SEMGREP_JSON_ADAPTER,
    parse_bandit_json,
    parse_semgrep_json,
)
from secscan.tool_adapters.secrets_parsers import (
    DETECT_SECRETS_REPORT_ADAPTER,
    GITLEAKS_REPORT_ADAPTER,
    parse_detect_secrets_report_json,
    parse_gitleaks_report_json,
)
from secscan.tool_run_result import (
    attach_run_payload,
    outcome_from_exit_code,
    outcome_setup_failed,
)


def _finalize_tool(
    tool_dict: dict,
    *,
    code: int,
    stderr: str = "",
    parse_error: str | None = None,
    nonzero_exit_ok_when_signal: bool = False,
    signal_present: bool = False,
) -> None:
    """Attach canonical `run` payload for phase_status / consumers."""
    if parse_error:
        attach_run_payload(tool_dict, outcome_setup_failed(parse_error))
        return
    hint = (stderr or "")[:300]
    outcome = outcome_from_exit_code(code, stderr_hint=hint)
    prop = True
    if nonzero_exit_ok_when_signal and signal_present and code != 0:
        prop = False
    attach_run_payload(tool_dict, outcome, propagate_legacy_error=prop)


def _gitleaks_config_arg(scan_root: str) -> list[str]:
    root = Path(scan_root)
    for name in (".gitleaks.toml", "gitleaks.toml"):
        cfg = root / name
        if cfg.is_file():
            return ["--config", str(cfg)]
    return []


def _task_gitleaks(path: str) -> dict:
    info("Running gitleaks...")
    results: dict = {}
    gl_out = Path(f"gitleaks_report_{os.getpid()}.json")
    code, out, err, meta = run_with_retries(
        [
            "gitleaks", "detect", "--source", path,
            *_gitleaks_config_arg(path),
            "--report-format", "json",
            "--report-path", str(gl_out),
            "--no-banner",
        ],
        timeout=scan_timeout_sec("gitleaks", 120),
    )
    integration = meta.as_integration_dict(GITLEAKS_REPORT_ADAPTER)
    if gl_out.exists():
        try:
            raw = gl_out.read_text(encoding="utf-8") or "[]"
            data, perr = parse_gitleaks_report_json(raw)
            if perr:
                results["gitleaks"] = {
                    "error": perr,
                    "integration": integration,
                    "raw": raw[:500],
                }
                _finalize_tool(results["gitleaks"], code=code, stderr=err or "", parse_error=perr)
                warn(f"gitleaks — {perr}")
            else:
                results["gitleaks"] = {
                    "findings": data,
                    "count": len(data),
                    "integration": integration,
                }
                _finalize_tool(
                    results["gitleaks"],
                    code=code,
                    stderr=err or "",
                    nonzero_exit_ok_when_signal=True,
                    signal_present=len(data) > 0,
                )
                if data:
                    fail(f"gitleaks — {len(data)} secret(s) found")
                    for f in data[:5]:
                        print(
                            f"           {RED}→{RESET} {f.get('RuleID', '?')} "
                            f"in {f.get('File', '?')}:{f.get('StartLine', '?')}"
                        )
                else:
                    ok("gitleaks — no secrets found")
        finally:
            gl_out.unlink(missing_ok=True)
    else:
        results["gitleaks"] = {
            "error": err or "no report generated",
            "integration": integration,
        }
        _finalize_tool(results["gitleaks"], code=code, stderr=err or "")
        warn(f"gitleaks — {err.strip()[:80]}" if err else "gitleaks — no report generated")
    return results


def _task_detect_secrets(path: str) -> dict:
    info("Running detect-secrets...")
    results: dict = {}
    code, out, err, meta = run_with_retries(
        ["detect-secrets", "scan", path],
        timeout=scan_timeout_sec("detect_secrets", 120),
    )
    integration = meta.as_integration_dict(DETECT_SECRETS_REPORT_ADAPTER)
    if code == 0 and out:
        inner, perr = parse_detect_secrets_report_json(out)
        if perr:
            results["detect_secrets"] = {
                "error": perr,
                "integration": integration,
                "raw": out[:500],
            }
            _finalize_tool(results["detect_secrets"], code=code, stderr=err or "", parse_error=perr)
            warn(f"detect-secrets — {perr}")
        else:
            files_with_secrets = {k: v for k, v in inner.items() if v}
            count = sum(len(v) for v in files_with_secrets.values())
            results["detect_secrets"] = {
                "findings": files_with_secrets,
                "count": count,
                "integration": integration,
            }
            _finalize_tool(
                results["detect_secrets"],
                code=code,
                stderr=err or "",
                nonzero_exit_ok_when_signal=True,
                signal_present=count > 0,
            )
            if count:
                fail(f"detect-secrets — {count} potential secret(s) found")
                for fname, secrets in list(files_with_secrets.items())[:5]:
                    print(f"           {RED}→{RESET} {fname} ({len(secrets)} hit(s))")
            else:
                ok("detect-secrets — no secrets found")
    else:
        results["detect_secrets"] = {"error": err, "integration": integration}
        _finalize_tool(results["detect_secrets"], code=code, stderr=err or "")
        warn(f"detect-secrets — {err.strip()[:80]}")
    return results


def phase_secrets(path: str) -> dict:
    header("Phase 1 — Secret Detection (Parallel)")
    results: dict = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        fg = pool.submit(_task_gitleaks, path)
        fd = pool.submit(_task_detect_secrets, path)
        results.update(fg.result())
        results.update(fd.result())
    return results


def _task_semgrep(path: str) -> dict:
    info("Running semgrep (owasp-top-ten + python rules)...")
    results: dict = {}
    code, out, err, meta = run_with_retries(
        [
            "semgrep",
            "--config", "p/owasp-top-ten",
            "--config", "p/python",
            "--json",
            path,
        ],
        timeout=scan_timeout_sec("semgrep", 180),
    )
    integration = meta.as_integration_dict(SEMGREP_JSON_ADAPTER)
    out = out or ""
    if out.strip():
        findings, perr = parse_semgrep_json(out)
        if perr:
            results["semgrep"] = {
                "error": perr,
                "integration": integration,
                "raw": out[:500],
            }
            _finalize_tool(results["semgrep"], code=code, stderr=err or "", parse_error=perr)
            warn(f"semgrep — {perr}")
        else:
            results["semgrep"] = {
                "findings": findings,
                "count": len(findings),
                "integration": integration,
            }
            _finalize_tool(
                results["semgrep"],
                code=code,
                stderr=err or "",
                nonzero_exit_ok_when_signal=True,
                signal_present=len(findings) > 0,
            )
            if findings:
                fail(f"semgrep — {len(findings)} issue(s) found")
                for f in findings[:5]:
                    loc = f.get("path", "?") + ":" + str(f.get("start", {}).get("line", "?"))
                    msg = f.get("extra", {}).get("message", "")[:60]
                    print(f"           {RED}→{RESET} [{f.get('extra',{}).get('severity','?')}] {loc} — {msg}")
            else:
                ok("semgrep — no issues found")
    else:
        results["semgrep"] = {"error": err, "integration": integration}
        _finalize_tool(results["semgrep"], code=code, stderr=err or "")
        warn(f"semgrep — {err.strip()[:80]}")
    return results


def _bandit_config_arg(scan_root: str) -> list[str]:
    root = Path(scan_root)
    for name in ("bandit.yaml", ".bandit", "pyproject.toml"):
        cfg = root / name
        if cfg.is_file():
            return ["-c", str(cfg)]
    return []


def _task_bandit(path: str) -> dict:
    info("Running bandit...")
    results: dict = {}
    code, out, err, meta = run_with_retries(
        [
            "bandit", "-r", path, "-f", "json", "-q",
            *_bandit_config_arg(path),
            "--exclude", "venv,.venv,node_modules,.git,dist,build",
        ],
        timeout=scan_timeout_sec("bandit", 120),
    )
    integration = meta.as_integration_dict(BANDIT_JSON_ADAPTER)
    raw = out or err
    if raw:
        issues, metrics, perr = parse_bandit_json(raw)
        if perr:
            results["bandit"] = {
                "error": perr,
                "integration": integration,
                "raw": raw[:500],
            }
            _finalize_tool(results["bandit"], code=code, stderr=err or "", parse_error=perr)
            warn(f"bandit — {perr}")
        else:
            results["bandit"] = {
                "findings": issues,
                "count": len(issues),
                "metrics": metrics,
                "integration": integration,
            }
            _finalize_tool(
                results["bandit"],
                code=code,
                stderr=err or "",
                nonzero_exit_ok_when_signal=True,
                signal_present=len(issues) > 0,
            )
            high = [i for i in issues if i.get("issue_severity") == "HIGH"]
            med = [i for i in issues if i.get("issue_severity") == "MEDIUM"]
            if issues:
                fail(f"bandit — {len(issues)} issue(s) [{len(high)} HIGH, {len(med)} MEDIUM]")
                for i in issues[:5]:
                    loc = i.get("filename", "?") + ":" + str(i.get("line_number", "?"))
                    print(f"           {RED}→{RESET} [{i.get('issue_severity','?')}] {loc} — {i.get('issue_text','')[:60]}")
            else:
                ok("bandit — no issues found")
    else:
        results["bandit"] = {"error": "no output", "integration": integration}
        _finalize_tool(results["bandit"], code=code, stderr=err or "")
        warn("bandit — no output received")
    return results


def phase_sast(path: str) -> dict:
    header("Phase 2 — Static Analysis (SAST) (Parallel)")
    results: dict = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        fs = pool.submit(_task_semgrep, path)
        fb = pool.submit(_task_bandit, path)
        results.update(fs.result())
        results.update(fb.result())
    return results


def _pip_audit_cmd(scan_root: str) -> list[str]:
    root = Path(scan_root)
    if (root / "pyproject.toml").is_file():
        return ["pip-audit", "--format", "json", str(root)]
    for name in ("requirements.txt", "requirements-dev.txt"):
        req = root / name
        if req.is_file():
            return ["pip-audit", "--format", "json", "-r", str(req)]
    return ["pip-audit", "--format", "json"]


def _task_pip_audit(path: str) -> dict:
    info("Running pip-audit...")
    results: dict = {}
    code, out, err, meta = run_with_retries(
        _pip_audit_cmd(path),
        timeout=scan_timeout_sec("pip_audit", 120),
    )
    integration = meta.as_integration_dict(PIP_AUDIT_JSON_ADAPTER)
    raw = out or err
    if raw:
        deps, perr = parse_pip_audit_json(raw)
        if perr:
            results["pip_audit"] = {
                "error": perr,
                "integration": integration,
                "raw": raw[:500],
            }
            _finalize_tool(results["pip_audit"], code=code, stderr=err or "", parse_error=perr)
            warn(f"pip-audit — {perr}")
        else:
            vulns = [d for d in deps if d.get("vulns")]
            count = sum(len(d["vulns"]) for d in vulns)
            results["pip_audit"] = {
                "findings": vulns,
                "count": count,
                "integration": integration,
            }
            _finalize_tool(
                results["pip_audit"],
                code=code,
                stderr=err or "",
                nonzero_exit_ok_when_signal=True,
                signal_present=count > 0,
            )
            if count:
                fail(f"pip-audit — {count} vulnerability(ies) found")
                for pkg in vulns[:5]:
                    for v in pkg["vulns"][:2]:
                        print(f"           {RED}→{RESET} {pkg['name']}=={pkg['version']} — {v.get('id', '?')}")
            else:
                ok("pip-audit — no vulnerabilities found")
    else:
        results["pip_audit"] = {"error": err, "integration": integration}
        _finalize_tool(results["pip_audit"], code=code, stderr=err or "")
        warn(f"pip-audit — {err.strip()[:80]}")
    return results


def _task_safety() -> dict:
    info("Running safety check...")
    results: dict = {}
    code, out, err, meta = run_with_retries(
        ["safety", "check", "--json"],
        timeout=scan_timeout_sec("safety", 120),
    )
    integration = meta.as_integration_dict(SAFETY_JSON_ADAPTER)
    raw = out or err
    if raw:
        data, perr = parse_safety_json(raw)
        if perr:
            results["safety"] = {
                "error": perr,
                "integration": integration,
                "raw": raw[:300],
            }
            _finalize_tool(results["safety"], code=code, stderr=err or "", parse_error=perr)
            warn(f"safety — {perr}")
        elif isinstance(data, list):
            results["safety"] = {"findings": data, "count": len(data), "integration": integration}
            _finalize_tool(
                results["safety"],
                code=code,
                stderr=err or "",
                nonzero_exit_ok_when_signal=True,
                signal_present=len(data) > 0,
            )
            if data:
                fail(f"safety — {len(data)} vulnerability(ies) found")
                for v in data[:5]:
                    print(f"           {RED}→{RESET} {v[0]} {v[2]} — {v[3][:60]}")
            else:
                ok("safety — no vulnerabilities found")
        else:
            results["safety"] = {"raw": data, "integration": integration}
            _finalize_tool(results["safety"], code=code, stderr=err or "")
            ok("safety — scan complete (see report for details)")
    else:
        results["safety"] = {"error": err, "integration": integration}
        _finalize_tool(results["safety"], code=code, stderr=err or "")
        warn(f"safety — {err.strip()[:80]}")
    return results


def phase_dependencies(path: str) -> dict:
    header("Phase 3 — Dependency Audit (Parallel)")
    results: dict = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        fp = pool.submit(_task_pip_audit, path)
        fs = pool.submit(_task_safety)
        results.update(fp.result())
        results.update(fs.result())
    return results
