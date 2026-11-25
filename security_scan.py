"""
Security Suite Orchestrator
Runs: Phase 0.5 AI code analysis (local Ollama, source-aware threat model),
      gitleaks, detect-secrets, semgrep, bandit, pip-audit, safety, nuclei, schemathesis,
      nmap recon, subfinder, whatweb, Phase 2 optional auth (--auth-config), playwright,
      OWASP ZAP (proxy DAST), poc exploitation, ollama (AI reasoning).
      Phase 3 optional request chains (--chain-config) for CSRF / multi-step APIs.
Usage:
  python security_scan.py --url https://app.com --auth-config auth.example.json
  python security_scan.py --url https://app.com --chain-config chain.example.json
  python security_scan.py --path . --url http://localhost:8080 --output report.json
  python security_scan.py --skip browser ai auth       # skip optional phases
  python security_scan.py --path . --url http://localhost:8080 --resume myhost_abc123  # resume run id under scan_workspace/
  python security_scan.py --path . --url http://localhost:8080 --fail-on any            # CI: exit 1 if any tool reported findings
  python security_scan.py --url http://localhost:8080 --notify-webhook https://hooks.slack.com/...  # alert on confirmed PoC (see --notify-on)
  python security_scan.py --path . --sarif-output results.sarif --baseline baseline.example.json
  python security_scan.py --config security_scan.toml.example -v --log-json
  python security_scan.py --replay-bundle-output replay.json   # archive pins + config hash (see CORRELATION_JOIN_RULES.md)
  python security_scan.py --replay-include-pip-freeze          # add pip freeze SHA-256 to replay_bundle (REPRODUCIBILITY.md)
  python security_scan.py --network-mode offline-static       # merge extra --skip for less outbound (SAFE_OPERATIONS.md)
  python security_scan.py --include-glob 'src/**' --exclude-glob 'vendor/**'   # scope unified gate (SAFE_OPERATIONS.md)
  python security_scan.py --wipe-run-dir                       # delete workspace/RUN_ID after success (see WORKSPACE_CONTRACT.md)
  python security_scan.py --wipe-temp                          # remove registered temp artifacts after success (see HARDENING_CHECKLIST.md)
  python security_scan.py --report-tier executive              # HTML/PDF: EXPLOITED-first narrative (see REPORT_TIERS.md)
  python security_scan.py --audit-log-jsonl build/audit.jsonl --hmac-sign-report
  python security_scan.py --ci-profile --sarif-output out.sarif --sarif-source unified --junit-output junit.xml

See OPERATING_GUARANTEES.md for supported use, limits, and versioning expectations.
"""

import argparse
import datetime
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from secscan.checkpoint_core import (
    CHECKPOINT_VERSION as _CHECKPOINT_VERSION,
    DEFAULT_WORKSPACE_DIR as _DEFAULT_WORKSPACE_DIR,
    checkpoint_path as _checkpoint_path,
    checkpoint_read as _checkpoint_read,
    checkpoint_write as _checkpoint_write,
    default_run_id as _default_run_id,
    resolve_run_dir as _resolve_run_dir,
    restore_session_from_phases as _restore_session_from_phases,
    validate_resume as _validate_resume,
    validate_run_id as _validate_run_id,
)
from secscan.session_sanitize import strip_session_secrets
from secscan.ci_gates import assess_fail_on as _assess_fail_on, should_send_notification as _should_send_notification
from secscan.cli_output import (
    BLUE,
    BOLD,
    GREEN,
    RED,
    RESET,
    YELLOW,
    configure_cli_output,
    configure_secscan_logger,
    fail,
    header,
    info,
    ok,
    warn,
)
from secscan.config_io import load_auth_config, load_chain_config
from secscan.constants import (
    CORRELATION_JOIN_RULES_VERSION,
    ORCHESTRATOR_VERSION,
    REPORT_SCHEMA_COMPAT_VERSION,
)
from secscan.correlation_bridge import build_correlation_hints
from secscan.export_sanitize import sanitize_report_copy
from secscan.findings_unified import (
    filter_findings_by_baseline,
    load_baseline_fingerprints,
    stable_correlation_id as _stable_correlation_id,
    tag_correlation_ids as _tag_correlation_ids,
)
from secscan.http_session import auth_clear
from secscan.json_util import safe_json_decode
from secscan.junit_xml import write_junit_report
from secscan.logging_config import setup_logging
from secscan.notifications import post_notification_webhook as _post_notification_webhook
from secscan.redaction import redact_sensitive_obj, redact_sensitive_text
from secscan.report_core import build_report
from secscan.report_tiers import build_report_policy_embed, normalize_report_tier
from secscan.run_manifest import build_run_manifest
from secscan.auditability_embed import build_auditability_embed
from secscan.safe_operations_embed import build_safe_operations_embed
from secscan.unified_report import apply_unified_findings_to_report
from secscan.user_config import merged_arg_defaults
from secscan.cli_run_parser import (
    CLI_RUN_EPILOG as _CLI_EPILOG,
    build_run_parser,
    run_replay_stub,
    strip_optional_run_argv,
)

# Phase implementations and report writers (modular package layout)
from secscan.phases import (
    phase_ai_code_analysis,
    phase_ai_reasoning,
    phase_auth_session,
    phase_browser,
    phase_dependencies,
    phase_dast,
    phase_exploit,
    phase_recon,
    phase_request_chain,
    phase_sast,
    phase_secrets,
    phase_specialized_agents,
    phase_zap,
)
from secscan.reporting.output_reports import (
    generate_html_report,
    generate_pdf_report,
    generate_sarif_report,
    print_final_summary,
)

# ── Windows console: enable ANSI + UTF-8 output ──────────────────────────────
if sys.platform == "win32":
    os.system("color")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ── Entry point ─────────────────────────────────────────────────────────────────


def main() -> None:
    sub, argv = strip_optional_run_argv(sys.argv[1:])
    if sub == "replay":
        run_replay_stub(argv)
        return
    if sub == "doctor":
        from secscan.tool_doctor import run_doctor_subcommand

        raise SystemExit(run_doctor_subcommand(argv))

    _cfg_pre = argparse.ArgumentParser(add_help=False)
    _cfg_pre.add_argument("--config", default=None, help=argparse.SUPPRESS)
    _cfg_early, _ = _cfg_pre.parse_known_args(argv)
    _merged = merged_arg_defaults(_cfg_early.config)
    parser = build_run_parser(_merged)
    args = parser.parse_args(argv)

    if getattr(args, "print_completion", None):
        from secscan.cli_completions import write_completion_script

        write_completion_script(sys.stdout, parser, args.print_completion)
        raise SystemExit(0)

    configure_cli_output(quiet=bool(getattr(args, "quiet", False)))

    if getattr(args, "config_dry_run", False):
        from secscan.cli_config_dry_run import print_effective_config

        if getattr(args, "ci_profile", False):
            from secscan.ci_profile import apply_ci_profile_to_args

            apply_ci_profile_to_args(args)
        if getattr(args, "network_mode", "default") not in ("default", None):
            from secscan.network_posture import apply_network_mode_to_args

            apply_network_mode_to_args(args)
        print_effective_config(args, explicit_config=args.config)
        raise SystemExit(0)

    if getattr(args, "doctor", False):
        from secscan.tool_doctor import run_doctor_subcommand

        # Fast default for CI-style gates; `security-scan doctor` alone uses full profile (see tool_doctor).
        raise SystemExit(run_doctor_subcommand(["--profile", "ci-minimal"]))

    if args.resume and args.no_checkpoint:
        parser.error("--resume cannot be used with --no-checkpoint")

    if args.config and not Path(args.config).expanduser().is_file():
        warn(f"Config file not found: {args.config}")
    _log_path = Path(args.log_file).expanduser() if args.log_file else None
    if _log_path:
        try:
            _log_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            warn(f"Could not create log file directory — {e}")
            _log_path = None
    configure_secscan_logger(
        setup_logging(
            verbose=args.verbose,
            log_json=args.log_json,
            log_file=_log_path,
        )
    )

    if getattr(args, "ci_profile", False):
        from secscan.ci_profile import apply_ci_profile_to_args

        apply_ci_profile_to_args(args)
        info("CI profile — merged skips, technical report tier, fail_on=high if was never (see CI_AND_GATES.md)")

    if getattr(args, "network_mode", "default") not in ("default", None):
        from secscan.network_posture import apply_network_mode_to_args

        apply_network_mode_to_args(args)
        info(f"Network mode {args.network_mode!r} — merged recommended skips (see NETWORK_MODE.md)")

    auth_clear()
    scan_path = str(Path(args.path).resolve())
    workspace = Path(args.workspace).resolve()
    resuming = bool(args.resume) and not args.no_checkpoint
    if resuming:
        try:
            run_id = _validate_run_id(args.resume)
        except ValueError as e:
            fail(f"Resume — {e}")
            sys.exit(1)
    else:
        raw_run = args.run_id or _default_run_id(scan_path, args.url)
        try:
            run_id = _validate_run_id(raw_run)
        except ValueError as e:
            fail(f"run-id — {e}")
            sys.exit(1)

    print(f"\n{BOLD}Security Suite Orchestrator{RESET}")
    print(f"  Target path : {scan_path}")
    print(f"  Target URL  : {args.url or 'not set (DAST skipped)'}")
    print(f"  AI model    : {args.ai_model}")
    print(f"  Auth config : {args.auth_config or 'none'}")
    print(f"  Chain config: {args.chain_config or 'none'}")
    print(f"  Workspace   : {workspace}")
    print(f"  Run id      : {run_id}" + ("  [resume]" if resuming else ""))
    print(f"  Checkpoint  : {'off' if args.no_checkpoint else 'on'}")
    print(f"  Output JSON : {args.output}")
    print(f"  Output HTML : {args.html}")

    phases: dict = {}
    ai_result: dict = {}
    phase_timings: dict[str, Any] = {}
    completed: set[str] = set()
    resume_ck: dict | None = None

    if resuming:
        try:
            ck_p = _checkpoint_path(workspace, run_id)
        except ValueError as e:
            fail(f"Resume — {e}")
            sys.exit(1)
        if not ck_p.is_file():
            fail(f"Checkpoint not found: {ck_p}")
            sys.exit(1)
        try:
            resume_ck = _checkpoint_read(ck_p)
        except ValueError as e:
            fail(str(e))
            sys.exit(1)
        err = _validate_resume(
            resume_ck,
            scan_path,
            args.url,
            args.auth_config,
            args.chain_config,
        )
        if err:
            fail(f"Resume — {err}")
            sys.exit(1)
        phases = resume_ck.get("phases") or {}
        if not isinstance(phases, dict):
            phases = {}
        ar = resume_ck.get("ai_reasoning")
        ai_result = ar if isinstance(ar, dict) else {}
        completed = set(resume_ck.get("completed") or [])
        _restore_session_from_phases(phases)
        # Hardened checkpoints omit live cookies; re-run auth/chain so later phases have a session.
        from secscan.http_session import has_session_credentials

        if not has_session_credentials():
            for pkey in ("auth", "chain"):
                if pkey in completed:
                    completed.discard(pkey)
                    phases.pop(pkey, None)
            if args.auth_config or args.chain_config:
                info("Resume — re-running auth/chain (credentials are not stored in checkpoints)")
        info(f"Resuming — loaded {len(completed)} completed phase(s) from checkpoint")
        if resume_ck.get("ai_model") and resume_ck["ai_model"] != args.ai_model:
            warn(
                f"AI model differs from checkpoint ({resume_ck['ai_model']!r} vs {args.ai_model!r})"
            )

    def save_ck() -> None:
        if args.no_checkpoint:
            return
        meta = {
            "version": _CHECKPOINT_VERSION,
            "scan_path": scan_path,
            "target_url": args.url,
            "auth_config": args.auth_config,
            "chain_config": args.chain_config,
            "ai_model": args.ai_model,
            "completed": sorted(completed),
            "phases": phases,
            "ai_reasoning": ai_result,
        }
        p = _checkpoint_write(workspace, run_id, meta)
        info(f"Checkpoint saved → {p}")

    def has_restored(pkey: str, dkey: str | None) -> bool:
        if not resuming or pkey not in completed:
            return False
        if pkey == "ai":
            return True
        return bool(dkey and dkey in phases)

    def _mark_phase(name: str, t0: float, iso: str) -> None:
        phase_timings[name] = {
            "started_at": iso,
            "duration_ms": max(0, int((time.perf_counter() - t0) * 1000)),
        }

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("code_ai", "ai_code"):
        info("Phase 0.5 — AI Code Analysis (from checkpoint)")
    elif "code_ai" in args.skip:
        header("Phase 0.5 — AI Code Analysis (Local Ollama)")
        warn("Skipped — 'code_ai' in --skip list.")
    else:
        phases["ai_code"] = {"threat_model": phase_ai_code_analysis(scan_path, args.ai_model)}
        completed.add("code_ai")
        save_ck()
    _mark_phase("code_ai", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("secrets", "secrets"):
        info("Phase — Secrets scan (from checkpoint)")
    elif "secrets" not in args.skip:
        phases["secrets"] = phase_secrets(scan_path)
        completed.add("secrets")
        save_ck()
    _mark_phase("secrets", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("sast", "sast"):
        info("Phase — SAST (from checkpoint)")
    elif "sast" not in args.skip:
        phases["sast"] = phase_sast(scan_path)
        completed.add("sast")
        save_ck()
    _mark_phase("sast", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("deps", "deps"):
        info("Phase — Dependencies (from checkpoint)")
    elif "deps" not in args.skip:
        phases["deps"] = phase_dependencies(scan_path)
        completed.add("deps")
        save_ck()
    _mark_phase("deps", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("recon", "recon"):
        info("Phase 0 — Reconnaissance (from checkpoint)")
    elif "recon" not in args.skip:
        if args.url:
            phases["recon"] = phase_recon(args.url)
            completed.add("recon")
            save_ck()
        else:
            header("Phase 0 — Reconnaissance")
            warn("Skipped — no --url provided. Pass --url http://localhost:8080 to enable.")
    _mark_phase("recon", _t, _iso)

    if args.auth_config:
        _t = time.perf_counter()
        _iso = datetime.datetime.now().isoformat()
        if has_restored("auth", "auth"):
            info("Phase 2 — Authenticated Session (from checkpoint)")
        elif "auth" not in args.skip:
            if args.url:
                try:
                    acfg = load_auth_config(args.auth_config)
                    phases["auth"] = {"session": phase_auth_session(args.url, acfg)}
                    completed.add("auth")
                    save_ck()
                except FileNotFoundError as e:
                    fail(f"Auth — {e}")
                except Exception as e:
                    fail(f"Auth — {e}")
            else:
                header("Phase 2 — Authenticated Session")
                warn("--auth-config requires --url")
        _mark_phase("auth", _t, _iso)

    if args.chain_config:
        _t = time.perf_counter()
        _iso = datetime.datetime.now().isoformat()
        if has_restored("chain", "chain"):
            info("Phase 3 — Request Chain (from checkpoint)")
        elif "chain" not in args.skip:
            if args.url:
                try:
                    ccfg = load_chain_config(args.chain_config)
                    phases["chain"] = {"chain": phase_request_chain(args.url, ccfg)}
                    completed.add("chain")
                    save_ck()
                except FileNotFoundError as e:
                    fail(f"Chain — {e}")
                except Exception as e:
                    fail(f"Chain — {e}")
            else:
                header("Phase 3 — Request Chain")
                warn("--chain-config requires --url")
        _mark_phase("chain", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("dast", "dast"):
        info("Phase 4 — DAST (from checkpoint)")
    elif "dast" not in args.skip:
        if args.url:
            phases["dast"] = phase_dast(args.url, phases)
            completed.add("dast")
            save_ck()
        else:
            header("Phase 4 — Dynamic Analysis (DAST)")
            warn("Skipped — no --url provided. Pass --url http://localhost:8080 to enable.")
    _mark_phase("dast", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("browser", "browser"):
        info("Phase 4b — Browser Automation (from checkpoint)")
    elif "browser" not in args.skip:
        if args.url:
            phases["browser"] = phase_browser(args.url, phases)
            completed.add("browser")
            save_ck()
        else:
            header("Phase 4b — Browser Automation (Playwright)")
            warn("Skipped — no --url provided. Pass --url http://localhost:8080 to enable.")
    _mark_phase("browser", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("zap", "zap"):
        info("Phase 4c — OWASP ZAP (from checkpoint)")
    elif "zap" not in args.skip:
        if args.url:
            phases["zap"] = phase_zap(args.url)
            completed.add("zap")
            save_ck()
        else:
            header("Phase 4c — OWASP ZAP (Proxy DAST)")
            warn("Skipped — no --url provided. Pass --url http://localhost:8080 to enable.")
    _mark_phase("zap", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("agents", "specialized"):
        info("Phase 5b — Specialized Agents (from checkpoint)")
    elif "agents" not in args.skip:
        if args.url:
            phases["specialized"] = phase_specialized_agents(args.url, scan_path, phases)
            completed.add("agents")
            save_ck()
        else:
            header("Phase 5b — Specialized Attack Domain Agents")
            warn("Skipped — no --url provided. Pass --url http://localhost:8080 to enable.")
    _mark_phase("agents", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("exploit", "exploit"):
        info("Phase 5 — PoC Exploitation (from checkpoint)")
    elif "exploit" not in args.skip:
        if args.url:
            phases["exploit"] = phase_exploit(args.url, phases)
            completed.add("exploit")
            save_ck()
        else:
            header("Phase 5 — PoC Exploitation")
            warn("Skipped — no --url provided. Pass --url http://localhost:8080 to enable.")
    _mark_phase("exploit", _t, _iso)

    _t = time.perf_counter()
    _iso = datetime.datetime.now().isoformat()
    if has_restored("ai", None):
        info("Phase 6 — AI Reasoning (from checkpoint)")
    elif "ai" not in args.skip:
        ai_result = phase_ai_reasoning(phases, model=args.ai_model)
        completed.add("ai")
        save_ck()
    else:
        header("Phase 6 — AI Reasoning (Local Ollama)")
        warn("Skipped — 'ai' in --skip list.")
    _mark_phase("ai", _t, _iso)

    report = build_report(scan_path, args.url, phases)
    report["ai_reasoning"] = ai_result
    report["phase_timings"] = phase_timings
    report["correlation_hints"] = build_correlation_hints(phases)
    report["_output_path"] = args.output
    report["_html_path"] = args.html
    report["_run_id"] = run_id
    report["_workspace"] = str(workspace)
    _rt = normalize_report_tier(getattr(args, "report_tier", None))
    report["report_tier"] = _rt
    report["report_policy"] = build_report_policy_embed(_rt)

    baseline_fps: set[str] = set()
    if args.baseline:
        try:
            baseline_fps = load_baseline_fingerprints(args.baseline)
            info(f"Baseline — {len(baseline_fps)} fingerprint(s) loaded from {args.baseline}")
        except (OSError, json.JSONDecodeError) as e:
            fail(f"Baseline — {e}")
            sys.exit(1)

    _inc = tuple(getattr(args, "include_globs", None) or ())
    _exc = tuple(getattr(args, "exclude_globs", None) or ())
    _path_scope = (Path(scan_path), _inc, _exc) if (_inc or _exc) else None
    unified_all, unified_gate, n_suppressed = apply_unified_findings_to_report(
        report, baseline_fps, path_scope=_path_scope
    )
    if args.baseline:
        report["baseline_path"] = str(Path(args.baseline).resolve())

    if args.emit_baseline_suggestions:
        sugg_path = Path(args.emit_baseline_suggestions).expanduser()
        try:
            sugg_path.parent.mkdir(parents=True, exist_ok=True)
            fps = [str(f.get("correlation_id", "")) for f in unified_all if f.get("correlation_id")]
            detail = [
                {
                    "correlation_id": f.get("correlation_id"),
                    "phase": f.get("phase"),
                    "tool": f.get("tool"),
                    "type": f.get("type"),
                    "severity": f.get("severity"),
                    "location": f.get("location"),
                }
                for f in unified_all[:2000]
            ]
            sugg_path.write_text(
                json.dumps(
                    {
                        "fingerprints": fps,
                        "details": detail,
                        "note": "Copy selected hex strings into baseline JSON to suppress known noise.",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            info(f"Baseline suggestions → {sugg_path} ({len(fps)} fingerprint(s))")
        except OSError as e:
            warn(f"Baseline suggestions — could not write: {e}")

    report["run_manifest"] = build_run_manifest(
        scan_path, args, workspace=workspace, run_id=run_id
    )

    exit_code, exit_reason = _assess_fail_on(
        report, args.fail_on, unified_filtered=unified_gate
    )
    report["_exit_code"] = exit_code
    report["_fail_on_policy"] = args.fail_on
    if exit_reason:
        report["_fail_on_reason"] = exit_reason

    report["auditability"] = build_auditability_embed(
        report,
        args,
        suppressed_baseline_count=n_suppressed,
        unified_after_baseline_count=len(unified_gate),
        exit_code=exit_code,
        exit_reason=exit_reason or "",
    )
    report["safe_operations"] = build_safe_operations_embed(args, scan_path)

    # Always strip live session secrets from on-disk reports; optional deeper redaction next.
    disk_report = strip_session_secrets(report)
    if args.sanitize_exports:
        disk_report = sanitize_report_copy(disk_report)
    output_path = Path(args.output)
    output_path.write_text(json.dumps(disk_report, indent=2, default=str), encoding="utf-8")
    _out_abs = output_path.expanduser().resolve()

    if args.audit_log_jsonl:
        try:
            from secscan.audit_integrity import append_audit_jsonl, sha256_file

            _aud = disk_report.get("auditability") or report.get("auditability") or {}
            _base = _aud.get("baseline") if isinstance(_aud, dict) else {}
            _pol = _aud.get("policy_outcome") if isinstance(_aud, dict) else {}
            append_audit_jsonl(
                Path(args.audit_log_jsonl).expanduser(),
                {
                    "event": "scan_complete",
                    "orchestrator_version": ORCHESTRATOR_VERSION,
                    "report_path": str(_out_abs),
                    "report_sha256": sha256_file(_out_abs),
                    "report_tier": getattr(args, "report_tier", "full"),
                    "exit_code": exit_code,
                    "fail_on": args.fail_on,
                    "fail_reason": exit_reason or "",
                    "scan_path": scan_path,
                    "baseline_path_sha256": (_base or {}).get("path_sha256"),
                    "baseline_file_content_sha256": (_base or {}).get("file_content_sha256"),
                    "suppressed_by_baseline": (_pol or {}).get("suppressed_by_baseline"),
                    "unified_findings_after_baseline": (_pol or {}).get(
                        "unified_findings_after_baseline"
                    ),
                    "ci_profile": bool(getattr(args, "ci_profile", False)),
                    "sarif_source": getattr(args, "sarif_source", "tool_native"),
                    "auditability_schema_version": (_aud or {}).get("schema_version"),
                },
            )
            info(f"Audit log appended → {args.audit_log_jsonl}")
        except OSError as e:
            warn(f"Audit log — {e}")

    if getattr(args, "hmac_sign_report", False):
        from secscan.audit_integrity import load_hmac_key_from_env_or_file, write_hmac_sidecar

        _key = load_hmac_key_from_env_or_file(getattr(args, "report_hmac_key_file", None))
        if _key:
            try:
                sc = write_hmac_sidecar(_out_abs, _key)
                info(f"HMAC sidecar → {sc}")
            except OSError as e:
                warn(f"HMAC sidecar — {e}")
        else:
            warn("HMAC signing skipped — set SECURITY_SCAN_REPORT_HMAC_KEY or --report-hmac-key-file")

    if args.replay_bundle_output:
        try:
            rb_path = Path(args.replay_bundle_output).expanduser()
            rb_path.parent.mkdir(parents=True, exist_ok=True)
            rm = disk_report.get("run_manifest") or report.get("run_manifest") or {}
            rb = rm.get("replay_bundle") or {}
            rb_path.write_text(
                json.dumps(
                    {
                        "orchestrator_version": rm.get("orchestrator_version"),
                        "replay_bundle": rb,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            info(f"Replay bundle → {rb_path}")
        except OSError as e:
            warn(f"Replay bundle — could not write: {e}")

    sarif_result_count: int | None = None
    if args.sarif_output:
        try:
            sarif_result_count = generate_sarif_report(
                report,
                args.sarif_output,
                sarif_source=getattr(args, "sarif_source", "tool_native"),
                unified_findings=unified_gate,
            )
        except OSError as e:
            warn(f"SARIF — could not write: {e}")

    if args.junit_output:
        try:
            jp = Path(args.junit_output).expanduser()
            jp.parent.mkdir(parents=True, exist_ok=True)
            n_conf = len(
                (phases.get("exploit") or {}).get("exploit", {}).get("confirmed") or []
            )
            write_junit_report(
                str(jp),
                suite_name="security_suite_orchestrator",
                exit_code=exit_code,
                fail_on=args.fail_on,
                fail_reason=exit_reason or "",
                unified_after_baseline=len(unified_gate),
                exploit_confirmed=n_conf,
                extra_properties={
                    "sarif_source": getattr(args, "sarif_source", "tool_native"),
                    "sarif_result_count": ""
                    if sarif_result_count is None
                    else str(sarif_result_count),
                    "ci_profile": str(bool(getattr(args, "ci_profile", False))),
                    "orchestrator_version": ORCHESTRATOR_VERSION,
                    "report_schema_compat_version": REPORT_SCHEMA_COMPAT_VERSION,
                    "correlation_join_rules_version": CORRELATION_JOIN_RULES_VERSION,
                },
            )
        except OSError as e:
            warn(f"JUnit — could not write: {e}")

    html_pdf_src = strip_session_secrets(report)
    if args.sanitize_exports:
        html_pdf_src = sanitize_report_copy(html_pdf_src)
    generate_html_report(html_pdf_src, args.html)
    generate_pdf_report(html_pdf_src, args.pdf)

    print_final_summary(report)

    if args.notify_webhook and _should_send_notification(
        report, args.notify_on, unified_filtered=unified_gate
    ):
        _post_notification_webhook(
            args.notify_webhook,
            report,
            {
                "notify_on": args.notify_on,
                "fail_on": args.fail_on,
                "policy_failed": exit_code != 0,
                "reason": exit_reason or "",
            },
        )

    sp = phases.get("auth", {}).get("session", {}).get("storage_state")
    if sp and Path(sp).exists():
        try:
            os.unlink(sp)
        except OSError:
            pass
    auth_clear()

    if (
        exit_code == 0
        and getattr(args, "wipe_run_dir", False)
        and not args.no_checkpoint
        and not resuming
        and run_id
    ):
        try:
            run_dir = _resolve_run_dir(workspace, run_id)
        except ValueError as e:
            warn(f"Wipe run dir — refused unsafe run id: {e}")
            run_dir = None
        if run_dir is not None and run_dir.is_dir():
            try:
                shutil.rmtree(run_dir)
                info(f"Removed run directory — {run_dir}")
            except OSError as e:
                warn(f"Wipe run dir — could not remove {run_dir}: {e}")

    if exit_code == 0 and getattr(args, "wipe_temp", False):
        from secscan.temp_registry import wipe_registered_temp_paths

        n_removed, terr = wipe_registered_temp_paths()
        if n_removed:
            info(f"Removed {n_removed} registered temp file(s)")
        for msg in terr[:5]:
            warn(f"Wipe temp — {msg}")

    if exit_reason and exit_code:
        warn(exit_reason)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
