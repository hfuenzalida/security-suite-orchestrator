"""Optional security_scan.toml + SECURITY_SCAN_* environment defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from secscan.constants import ENV_PREFIX

try:
    import tomllib
except ImportError:
    tomllib = None  # type: ignore[misc, assignment]


def _env_bool(key: str) -> bool | None:
    v = os.environ.get(key)
    if v is None:
        return None
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_str(key: str) -> str | None:
    v = os.environ.get(key)
    return v.strip() if v else None


def load_toml_defaults(path: Path) -> dict[str, Any]:
    if not path.is_file() or tomllib is None:
        return {}
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    defaults = data.get("defaults") or {}
    paths = data.get("paths") or {}
    out: dict[str, Any] = {}
    if isinstance(defaults, dict):
        keymap = {
            "ai_model": "ai_model",
            "workspace": "workspace",
            "path": "path",
            "url": "url",
            "fail_on": "fail_on",
            "verbose": "verbose",
            "log_json": "log_json",
            "skip": "skip",
            "report_tier": "report_tier",
            "sarif_source": "sarif_source",
            "quiet": "quiet",
        }
        for a, b in keymap.items():
            if a in defaults:
                out[b] = defaults[a]
    if isinstance(paths, dict):
        if "zap_bat" in paths:
            os.environ.setdefault("SECURITY_SCAN_ZAP_BAT", str(paths["zap_bat"]))
        if "nmap" in paths:
            os.environ.setdefault("SECURITY_SCAN_NMAP", str(paths["nmap"]))
    timeouts = data.get("timeouts")
    if isinstance(timeouts, dict):
        for k, v in timeouts.items():
            try:
                iv = int(v)
                if iv > 0:
                    env_k = f"{ENV_PREFIX}TIMEOUT_{str(k).upper().replace('-', '_')}"
                    os.environ.setdefault(env_k, str(iv))
            except (TypeError, ValueError):
                pass
    ci = data.get("ci") or {}
    if isinstance(ci, dict) and ci.get("profile"):
        out["ci_profile"] = True
    return out


def env_defaults() -> dict[str, Any]:
    """Map SECURITY_SCAN_* env vars to argparse destination names."""
    out: dict[str, Any] = {}
    m = (
        ("AI_MODEL", "ai_model"),
        ("WORKSPACE", "workspace"),
        ("PATH", "path"),
        ("URL", "url"),
        ("FAIL_ON", "fail_on"),
        ("OUTPUT", "output"),
        ("HTML", "html"),
        ("PDF", "pdf"),
        ("AI_MODEL", "ai_model"),
        ("AUTH_CONFIG", "auth_config"),
        ("CHAIN_CONFIG", "chain_config"),
        ("SARIF_OUTPUT", "sarif_output"),
        ("BASELINE", "baseline"),
        ("LOG_FILE", "log_file"),
        ("JUNIT_OUTPUT", "junit_output"),
        ("EMIT_BASELINE_SUGGESTIONS", "emit_baseline_suggestions"),
        ("REPORT_TIER", "report_tier"),
        ("AUDIT_LOG_JSONL", "audit_log_jsonl"),
        ("SARIF_SOURCE", "sarif_source"),
    )
    for ek, dest in m:
        v = _env_str(f"{ENV_PREFIX}{ek}")
        if v is not None:
            out[dest] = v
    vb = _env_bool(f"{ENV_PREFIX}VERBOSE")
    if vb is not None:
        out["verbose"] = vb
    lj = _env_bool(f"{ENV_PREFIX}LOG_JSON")
    if lj is not None:
        out["log_json"] = lj
    san = _env_bool(f"{ENV_PREFIX}SANITIZE_EXPORTS")
    if san is not None:
        out["sanitize_exports"] = san
    cp = _env_bool(f"{ENV_PREFIX}CI_PROFILE")
    if cp is not None:
        out["ci_profile"] = cp
    rpf = _env_bool(f"{ENV_PREFIX}REPLAY_PIP_FREEZE")
    if rpf is not None:
        out["replay_include_pip_freeze"] = rpf
    nm = _env_str(f"{ENV_PREFIX}NETWORK_MODE")
    if nm:
        out["network_mode"] = nm.strip()
    ig = _env_str(f"{ENV_PREFIX}INCLUDE_GLOBS")
    if ig:
        out["include_globs"] = [x.strip() for x in ig.split(",") if x.strip()]
    eg = _env_str(f"{ENV_PREFIX}EXCLUDE_GLOBS")
    if eg:
        out["exclude_globs"] = [x.strip() for x in eg.split(",") if x.strip()]
    qb = _env_bool(f"{ENV_PREFIX}QUIET")
    if qb is not None:
        out["quiet"] = qb
    return out


def discover_config_file(explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit).expanduser()
    env_p = _env_str(f"{ENV_PREFIX}CONFIG")
    if env_p:
        return Path(env_p).expanduser()
    for name in ("security_scan.toml", "secscan.toml"):
        p = Path(name)
        if p.is_file():
            return p
    return None


def merged_arg_defaults(config_path: str | None = None) -> dict[str, Any]:
    """Defaults to pass to parser.set_defaults() — lowest priority: TOML, then env."""
    out: dict[str, Any] = {}
    path = discover_config_file(config_path)
    if path and path.is_file():
        out.update(load_toml_defaults(path))
    out.update(env_defaults())
    return out

