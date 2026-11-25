"""Load JSON/TOML config files for auth and chain phases."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

try:
    import tomllib
except ImportError:
    tomllib = None  # type: ignore[misc, assignment]

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def interpolate_secret_refs(
    obj: Any,
    *,
    env: Mapping[str, str] | None = None,
) -> Any:
    """
    Resolve ``${ENV_VAR}`` placeholders in strings (recursively).

    Use ``${ENV_VAR:-default}`` for optional values (empty default is allowed).
    Missing required variables raise ``ValueError`` so misconfigured auth fails
    closed instead of sending literal ``${...}`` to a login form.
    """
    environ = env if env is not None else os.environ

    def _resolve_str(s: str) -> str:
        def repl(m: re.Match[str]) -> str:
            key = m.group(1)
            has_default = m.group(0).find(":-") != -1
            default = m.group(2) if has_default else None
            if key in environ:
                return environ[key]
            if has_default:
                return default or ""
            raise ValueError(
                f"secret reference ${{{key}}} is not set in the environment"
            )

        return _ENV_REF.sub(repl, s)

    if isinstance(obj, str):
        return _resolve_str(obj)
    if isinstance(obj, dict):
        return {k: interpolate_secret_refs(v, env=environ) for k, v in obj.items()}
    if isinstance(obj, list):
        return [interpolate_secret_refs(x, env=environ) for x in obj]
    return obj


def load_json_or_toml(path: str) -> dict:
    """Load a JSON or TOML object from disk."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    raw = p.read_text(encoding="utf-8")
    suf = p.suffix.lower()
    if suf in (".toml", ".tml"):
        if tomllib is None:
            raise RuntimeError("TOML config requires Python 3.11+ (tomllib)")
        data = tomllib.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("TOML root must be a table/object")
        return data
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object")
    return data


def load_auth_config(path: str) -> dict:
    """Load JSON or TOML auth profile and resolve ``${ENV_VAR}`` secret refs."""
    return interpolate_secret_refs(load_json_or_toml(path))


def load_chain_config(path: str) -> dict:
    """Load JSON or TOML Phase 3 request chain (with ``${ENV_VAR}`` resolution)."""
    return interpolate_secret_refs(load_json_or_toml(path))
