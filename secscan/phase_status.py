"""Normalize per-phase outcomes for programmatic consumers (report['phase_status'])."""

from __future__ import annotations

from typing import Any

_OK_RUN_CODES = frozenset(("", "OK", "ok"))


def _tool_entry_has_fault(data: dict[str, Any]) -> bool:
    """True if this tool payload should surface as a phase-level fault."""
    if data.get("ok") is True:
        return False
    if data.get("status") == "passed":
        return False
    if data.get("error"):
        return True
    st = data.get("status")
    if st == "error":
        return True
    if st == "failed":
        return True
    run = data.get("run")
    if isinstance(run, dict):
        code = run.get("code")
        if code is not None and str(code).upper() not in _OK_RUN_CODES:
            return True
    if data.get("ok") is False:
        return True
    return False


def summarize_phases(phases: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Build a coarse {phase_name: {ok, errors[], tool_summaries{}}} from nested phase dicts.
    Phases store heterogeneous tool payloads; we surface explicit 'error' keys and empty counts.
    """
    summary: dict[str, dict[str, Any]] = {}
    for phase_name, tools in phases.items():
        if not isinstance(tools, dict):
            continue
        errors: list[str] = []
        tool_summaries: dict[str, Any] = {}
        ok = True
        for tool_name, data in tools.items():
            if not isinstance(data, dict):
                continue
            fault = _tool_entry_has_fault(data)
            err = data.get("error")
            if fault:
                ok = False
                if err:
                    errors.append(f"{tool_name}: {err}")
                elif isinstance(data.get("run"), dict) and data["run"].get("code"):
                    errors.append(
                        f"{tool_name}: {data['run'].get('code')} "
                        f"({data['run'].get('message', '')})"
                    )
                else:
                    errors.append(f"{tool_name}: fault")
            tool_summaries[tool_name] = {
                "count": data.get("count", 0),
                "has_error": fault,
                "run_code": (data.get("run") or {}).get("code") if isinstance(data.get("run"), dict) else None,
            }
        summary[phase_name] = {
            "ok": ok,
            "errors": errors,
            "tools": tool_summaries,
        }
    return summary
