"""
Canonical model for external tool subprocess outcomes.

Phases should attach a `run` object to each tool dict so `phase_status` and
downstream consumers see one shape: { code, message, exit_code }.
Legacy `error` / `status` keys remain for backward compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secscan.tool_run_types import ToolRunPayload

# Aligned with secscan.subprocess_runner / tool_adapters.runner
EXIT_NOT_FOUND = -1
EXIT_TIMEOUT = -2

RUN_OK = "OK"
RUN_BINARY_NOT_FOUND = "BINARY_NOT_FOUND"
RUN_TIMEOUT = "TIMEOUT"
RUN_NONZERO_EXIT = "NONZERO_EXIT"
RUN_SETUP_FAILED = "SETUP_FAILED"
RUN_UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ToolRunOutcome:
    ok: bool
    code: str
    message: str = ""
    exit_code: int | None = None


def outcome_from_exit_code(
    exit_code: int,
    *,
    stderr_hint: str = "",
) -> ToolRunOutcome:
    """Map orchestrator subprocess exit codes to a stable run code."""
    if exit_code == EXIT_NOT_FOUND:
        return ToolRunOutcome(
            False,
            RUN_BINARY_NOT_FOUND,
            (stderr_hint or "command not found").strip() or "command not found",
            exit_code,
        )
    if exit_code == EXIT_TIMEOUT:
        return ToolRunOutcome(
            False,
            RUN_TIMEOUT,
            (stderr_hint or "timeout").strip() or "timeout",
            exit_code,
        )
    if exit_code == 0:
        return ToolRunOutcome(True, RUN_OK, "", 0)
    return ToolRunOutcome(
        False,
        RUN_NONZERO_EXIT,
        (stderr_hint or f"exit {exit_code}").strip(),
        exit_code,
    )


def outcome_setup_failed(message: str) -> ToolRunOutcome:
    return ToolRunOutcome(False, RUN_SETUP_FAILED, message, None)


def attach_run_payload(
    tool_dict: dict[str, Any],
    outcome: ToolRunOutcome,
    *,
    propagate_legacy_error: bool = True,
) -> dict[str, Any]:
    """
    Mutate tool_dict in place: set `run` (always) and `ok`.

    If propagate_legacy_error is True and outcome is not ok, set legacy `error` / `status`
    for phase_status. Set propagate_legacy_error False when the tool returned usable
    results despite a non-zero exit (e.g. nuclei findings present).
    """
    tool_dict["ok"] = outcome.ok
    payload: ToolRunPayload = {
        "code": outcome.code,
        "message": outcome.message[:2000] if outcome.message else "",
        "exit_code": outcome.exit_code,
    }
    tool_dict["run"] = payload
    if not outcome.ok and propagate_legacy_error:
        tool_dict["error"] = outcome.message or outcome.code
        tool_dict["status"] = "error"
    elif outcome.ok or not propagate_legacy_error:
        tool_dict.pop("error", None)
        if tool_dict.get("status") == "error":
            tool_dict.pop("status", None)
    return tool_dict
