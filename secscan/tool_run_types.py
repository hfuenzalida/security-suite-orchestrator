"""Typed shapes for tool `run` payloads (maintainability / static checks)."""

from __future__ import annotations

from typing import TypedDict


class ToolRunPayload(TypedDict):
    """Shape of `tool_dict[\"run\"]` after attach_run_payload."""

    code: str
    message: str
    exit_code: int | None
