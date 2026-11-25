"""CLI network posture presets: merge recommended --skip lists (see NETWORK_MODE.md)."""

from __future__ import annotations

import argparse

# Extra phases to skip for reduced outbound / offline-static analysis.
MINIMAL_OUTBOUND_SKIP: frozenset[str] = frozenset({"recon"})
OFFLINE_STATIC_SKIP: frozenset[str] = frozenset({"recon", "code_ai", "ai"})


def apply_network_mode_to_args(args: argparse.Namespace) -> None:
    """
    Union recommended skips into args.skip. Idempotent per extra set.
    default: no-op. minimal-outbound: recon. offline-static: recon + code_ai + ai.
    """
    mode = getattr(args, "network_mode", "default") or "default"
    if mode == "default":
        return
    if mode == "minimal-outbound":
        extra = MINIMAL_OUTBOUND_SKIP
    elif mode == "offline-static":
        extra = OFFLINE_STATIC_SKIP
    else:
        return
    cur = set(getattr(args, "skip", None) or [])
    cur |= set(extra)
    args.skip = sorted(cur)
