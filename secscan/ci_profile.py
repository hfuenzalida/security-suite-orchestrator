"""Preset for CI pipelines: faster phases + gate-friendly defaults."""

from __future__ import annotations

import argparse

# Phases to skip for a typical static+deps+SAST+DAST(nuclei) CI job (no browser lab, no PoC lab).
CI_EXTRA_SKIP: frozenset[str] = frozenset({
    "code_ai",
    "recon",
    "browser",
    "zap",
    "agents",
    "exploit",
    "ai",
})


def apply_ci_profile_to_args(args: argparse.Namespace) -> None:
    """
    Merge CI skip list, set technical report tier, and upgrade fail_on from never→high
    when the operator did not choose a stricter policy.
    """
    cur = set(getattr(args, "skip", None) or [])
    cur |= set(CI_EXTRA_SKIP)
    args.skip = sorted(cur)
    args.report_tier = "technical"
    if getattr(args, "fail_on", "never") == "never":
        args.fail_on = "high"
