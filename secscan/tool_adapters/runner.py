"""
Shell-out runner with retries for flaky integrations (timeouts only).

Pair with versioned JSON adapters in this package; see DISCIPLINE_ENGINEERING_GAPS.md.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from secscan.subprocess_runner import run as _run_once

# Must stay aligned with secscan.subprocess_runner.run return codes
EXIT_NOT_FOUND = -1
EXIT_TIMEOUT = -2


@dataclass(frozen=True)
class RunMetadata:
    """Telemetry for one logical tool invocation (may include retries)."""

    attempts: int
    elapsed_ms_total: float
    retried: bool
    exit_code: int

    def as_integration_dict(self, adapter_id: str) -> dict[str, Any]:
        return {
            "adapter": adapter_id,
            "attempts": self.attempts,
            "elapsed_ms": round(self.elapsed_ms_total, 2),
            "retried": self.retried,
            "exit_code": self.exit_code,
        }


def run_with_retries(
    cmd: list[str],
    *,
    timeout: int,
    max_attempts: int = 2,
    backoff_seconds: float = 1.25,
) -> tuple[int, str, str, RunMetadata]:
    """
    Run an external command; retry only on timeout (exit code EXIT_TIMEOUT).

    Missing binaries (EXIT_NOT_FOUND) and non-timeout failures are not retried.
    """
    if max_attempts < 1:
        max_attempts = 1

    total_ms = 0.0
    last_code = EXIT_NOT_FOUND
    last_out = ""
    last_err = ""
    attempts_used = 0
    retried = False

    for attempt in range(1, max_attempts + 1):
        attempts_used = attempt
        t0 = time.perf_counter()
        last_code, last_out, last_err = _run_once(cmd, timeout=timeout)
        total_ms += (time.perf_counter() - t0) * 1000

        if last_code != EXIT_TIMEOUT or attempt >= max_attempts:
            break
        retried = True
        time.sleep(backoff_seconds * attempt)

    meta = RunMetadata(
        attempts=attempts_used,
        elapsed_ms_total=total_ms,
        retried=retried,
        exit_code=last_code,
    )
    return last_code, last_out, last_err, meta
