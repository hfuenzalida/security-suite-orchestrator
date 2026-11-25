"""
External tool lists per CI install profile — keeps `check_security_tools.py` and docs aligned.

* **ci-minimal** — pip-installable CLIs enough for a typical `--ci-profile` static+deps+secrets gate on GitHub-hosted runners (no nuclei/ZAP/recon binaries).
* **ci-extended** — adds API fuzzing + common DAST/secret binaries teams often install on self-hosted agents.
* **full** — every tool the orchestrator can invoke (lab / pentest / full scan).
"""

from __future__ import annotations

from dataclasses import dataclass

PROFILE_CI_MINIMAL = "ci-minimal"
PROFILE_CI_EXTENDED = "ci-extended"
PROFILE_FULL = "full"

PROFILE_CHOICES: tuple[str, ...] = (PROFILE_CI_MINIMAL, PROFILE_CI_EXTENDED, PROFILE_FULL)


@dataclass(frozen=True)
class ToolSpec:
    """One executable checked with `cmd` (must return quickly)."""

    key: str
    cmd: list[str]
    profiles: frozenset[str]


def _p(*names: str) -> frozenset[str]:
    return frozenset(names)


# Order preserved for human-readable `check_security_tools.py` output.
_TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec("semgrep", ["semgrep", "--version"], _p(PROFILE_CI_MINIMAL, PROFILE_CI_EXTENDED, PROFILE_FULL)),
    ToolSpec("bandit", ["bandit", "--version"], _p(PROFILE_CI_MINIMAL, PROFILE_CI_EXTENDED, PROFILE_FULL)),
    ToolSpec("pip-audit", ["pip-audit", "--version"], _p(PROFILE_CI_MINIMAL, PROFILE_CI_EXTENDED, PROFILE_FULL)),
    ToolSpec("detect-secrets", ["detect-secrets", "--version"], _p(PROFILE_CI_MINIMAL, PROFILE_CI_EXTENDED, PROFILE_FULL)),
    ToolSpec("safety", ["safety", "--version"], _p(PROFILE_CI_EXTENDED, PROFILE_FULL)),
    ToolSpec("schemathesis", ["schemathesis", "--version"], _p(PROFILE_CI_EXTENDED, PROFILE_FULL)),
    ToolSpec("gitleaks", ["gitleaks", "version"], _p(PROFILE_CI_EXTENDED, PROFILE_FULL)),
    ToolSpec("nuclei", ["nuclei", "-version"], _p(PROFILE_CI_EXTENDED, PROFILE_FULL)),
    ToolSpec("subfinder", ["subfinder", "-version"], _p(PROFILE_FULL)),
    ToolSpec("whatweb", ["whatweb", "--version"], _p(PROFILE_FULL)),
    ToolSpec("nmap", ["nmap", "--version"], _p(PROFILE_FULL)),
    ToolSpec("playwright", ["playwright", "--version"], _p(PROFILE_FULL)),
    ToolSpec("ollama", ["ollama", "--version"], _p(PROFILE_FULL)),
    ToolSpec("java (ZAP)", ["java", "-version"], _p(PROFILE_FULL)),
)


def tool_specs_for_profile(profile: str) -> list[ToolSpec]:
    if profile == PROFILE_FULL:
        return list(_TOOL_SPECS)
    if profile not in (PROFILE_CI_MINIMAL, PROFILE_CI_EXTENDED):
        raise ValueError(f"unknown profile {profile!r}; use one of {PROFILE_CHOICES}")
    return [t for t in _TOOL_SPECS if profile in t.profiles]


def all_tool_specs() -> tuple[ToolSpec, ...]:
    return _TOOL_SPECS
