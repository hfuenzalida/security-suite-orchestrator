"""
Compatibility re-exports: implementations live in focused modules under ``secscan.phases``.
"""
from __future__ import annotations

from secscan.phases.ai_reasoning import phase_ai_reasoning
from secscan.phases.auth_session import phase_auth_session
from secscan.phases.browser import phase_browser
from secscan.phases.chain import phase_request_chain
from secscan.phases.code_ai import phase_ai_code_analysis
from secscan.phases.dast import phase_dast
from secscan.phases.exploit import phase_exploit
from secscan.phases.recon import phase_recon
from secscan.phases.secrets_sast_deps import (
    phase_dependencies,
    phase_sast,
    phase_secrets,
)
from secscan.phases.specialized_agents import phase_specialized_agents
from secscan.phases.zap import phase_zap

__all__ = [
    "phase_ai_code_analysis",
    "phase_ai_reasoning",
    "phase_auth_session",
    "phase_browser",
    "phase_dast",
    "phase_dependencies",
    "phase_exploit",
    "phase_recon",
    "phase_request_chain",
    "phase_sast",
    "phase_secrets",
    "phase_specialized_agents",
    "phase_zap",
]
