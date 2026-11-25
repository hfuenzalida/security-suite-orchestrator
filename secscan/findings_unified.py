"""Unified finding list, correlation IDs, and baseline filtering."""

from __future__ import annotations

import hashlib as _hashlib
import json
from pathlib import Path
from typing import Any

# Shared ordering for HTML / unified list / sort
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "INFO": 4}
RISK_TO_SEV = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFO"}


def stable_correlation_id(f: dict[str, Any]) -> str:
    raw = "|".join(
        str(f.get(k, "") or "")
        for k in ("phase", "tool", "type", "severity", "location", "result")
    )
    return _hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def tag_correlation_ids(findings: list[dict]) -> None:
    for f in findings:
        if isinstance(f, dict) and "correlation_id" not in f:
            f["correlation_id"] = stable_correlation_id(f)


def load_baseline_fingerprints(path: str) -> set[str]:
    """Load JSON `{fingerprints: [...]}` or a plain list of sha256 hex strings."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    items: list = []
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = list(raw.get("fingerprints") or raw.get("ignore") or raw.get("ids") or [])
    out: set[str] = set()
    for x in items:
        # Normalize case: unified correlation_id is lowercase hex; baseline files often use
        # uppercase from other tools — match filter_findings_by_baseline (cid.lower()).
        s = str(x).strip().lower()
        if s:
            out.add(s)
    return out


def filter_findings_by_baseline(
    findings: list[dict], baseline: set[str]
) -> tuple[list[dict], int]:
    if not baseline:
        return findings, 0
    kept: list[dict] = []
    suppressed = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        cid = str(f.get("correlation_id", "")).strip().lower()
        if cid and cid in baseline:
            suppressed += 1
            continue
        kept.append(f)
    return kept, suppressed


def collect_findings(report: dict) -> list[dict]:
    """Flatten all findings from every phase into a unified list."""
    out: list[dict] = []
    phases = report.get("phases", {})

    tm = phases.get("ai_code", {}).get("threat_model", {})
    st = tm.get("structured") if isinstance(tm, dict) else None
    if isinstance(st, dict):
        _rp = st.get("risky_patterns") or []
        if isinstance(_rp, dict):
            _rp = list(_rp.values())
        elif not isinstance(_rp, list):
            _rp = []
        for r in _rp:
            if not isinstance(r, dict):
                continue
            sev = str(r.get("severity", "MEDIUM")).upper()
            out.append({
                "phase": "AI Code (0.5)", "tool": "threat_model",
                "severity": sev if sev in SEVERITY_ORDER else "MEDIUM",
                "result": "POTENTIAL",
                "type": str(r.get("pattern", "Risk pattern"))[:200],
                "evidence": str(r.get("reason", ""))[:400],
                "location": str(r.get("file", "")),
            })

    for tool, data in phases.get("secrets", {}).items():
        for leak in data.get("findings", []):
            out.append({
                "phase": "Secrets", "tool": tool, "severity": "CRITICAL",
                "result": "EXPLOITED",
                "type": leak.get("RuleID", leak.get("type", "Hardcoded Secret")),
                "evidence": leak.get("Description", leak.get("Match", "")),
                "location": leak.get("File", leak.get("filename", "")),
            })

    for tool, data in phases.get("sast", {}).items():
        for issue in data.get("findings", []):
            sev = str(issue.get("severity", issue.get("issue_severity", "MEDIUM"))).upper()
            out.append({
                "phase": "SAST", "tool": tool, "severity": sev, "result": "POTENTIAL",
                "type": issue.get("check_id", issue.get("test_name", "Issue")),
                "evidence": (issue.get("extra", {}).get("message", "")
                             or issue.get("issue_text", ""))[:300],
                "location": (f"{issue.get('path', issue.get('filename',''))}:"
                             f"{issue.get('start', {}).get('line', issue.get('line_number',''))}"),
            })

    for tool, data in phases.get("deps", {}).items():
        for vuln in data.get("findings", []):
            out.append({
                "phase": "Dependencies", "tool": tool, "severity": "HIGH", "result": "POTENTIAL",
                "type": f"Vulnerable package: {vuln.get('name', vuln.get('package','?'))}",
                "evidence": f"{vuln.get('id', vuln.get('vulnerability_id','?'))} — {vuln.get('fix_versions', vuln.get('affected_versions',''))}",
                "location": vuln.get("name", ""),
            })

    for tool, data in phases.get("dast", {}).items():
        if tool != "nuclei":
            continue
        for row in data.get("findings", []):
            if not isinstance(row, dict):
                continue
            info_d = row.get("info") if isinstance(row.get("info"), dict) else {}
            sev = str(info_d.get("severity", "MEDIUM")).upper()
            if sev not in SEVERITY_ORDER:
                sev = "MEDIUM"
            out.append({
                "phase": "DAST", "tool": "nuclei",
                "severity": sev, "result": "POTENTIAL",
                "type": str(row.get("template-id", "nuclei")),
                "evidence": str(info_d.get("name", row.get("matcher-name", "")))[:400],
                "location": str(row.get("matched-at", "")),
            })

    zap = phases.get("zap", {}).get("zap", {})
    for alert in zap.get("alerts", []):
        sev = RISK_TO_SEV.get(alert.get("risk", "Low"), "LOW")
        out.append({
            "phase": "OWASP ZAP", "tool": "zap", "severity": sev, "result": "POTENTIAL",
            "type": alert.get("alert", ""),
            "evidence": alert.get("description", "")[:300],
            "location": alert.get("url", ""),
        })

    agent_labels = {"jwt": "JWT", "idor": "IDOR", "ssrf": "SSRF",
                    "xss_taint": "XSS Taint", "auth": "Auth"}
    for agent, data in phases.get("specialized", {}).items():
        label = agent_labels.get(agent, agent.upper())
        for f in data.get("findings", []):
            out.append({
                "phase": f"Agent: {label}", "tool": agent,
                "severity": f.get("severity", "MEDIUM"),
                "result": f.get("result", "POTENTIAL"),
                "type": f.get("type", ""),
                "evidence": f.get("evidence", ""),
                "location": f.get("url", f.get("file", f.get("tested", ""))),
            })

    for tool, data in phases.get("exploit", {}).items():
        for f in data.get("confirmed", []):
            out.append({
                "phase": "PoC Exploitation", "tool": tool,
                "severity": f.get("severity", "HIGH"), "result": "EXPLOITED",
                "type": f.get("type", ""),
                "evidence": f.get("evidence", ""),
                "location": f.get("target", f.get("url", "")),
            })

    st = phases.get("dast", {}).get("schemathesis", {})
    if isinstance(st, dict) and st.get("status") == "failed":
        out.append({
            "phase": "DAST", "tool": "schemathesis",
            "severity": "HIGH", "result": "POTENTIAL",
            "type": "API contract / OpenAPI fuzz failure",
            "evidence": str(st.get("output", ""))[:400],
            "location": str(report.get("target_url", "") or ""),
        })

    tag_correlation_ids(out)
    out.sort(
        key=lambda x: SEVERITY_ORDER.get(str(x.get("severity", "")).upper(), 99),
    )
    return out
