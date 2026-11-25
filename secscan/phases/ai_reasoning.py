"""Phase 6 — AI reasoning over findings (local Ollama)."""
from secscan.ollama_client import ollama_generate
from secscan.phases._imports import *  # noqa: F403

# ── AI Reasoning ───────────────────────────────────────────────────────────────

def _extract_findings_summary(phases: dict) -> list[dict]:
    """Flatten all phase findings into a concise list for the LLM."""
    summary = []
    for phase_name, tools in phases.items():
        if phase_name in ("ai_code", "auth", "chain"):
            continue
        if not isinstance(tools, dict):
            continue
        for tool, data in tools.items():
            if not isinstance(data, dict):
                continue
            count = data.get("count", 0)
            if not count:
                continue
            findings = data.get("findings", [])
            samples: list[dict] = []
            for f in findings[:5]:
                if isinstance(f, dict):
                    # Extract the most useful fields depending on tool
                    sample = {
                        k: v for k, v in f.items()
                        if k in (
                            "RuleID", "File", "StartLine",          # gitleaks
                            "type", "filename",                      # detect-secrets
                            "check_id", "path", "extra",             # semgrep
                            "issue_text", "issue_severity",          # bandit
                            "filename", "line_number",               # bandit
                            "name", "version", "vulns",              # pip-audit
                            "template-id", "matched-at", "info",    # nuclei
                        )
                    }
                    # Truncate long strings
                    for k, v in list(sample.items()):
                        if isinstance(v, str) and len(v) > 120:
                            sample[k] = v[:120] + "..."
                    samples.append(sample)
                elif isinstance(f, list) and len(f) >= 4:
                    _v = f[3]
                    samples.append(
                        {
                            "package": f[0],
                            "vuln": (str(_v)[:80] if _v is not None else ""),
                        }
                    )  # safety format

            # PoC exploitation uses confirmed/potential, not findings[]
            if not samples and tool == "exploit":
                for f in (data.get("confirmed") or [])[:5]:
                    if isinstance(f, dict):
                        samples.append({
                            "type": f.get("type"),
                            "result": f.get("result"),
                            "severity": f.get("severity"),
                            "target": (str(f.get("target", ""))[:180] + "…")
                            if len(str(f.get("target", ""))) > 180
                            else f.get("target"),
                            "evidence": (str(f.get("evidence", ""))[:120] + "…")
                            if len(str(f.get("evidence", ""))) > 120
                            else f.get("evidence"),
                        })
                for f in (data.get("potential") or [])[:3]:
                    if isinstance(f, dict):
                        samples.append({
                            "type": f.get("type"),
                            "result": "POTENTIAL",
                            "target": (str(f.get("target", ""))[:180] + "…")
                            if len(str(f.get("target", ""))) > 180
                            else f.get("target"),
                        })

            # OWASP ZAP stores alerts, not findings
            if not samples and tool == "zap":
                for a in (data.get("alerts") or [])[:5]:
                    if isinstance(a, dict):
                        samples.append({
                            "alert": a.get("alert"),
                            "risk": a.get("risk"),
                            "url": (str(a.get("url", ""))[:160] + "…")
                            if len(str(a.get("url", ""))) > 160
                            else a.get("url"),
                        })

            summary.append({"tool": tool, "phase": phase_name, "count": count, "samples": samples})
    return summary


_AI_REASONING_SCHEMA = """{
  "executive_summary": "2-4 sentences for leadership: overall risk posture and what to do first",
  "business_impact": {
    "operational": "availability, fraud, abuse, incident response load",
    "financial": "fines, fraud loss, breach costs, SLA penalties (short)",
    "compliance": "GDPR/PCI/HIPAA-style exposure if applicable, or 'unknown — verify'"
  },
  "top_priorities": [
    {"rank": 1, "tool": "scanner or PoC", "finding": "short label", "reason": "why it matters"}
  ],
  "false_positive_flags": [
    {"tool": "...", "finding": "...", "reason": "why it might be a false positive or needs manual check"}
  ],
  "patterns": ["recurring themes across tools, e.g. auth, injection, secrets"],
  "remediation_snippets": [
    {
      "area": "e.g. SQL injection | secret in repo | XSS",
      "finding_ref": "which tool / type",
      "fix_hint": "concrete fix in plain language (not generic 'use a library')",
      "language_or_stack": "e.g. Python/Flask, React, nginx — best guess from context"
    }
  ],
  "remediation_order": [
    {"priority": "HIGH|MEDIUM|LOW", "action": "one actionable step"}
  ]
}"""


def _print_ai_reasoning_box(structured: dict, raw_fallback: str | None) -> None:
    """Pretty-print Phase 6 JSON for the console."""
    print(f"\n{BLUE}  ┌─ AI Security Analysis (Phase 6) {'─'*22}┐{RESET}")

    def emit(msg: str) -> None:
        for sl in msg.splitlines()[:12]:
            print(f"{BLUE}  │{RESET} {sl}")

    if not structured:
        if raw_fallback:
            for ln in raw_fallback.splitlines()[:40]:
                print(f"{BLUE}  │{RESET} {ln}")
        print(f"{BLUE}  └{'─'*47}┘{RESET}\n")
        return

    es = structured.get("executive_summary")
    if es:
        print(f"{BLUE}  │{RESET} {BOLD}EXECUTIVE SUMMARY{RESET}")
        emit(str(es))

    bi = structured.get("business_impact")
    if isinstance(bi, dict) and bi:
        print(f"{BLUE}  │{RESET} {BOLD}BUSINESS IMPACT{RESET}")
        for k in ("operational", "financial", "compliance"):
            if bi.get(k):
                emit(f"  • {k}: {bi[k]}")

    for key, title in (
        ("top_priorities", "TOP PRIORITIES"),
        ("false_positive_flags", "FALSE POSITIVE / VERIFY"),
        ("patterns", "PATTERNS"),
        ("remediation_snippets", "REMEDIATION SNIPPETS"),
        ("remediation_order", "REMEDIATION ORDER"),
    ):
        items = structured.get(key)
        if not items:
            continue
        print(f"{BLUE}  │{RESET} {BOLD}{title}{RESET}")
        if isinstance(items, list):
            for item in items[:12]:
                if isinstance(item, dict):
                    if key == "remediation_snippets":
                        hint = item.get("fix_hint") or item.get("finding_ref") or str(item)
                        area = item.get("area", "")
                        stk = item.get("language_or_stack", "")
                        extra = f" [{area}]" if area else ""
                        extra2 = f" ({stk})" if stk else ""
                        print(f"{BLUE}  │{RESET}   • {hint}{extra}{extra2}")
                    else:
                        bullet = (
                            item.get("action")
                            or item.get("finding")
                            or item.get("reason")
                            or str(item)
                        )
                        print(f"{BLUE}  │{RESET}   • {bullet}")
                else:
                    print(f"{BLUE}  │{RESET}   • {item}")
        else:
            print(f"{BLUE}  │{RESET}   {items}")

    print(f"{BLUE}  └{'─'*47}┘{RESET}\n")


def phase_ai_reasoning(phases: dict, model: str = "qwen2.5-coder:3b") -> dict:
    header("Phase 6 — AI Reasoning (Local Ollama)")

    findings_summary = _extract_findings_summary(phases)
    total = sum(f["count"] for f in findings_summary)

    tm = phases.get("ai_code", {}).get("threat_model", {})
    threat_struct = tm.get("structured") if isinstance(tm, dict) else None
    threat_block = ""
    if isinstance(threat_struct, dict) and threat_struct:
        threat_block = json.dumps(threat_struct, indent=2)
        if len(threat_block) > 6000:
            threat_block = threat_block[:6000] + "\n... (truncated)"

    if not findings_summary and not threat_block:
        ok("AI Reasoning — no scanner findings and no Phase 0.5 threat model to analyze")
        return {
            "status": "no_findings",
            "model": model,
            "analysis": "No security findings detected across all phases.",
        }

    if findings_summary:
        info(f"Sending {total} finding(s) across {len(findings_summary)} tool group(s) to {model}...")
    else:
        info(f"No scanner findings — synthesizing from Phase 0.5 threat model only ({model})...")

    findings_json = json.dumps(findings_summary, indent=2) if findings_summary else "[]"
    if len(findings_json) > 5000:
        findings_json = findings_json[:5000] + "\n... (truncated)"

    prompt = (
        "You are a senior application security engineer advising both engineers and business stakeholders.\n"
        "Analyze the following security scan results"
        + (" and the pre-scan source-code threat model" if threat_block else "")
        + ". Tie conclusions to evidence. Prefer specific remediation over generic advice.\n"
        "Respond ONLY with one JSON object (no markdown fences, no commentary) matching this schema:\n"
        f"{_AI_REASONING_SCHEMA}\n\n"
        f"Scanner finding summary (samples per tool):\n{findings_json}\n"
    )
    if threat_block:
        prompt += f"\nSource-code threat model (Phase 0.5):\n{threat_block}\n"

    raw_analysis, oerr = ollama_generate(
        prompt, model, num_predict=2048, temperature=0.2,
        timeout=scan_timeout_sec("ollama", 180),
    )
    if oerr:
        warn(f"AI Reasoning — {oerr}")
        return {"status": "error", "model": model, "error": oerr}

    structured = safe_json_decode(raw_analysis) if raw_analysis else None

    ok(f"AI Reasoning — analysis complete ({model})")
    _print_ai_reasoning_box(structured if isinstance(structured, dict) else {}, raw_analysis)

    return {
        "status": "success",
        "model": model,
        "analysis": raw_analysis or "",
        "structured": structured if isinstance(structured, dict) else None,
    }

