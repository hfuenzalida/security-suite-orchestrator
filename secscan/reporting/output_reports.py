"""HTML/PDF reports and console summary (post-scan outputs)."""
from __future__ import annotations

import html as _html
import sys
from pathlib import Path
from typing import Any

from secscan.cli_output import (
    BLUE,
    BOLD,
    GREEN,
    RED,
    RESET,
    fail,
    header,
    is_quiet,
    ok,
    warn,
)
from secscan.export_limits import (
    MAX_HTML_EVIDENCE_CHARS,
    MAX_HTML_LOCATION_CHARS,
    MAX_HTML_TYPE_CHARS,
    MAX_PDF_EVIDENCE_CHARS,
    MAX_PDF_LOCATION_CHARS,
    MAX_PDF_TYPE_CHARS,
    clip_redacted_text,
)
from secscan.findings_unified import collect_findings as _collect_findings
from secscan.report_tiers import (
    normalize_report_tier,
    order_findings_display,
    partition_findings,
    summarize_counts_by_phase,
)
from secscan.sarif_emit import write_sarif_tool_native, write_sarif_unified_findings


def generate_sarif_report(
    report: dict,
    output_path: str,
    *,
    sarif_source: str = "tool_native",
    unified_findings: list[dict] | None = None,
) -> int:
    """
    Emit SARIF 2.1.0.
    tool_native: semgrep, bandit, nuclei JSON only (GitHub-native tool rows).
    unified: same rows as --fail-on gate (after baseline) — see CI_AND_GATES.md.
    """
    if sarif_source == "unified":
        n = write_sarif_unified_findings(list(unified_findings or []), output_path)
    else:
        n = write_sarif_tool_native(report, output_path)
    ok(f"SARIF report -> {output_path} ({n} result(s), source={sarif_source})")
    return n


# ── Report ──────────────────────────────────────────────────────────────────────
# build_report → secscan.report_core


def print_final_summary(report: dict) -> None:
    summary = report["summary"]
    total = report["total_findings"]
    out_path = report.get("_output_path", "report.json")

    if is_quiet():
        lines: list[str] = []
        for tool, count in summary.items():
            if count:
                lines.append(f"  {tool}: {count} finding(s)")
        ai = report.get("ai_reasoning", {})
        ai_status = ai.get("status", "skipped")
        if ai_status == "error":
            lines.append(f"  ai_reasoning: error — {ai.get('error', 'unavailable')[:80]}")
        elif ai_status not in ("skipped", "success", "no_findings"):
            lines.append(f"  ai_reasoning: {ai_status}")
        if lines:
            print("Summary (tools with findings / notes):", file=sys.stderr)
            print("\n".join(lines), file=sys.stderr)
        print(f"Total findings: {total}", file=sys.stderr)
        print(f"Report: {out_path}", file=sys.stderr)
        return

    header("Summary")

    for tool, count in summary.items():
        if count == 0:
            ok(f"{tool:<20} 0 findings")
        else:
            fail(f"{tool:<20} {count} finding(s)")

    ai = report.get("ai_reasoning", {})
    ai_status = ai.get("status", "skipped")
    if ai_status == "success":
        ok(f"{'ai_reasoning':<20} complete ({ai.get('model','')})")
    elif ai_status == "no_findings":
        ok(f"{'ai_reasoning':<20} nothing to analyze")
    elif ai_status == "error":
        warn(f"{'ai_reasoning':<20} {ai.get('error','unavailable')[:60]}")
    else:
        warn(f"{'ai_reasoning':<20} skipped")

    print(f"\n{BOLD}  Total findings: {RED if total else GREEN}{total}{RESET}")
    print(f"  Report saved  : {BLUE}{out_path}{RESET}\n")


# ── HTML Report ─────────────────────────────────────────────────────────────────

_HTML_CSS = """
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:24px;font-size:14px}
a{color:#58a6ff}
h1{color:#f0f6fc;font-size:22px;margin-bottom:4px}
h2{color:#f0f6fc;font-size:15px;border-left:3px solid #388bfd;padding-left:10px;margin:24px 0 10px}
h3{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:.8px;margin:16px 0 6px}
.meta{color:#8b949e;font-size:12px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin:16px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.card-label{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.card-val{font-size:28px;font-weight:700;margin-top:6px}
.c-crit{color:#ff6b6b}.c-high{color:#ffa657}.c-med{color:#e3b341}.c-low{color:#58a6ff}.c-ok{color:#3fb950}.c-info{color:#8b949e}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;margin-right:4px}
.b-CRITICAL{background:#3d1517;color:#ff6b6b}
.b-HIGH{background:#2d1f0f;color:#ffa657}
.b-MEDIUM{background:#2d250f;color:#e3b341}
.b-LOW{background:#0f1f30;color:#58a6ff}
.b-INFO{background:#1c1f23;color:#8b949e}
.b-EXPLOITED{background:#3d1517;color:#ff6b6b}
.b-POTENTIAL{background:#2d250f;color:#e3b341}
.finding{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 14px;margin:6px 0;border-left:3px solid #30363d}
.finding.CRITICAL{border-left-color:#ff6b6b}
.finding.HIGH{border-left-color:#ffa657}
.finding.MEDIUM{border-left-color:#e3b341}
.finding.LOW{border-left-color:#58a6ff}
.finding.INFO{border-left-color:#8b949e}
.finding-title{font-weight:600;color:#f0f6fc;font-size:13px}
.finding-loc{font-family:monospace;font-size:11px;color:#8b949e;margin-top:3px;word-break:break-all}
.finding-ev{font-size:12px;color:#8b949e;margin-top:5px;font-family:monospace;background:#0d1117;padding:6px 8px;border-radius:4px;word-break:break-all}
.tool-row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #21262d}
.tool-name{font-family:monospace;font-size:12px}
pre{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:#c9d1d9;margin:8px 0}
.section{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}
.no-find{color:#3fb950;font-size:13px;padding:8px 0}
.divider{border:none;border-top:1px solid #21262d;margin:20px 0}
.tag{display:inline-block;background:#21262d;color:#8b949e;border-radius:4px;padding:1px 6px;font-size:11px;font-family:monospace;margin:2px}
.audit-strip{background:#2d2419;border:1px solid #d29922;border-radius:8px;padding:12px 14px;margin:0 0 16px;font-size:13px;line-height:1.5;color:#e3b341}
.audit-strip code{color:#ffa657;font-size:12px}
.audit-strip strong{color:#f0883e}
.tier-banner{background:#1c2128;border:1px solid #388bfd;border-radius:8px;padding:12px 14px;margin:0 0 20px;font-size:13px;line-height:1.45;color:#c9d1d9}
.tier-banner strong{color:#58a6ff}
.truth-head{color:#3fb950;font-size:13px;text-transform:uppercase;letter-spacing:.6px;margin:20px 0 10px;border-bottom:1px solid #21262d;padding-bottom:6px}
.muted-policy{color:#8b949e;font-size:12px;margin-top:8px}
</style>
"""

def _esc(s: object) -> str:
    return _html.escape(str(s))


def _severity_class(sev: str) -> str:
    return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
            "LOW": "LOW"}.get(sev.upper(), "INFO")


def _html_finding_block(f: dict) -> str:
    sev = _severity_class(f["severity"])
    res = f.get("result", "")
    loc = (
        clip_redacted_text(str(f.get("location", "")), MAX_HTML_LOCATION_CHARS)
        if f.get("location")
        else ""
    )
    ev = (
        clip_redacted_text(str(f.get("evidence", "")), MAX_HTML_EVIDENCE_CHARS)
        if f.get("evidence")
        else ""
    )
    typ = clip_redacted_text(str(f.get("type", "")), MAX_HTML_TYPE_CHARS)
    return (
        f'<div class="finding {sev}">'
        f'<div class="finding-title">{_esc(typ)}'
        f'  <span class="badge b-{sev}">{sev}</span>'
        + (f'<span class="badge b-{res}">{res}</span>' if res else "")
        + "</div>"
        + (f'<div class="finding-loc">📍 {_esc(loc)}</div>' if loc else "")
        + (f'<div class="finding-ev">{_esc(ev)}</div>' if ev else "")
        + "</div>"
    )


def _html_findings_by_phase(findings: list[dict]) -> str:
    if not findings:
        return '<div class="no-find">✓ No findings in this section.</div>'
    out = ""
    current_phase = None
    for f in findings:
        if f["phase"] != current_phase:
            current_phase = f["phase"]
            out += f'<h3>{_esc(current_phase)}</h3>'
        out += _html_finding_block(f)
    return out


def generate_html_report(report: dict, output_path: str) -> None:
    tier = normalize_report_tier(report.get("report_tier"))
    raw_findings = _collect_findings(report)
    auth, rest = partition_findings(raw_findings)
    ordered = order_findings_display(raw_findings)
    total = len(raw_findings)
    n_auth = len(auth)
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in raw_findings:
        key = f["severity"].upper()
        by_sev[key] = by_sev.get(key, 0) + 1

    generated = report.get("generated_at", "")[:19].replace("T", " ")
    scan_path = _esc(report.get("scan_path", ""))
    target_url = _esc(report.get("target_url") or "N/A")
    ai = report.get("ai_reasoning", {})

    policy = report.get("report_policy") or {}
    tier_label = {"executive": "Executive", "technical": "Technical", "full": "Full"}.get(tier, tier)
    banner_body = (
        f"<strong>Report tier: {_esc(tier_label)}</strong> — "
        f"{_esc(policy.get('summary', 'See REPORT_TIERS.md'))}"
    )
    truth_note = (
        "<div class='muted-policy'><strong>Dynamic &quot;final truth&quot;:</strong> "
        f"{_esc(policy.get('dynamic_truth', 'EXPLOITED rows reflect PoC or live-secret confirmation; other hits are potential.'))}"
        f" <em>{_esc(policy.get('ci_note', ''))}</em></div>"
    )
    tier_banner = f'<div class="tier-banner">{banner_body}{truth_note}</div>'
    ab = report.get("auditability") if isinstance(report.get("auditability"), dict) else {}
    gt = ab.get("gate_truth") if isinstance(ab.get("gate_truth"), dict) else {}
    refs = gt.get("references") or ["CI_AND_GATES.md", "AUDITABILITY.md"]
    ref0 = refs[0] if isinstance(refs, list) and refs else "CI_AND_GATES.md"
    audit_strip = (
        '<div class="audit-strip"><strong>Automation / merge gates:</strong> '
        "Evaluate <code>--fail-on</code> against the <strong>JSON report</strong> unified findings "
        "(after baseline). This HTML is for human triage — use SARIF/JUnit for machine pipelines. "
        f"See <code>{_esc(ref0)}</code> and <code>AUDITABILITY.md</code>.</div>"
    )

    def _card(label: str, value: object, css: str) -> str:
        return (
            f'<div class="card"><div class="card-label">{label}</div>'
            f'<div class="card-val {css}">{_esc(value)}</div></div>'
        )

    cards = (
        _card("Total findings", total, "c-crit" if total else "c-ok")
        + _card("Authoritative (EXPLOITED)", n_auth, "c-crit" if n_auth else "c-ok")
        + _card("Critical", by_sev["CRITICAL"], "c-crit")
        + _card("High", by_sev["HIGH"], "c-high")
        + _card("Medium", by_sev["MEDIUM"], "c-med")
        + _card("Low", by_sev["LOW"], "c-low")
        + _card("Scanned", generated, "c-info")
    )

    summary_rows = ""
    for tool, count in report.get("summary", {}).items():
        cls = "c-crit" if count > 0 else "c-ok"
        label = f'<span class="{cls}">{"⚠ " + str(count) + " finding(s)" if count else "✓ Clean"}</span>'
        summary_rows += f'<div class="tool-row"><span class="tool-name">{_esc(tool)}</span>{label}</div>'

    # ── Findings HTML by tier ─────────────────────────────────────────────────
    if tier == "executive":
        findings_html = ""
        findings_html += '<div class="truth-head">Dynamic validation (authoritative)</div>'
        findings_html += '<div class="section">'
        if auth:
            findings_html += _html_findings_by_phase(auth)
        else:
            findings_html += '<div class="no-find">No EXPLOITED / confirmed items in this run.</div>'
        findings_html += "</div>"
        rest_counts = summarize_counts_by_phase(rest)
        if rest:
            bits = ", ".join(f"{_esc(k)}: {v}" for k, v in list(rest_counts.items())[:12])
            findings_html += (
                '<div class="truth-head">Potential / static (summary only)</div>'
                '<div class="section"><p>'
                f"{len(rest)} finding(s) not shown in detail in executive view. By phase: {bits}"
                ".</p><p>Use <code>--report-tier technical</code> or the JSON report for full rows.</p></div>"
            )
        tool_summary_html = (
            '<div class="section"><p class="muted-policy">Per-tool counts omitted in executive HTML — '
            "use JSON or <code>--report-tier technical</code> for the full table.</p></div>"
        )
    elif tier == "technical":
        findings_html = (
            '<div class="truth-head">Dynamic validation (authoritative — EXPLOITED)</div>'
            '<div class="section">'
            + (
                _html_findings_by_phase(auth)
                if auth
                else '<div class="no-find">No EXPLOITED / confirmed items.</div>'
            )
            + "</div>"
            + '<div class="truth-head">Potential / static analysis</div>'
            + '<div class="section">'
            + (_html_findings_by_phase(rest) if rest else '<div class="no-find">✓ No additional rows.</div>')
            + "</div>"
        )
        _no_tools = '<div class="no-find">No tools ran.</div>'
        tool_summary_html = f'<div class="section">{summary_rows or _no_tools}</div>'
    else:
        findings_html = (
            '<div class="truth-head">All findings (EXPLOITED first, then by severity)</div>'
            '<div class="section">'
            + (
                _html_findings_by_phase(ordered)
                if ordered
                else '<div class="no-find">✓ No findings across all phases.</div>'
            )
            + "</div>"
        )
        _no_tools = '<div class="no-find">No tools ran.</div>'
        tool_summary_html = f'<div class="section">{summary_rows or _no_tools}</div>'

    ai_status = ai.get("status", "skipped")
    if tier == "executive" and ai_status == "success":
        ai_html = (
            '<p class="muted-policy">AI narrative omitted in executive view — open technical tier or JSON for full text.</p>'
            f'<pre style="max-height:120px;overflow:hidden;opacity:.7">{_esc(ai.get("analysis", "")[:800])}</pre>'
        )
    elif ai_status == "success":
        ai_html = f'<pre>{_esc(ai.get("analysis", ""))}</pre>'
    elif ai_status == "no_findings":
        ai_html = '<div class="no-find">✓ Nothing to analyze — scan was clean.</div>'
    else:
        ai_html = (
            f'<div class="tag">{_esc(ai_status)}</div> '
            f'<span style="color:#8b949e">{_esc(ai.get("error", ""))}</span>'
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Scan Report — {generated}</title>
{_HTML_CSS}
</head>
<body>

<h1>Security Scan Report</h1>
<div class="meta">
  Generated: {generated} &nbsp;|&nbsp;
  Path: <code>{scan_path}</code> &nbsp;|&nbsp;
  Target: <code>{target_url}</code>
</div>
{audit_strip}
{tier_banner}

<h2>Executive Summary</h2>
<div class="grid">{cards}</div>

<h2>Tool Summary</h2>
{tool_summary_html}

<h2>Findings ({total})</h2>
{findings_html}

<h2>AI Reasoning</h2>
<div class="section ai-section">{ai_html}</div>

<hr class="divider">
<div class="meta">Generated by Security Suite Orchestrator — all analysis ran locally. Tier policy: REPORT_TIERS.md</div>

</body>
</html>"""

    Path(output_path).write_text(html_content, encoding="utf-8")
    ok(f"HTML report -> {output_path}")


# ── PDF Report (fpdf2) ───────────────────────────────────────────────────────────

def _pdf_safe(text: object) -> str:
    """Replace non-latin-1 characters so fpdf2's Helvetica font doesn't crash."""
    _REPLACEMENTS = {
        "\u2014": "--", "\u2013": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"',  "\u201d": '"', "\u2022": "*", "\u2026": "...",
        "\u00e9": "e",  "\u00e8": "e", "\u00e1": "a", "\u00f3": "o",
        "\u2192": "->", "\u2190": "<-", "\u00b7": ".",
    }
    s = str(text)
    for char, replacement in _REPLACEMENTS.items():
        s = s.replace(char, replacement)
    return s.encode("latin-1", errors="replace").decode("latin-1")


def generate_pdf_report(report: dict, output_path: str) -> None:
    try:
        from fpdf import FPDF
    except ImportError:
        warn("PDF report skipped — install fpdf2: pip install fpdf2")
        return

    tier = normalize_report_tier(report.get("report_tier"))
    findings_all = _collect_findings(report)
    auth, rest = partition_findings(findings_all)
    ordered = order_findings_display(findings_all)
    generated = report.get("generated_at", "")[:19].replace("T", " ")

    class _PDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 10)
            self.cell(0, 8, "Confidential Security Audit Report", ln=True, align="L")
            self.ln(2)

        def footer(self):
            self.set_y(-12)
            self.set_font("Helvetica", "I", 8)
            self.cell(0, 8, f"Page {self.page_no()}/{{nb}}", align="C")

    pdf = _PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Title ─────────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 12, "Security Scan Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, _pdf_safe(f"Generated: {generated}"), ln=True, align="C")
    pdf.cell(0, 6, _pdf_safe(f"Target:    {report.get('target_url') or 'N/A'}"), ln=True, align="C")
    pdf.cell(0, 6, _pdf_safe(f"Path:      {report.get('scan_path', '')}"), ln=True, align="C")
    tier_lbl = {"executive": "executive", "technical": "technical", "full": "full"}.get(tier, tier)
    pdf.cell(0, 6, _pdf_safe(f"Report tier: {tier_lbl}"), ln=True, align="C")
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(180, 100, 30)
    pdf.multi_cell(
        0,
        4,
        _pdf_safe(
            "Gates: evaluate --fail-on against report.json unified findings (after baseline), "
            "not this PDF alone. See CI_AND_GATES.md and AUDITABILITY.md."
        ),
    )
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)

    # ── Executive summary table ────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "Executive Summary", ln=True)
    pdf.ln(2)

    if tier != "executive":
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(100, 7, "Tool / Phase", border=1, fill=True)
        pdf.cell(40, 7, "Findings", border=1, fill=True, ln=True)
        pdf.set_font("Helvetica", "", 10)
        for tool, count in report.get("summary", {}).items():
            pdf.cell(100, 6, _pdf_safe(tool), border=1)
            pdf.cell(40, 6, str(count), border=1, ln=True)
    else:
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(
            0,
            5,
            _pdf_safe(
                "Per-tool table omitted (executive tier). EXPLOITED count: "
                f"{len(auth)}. Total unified: {len(findings_all)}."
            ),
        )
    pdf.ln(6)

    # ── Findings ──────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, f"Findings ({len(findings_all)})", ln=True)
    pdf.ln(2)

    _SEV_COLORS = {
        "CRITICAL": (220, 50, 50),
        "HIGH": (220, 120, 20),
        "MEDIUM": (200, 170, 10),
        "LOW": (30, 100, 200),
        "INFO": (120, 120, 120),
    }

    def _emit_pdf_findings_block(pdf_: Any, title: str, findings: list) -> None:
        if not findings:
            return
        pdf_.ln(2)
        pdf_.set_font("Helvetica", "B", 11)
        pdf_.set_fill_color(230, 240, 230)
        pdf_.cell(0, 7, _pdf_safe(title), ln=True, fill=True)
        pdf_.set_font("Helvetica", "", 9)
        current_phase = None
        for f in findings:
            if f["phase"] != current_phase:
                current_phase = f["phase"]
                pdf_.ln(2)
                pdf_.set_font("Helvetica", "B", 10)
                pdf_.cell(0, 6, _pdf_safe(current_phase), ln=True)
                pdf_.set_font("Helvetica", "", 9)
            sev = f["severity"].upper()
            r, g, b = _SEV_COLORS.get(sev, (120, 120, 120))
            pdf_.set_text_color(r, g, b)
            pdf_.set_font("Helvetica", "B", 9)
            res = f.get("result", "")
            typ = clip_redacted_text(str(f.get("type", "")), MAX_PDF_TYPE_CHARS)
            label = _pdf_safe(f"[{sev}] [{res}] {typ}")
            pdf_.cell(0, 5, label, ln=True)
            pdf_.set_text_color(0, 0, 0)
            pdf_.set_font("Helvetica", "", 8)
            if f.get("location"):
                loc = clip_redacted_text(str(f["location"]), MAX_PDF_LOCATION_CHARS)
                pdf_.cell(0, 4, _pdf_safe(f"  Location: {loc}"), ln=True)
            if f.get("evidence"):
                ev = clip_redacted_text(str(f["evidence"]), MAX_PDF_EVIDENCE_CHARS)
                pdf_.multi_cell(0, 4, _pdf_safe(f"  Evidence: {ev}"))
            pdf_.ln(1)

    if tier == "executive":
        if auth:
            _emit_pdf_findings_block(pdf, "Dynamic validation (EXPLOITED)", auth)
        else:
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 6, _pdf_safe("No EXPLOITED / confirmed findings in this run."), ln=True)
        if rest:
            pdf.set_font("Helvetica", "I", 9)
            pdf.multi_cell(
                0,
                5,
                _pdf_safe(
                    f"{len(rest)} potential/static finding(s) omitted — use technical tier or JSON."
                ),
            )
    elif tier == "technical":
        if auth:
            _emit_pdf_findings_block(pdf, "Authoritative (EXPLOITED)", auth)
        else:
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 6, _pdf_safe("No EXPLOITED / confirmed findings in this run."), ln=True)
        _emit_pdf_findings_block(pdf, "Potential / static", rest)
    else:
        pass

    current_phase = None
    for f in (ordered if tier == "full" else []):
        if f["phase"] != current_phase:
            current_phase = f["phase"]
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(0, 7, _pdf_safe(current_phase), ln=True, fill=True)
            pdf.set_font("Helvetica", "", 9)

        sev = f["severity"].upper()
        r, g, b = _SEV_COLORS.get(sev, (120, 120, 120))
        pdf.set_text_color(r, g, b)
        pdf.set_font("Helvetica", "B", 9)
        res = f.get("result", "")
        typ = clip_redacted_text(str(f.get("type", "")), MAX_PDF_TYPE_CHARS)
        label = _pdf_safe(f"[{sev}] [{res}] {typ}")
        pdf.cell(0, 5, label, ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 8)

        if f.get("location"):
            loc = clip_redacted_text(str(f["location"]), MAX_PDF_LOCATION_CHARS)
            pdf.cell(0, 4, _pdf_safe(f"  Location: {loc}"), ln=True)
        if f.get("evidence"):
            ev = clip_redacted_text(str(f["evidence"]), MAX_PDF_EVIDENCE_CHARS)
            pdf.multi_cell(0, 4, _pdf_safe(f"  Evidence: {ev}"))
        pdf.ln(1)

    # ── Screenshot (if any) ───────────────────────────────────────────────────
    screenshot = "browser_screenshot.png"
    if Path(screenshot).exists():
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 8, "Browser Screenshot", ln=True)
        pdf.ln(2)
        try:
            pdf.image(screenshot, x=10, w=190)
        except Exception:
            pdf.cell(0, 6, "(Screenshot could not be embedded)", ln=True)

    # ── AI Reasoning ──────────────────────────────────────────────────────────
    ai = report.get("ai_reasoning", {})
    if ai.get("status") == "success":
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 8, "AI Security Analysis", ln=True)
        pdf.ln(2)
        pdf.set_font("Courier", "", 8)
        cap = 800 if tier == "executive" else 3000
        analysis_text = _pdf_safe(ai.get("analysis", "")[:cap])
        if tier == "executive":
            pdf.set_font("Helvetica", "I", 8)
            pdf.cell(0, 5, _pdf_safe("(Truncated in executive tier — use technical tier or JSON for full text.)"), ln=True)
            pdf.ln(1)
            pdf.set_font("Courier", "", 8)
        pdf.multi_cell(0, 4, analysis_text)

    pdf.output(output_path)
    ok(f"PDF  report -> {output_path}")

