"""SARIF 2.1.0 emission (GitHub Code Scanning compatible subset)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from secscan.constants import ORCHESTRATOR_VERSION
from secscan.redaction import redact_sensitive_text

_SLUG = re.compile(r"[^a-zA-Z0-9._-]+")


def _slug(s: str, max_len: int = 64) -> str:
    t = _SLUG.sub("_", str(s).strip())[:max_len].strip("_")
    return t or "item"


def _artifact_from_unified_location(loc: str) -> dict[str, Any]:
    loc = (loc or "").strip()
    if not loc:
        return {
            "artifactLocation": {"uri": "unknown"},
            "region": {"startLine": 1, "startColumn": 1},
        }
    if loc.startswith("http://") or loc.startswith("https://"):
        return {
            "artifactLocation": {"uri": loc[:2000]},
            "region": {"startLine": 1, "startColumn": 1},
        }
    if ":" in loc:
        ix = loc.rfind(":")
        path_part, line_part = loc[:ix], loc[ix + 1 :]
        try:
            line = int(line_part)
            return {
                "artifactLocation": {"uri": path_part.replace("\\", "/")},
                "region": {"startLine": max(1, line), "startColumn": 1},
            }
        except ValueError:
            pass
    return {
        "artifactLocation": {"uri": loc.replace("\\", "/")[:2000]},
        "region": {"startLine": 1, "startColumn": 1},
    }


def _rule_id_for_unified(f: dict[str, Any]) -> str:
    cid = str(f.get("correlation_id") or "").strip()
    if len(cid) >= 16:
        return f"secscan.unified.{cid[:16]}"
    ph = _slug(str(f.get("phase", "phase")))
    tl = _slug(str(f.get("tool", "tool")))
    ty = _slug(str(f.get("type", "type")), 48)
    return f"secscan.unified.{ph}.{tl}.{ty}"


def _level_from_severity(sev: str) -> str:
    u = (sev or "").upper()
    if u in ("CRITICAL", "HIGH"):
        return "error"
    return "warning"


def write_sarif_tool_native(report: dict[str, Any], output_path: str) -> int:
    """
    Write SARIF from native tool JSON (semgrep, bandit, nuclei only).
    Does not include secrets/deps/agents — use write_sarif_unified_findings for gate parity.
    """
    phases = report.get("phases", {})
    sast = phases.get("sast", {})
    results: list[dict[str, Any]] = []
    rules_map: dict[str, dict[str, Any]] = {}

    def add_rule(rid: str, desc: str) -> None:
        if rid not in rules_map:
            rules_map[rid] = {"id": rid, "name": rid, "shortDescription": {"text": desc[:256]}}

    for f in sast.get("semgrep", {}).get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        rid = str(f.get("check_id", "semgrep.rule"))
        msg = (
            f.get("extra", {}).get("message")
            or f.get("extra", {}).get("metadata", {}).get("message")
            or rid
        )
        add_rule(rid, str(msg)[:200])
        path = f.get("path", "")
        line = int(f.get("start", {}).get("line", 1) or 1)
        col = int(f.get("start", {}).get("col", 1) or 1)
        sev = (f.get("extra", {}).get("severity") or "warning").upper()
        level = "error" if sev in ("ERROR", "CRITICAL") else "warning"
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": str(msg)[:2000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(path).replace("\\", "/")},
                    "region": {"startLine": line, "startColumn": max(1, col)},
                }
            }],
        })

    for f in sast.get("bandit", {}).get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        rid = f"bandit.{f.get('test_id', 'issue')}"
        msg = str(f.get("issue_text", "") or rid)
        add_rule(rid, msg[:200])
        path = str(f.get("filename", ""))
        line = int(f.get("line_number", 1) or 1)
        sev = (f.get("issue_severity") or "MEDIUM").upper()
        level = "error" if sev == "HIGH" else "warning"
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": msg[:2000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path.replace("\\", "/")},
                    "region": {"startLine": line, "startColumn": 1},
                }
            }],
        })

    for f in phases.get("dast", {}).get("nuclei", {}).get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        tid = str(f.get("template-id", "unknown"))
        rid = f"nuclei.{tid}"
        info_blk = f.get("info") or {}
        if not isinstance(info_blk, dict):
            info_blk = {}
        msg = str(info_blk.get("name") or info_blk.get("description") or tid)
        add_rule(rid, msg[:200])
        matched = str(f.get("matched-at", "") or f.get("host", "") or "dynamic")
        sev = str(info_blk.get("severity", "info")).upper()
        level = "error" if sev in ("CRITICAL", "HIGH") else "warning"
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": msg[:2000]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": matched.replace("\\", "/")[:2000]},
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }],
        })

    _write_sarif_file(
        output_path,
        results,
        rules_map,
        driver_suffix="",
        run_properties={"secscan:sarifSource": "tool_native"},
    )
    return len(results)


def write_sarif_unified_findings(findings: list[dict[str, Any]], output_path: str) -> int:
    """
    SARIF rows built from the same unified list used by --fail-on (after baseline).
    Aligns GitHub Code Scanning file counts with gate policy for --fail-on any|high|critical.
    """
    results: list[dict[str, Any]] = []
    rules_map: dict[str, dict[str, Any]] = {}

    def add_rule(rid: str, desc: str) -> None:
        if rid not in rules_map:
            rules_map[rid] = {"id": rid, "name": rid, "shortDescription": {"text": desc[:256]}}

    for f in findings:
        if not isinstance(f, dict):
            continue
        rid = _rule_id_for_unified(f)
        sev = str(f.get("severity", "MEDIUM"))
        typ = str(f.get("type", ""))
        phase = str(f.get("phase", "")).lower()
        tool = str(f.get("tool", "")).lower()
        # Never publish raw secret evidence into SARIF (shared CI UIs).
        if "secret" in phase or "secret" in tool or "secret" in typ.lower():
            ev = "[REDACTED]"
        else:
            ev = redact_sensitive_text(str(f.get("evidence", "")))
        msg = f"{typ} — {ev}"[:2000]
        add_rule(rid, typ[:200])
        loc = str(f.get("location", ""))
        phys = _artifact_from_unified_location(loc)
        results.append({
            "ruleId": rid,
            "level": _level_from_severity(sev),
            "message": {"text": msg},
            "locations": [{"physicalLocation": phys}],
        })

    _write_sarif_file(
        output_path,
        results,
        rules_map,
        driver_suffix=" (unified gate)",
        run_properties={
            "secscan:sarifSource": "unified",
            "secscan:unifiedResultCount": str(len(results)),
        },
    )
    return len(results)


def _write_sarif_file(
    output_path: str,
    results: list[dict[str, Any]],
    rules_map: dict[str, dict[str, Any]],
    *,
    driver_suffix: str,
    run_properties: dict[str, str],
) -> None:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": f"security-suite-orchestrator{driver_suffix}",
                    "version": ORCHESTRATOR_VERSION,
                    "informationUri": "https://github.com/",
                    "rules": list(rules_map.values()),
                }
            },
            "properties": run_properties,
            "results": results,
        }],
    }
    Path(output_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def write_sarif_report(report: dict[str, Any], output_path: str) -> int:
    """Backward-compatible alias: tool-native SARIF only."""
    return write_sarif_tool_native(report, output_path)
