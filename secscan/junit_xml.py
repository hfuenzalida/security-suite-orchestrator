"""Minimal JUnit XML for CI dashboards (GitLab/Jenkins-compatible subset)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from xml.dom import minidom


def write_junit_report(
    path: str,
    *,
    suite_name: str,
    exit_code: int,
    fail_on: str,
    fail_reason: str,
    unified_after_baseline: int,
    exploit_confirmed: int,
    extra_properties: dict[str, Any] | None = None,
) -> None:
    tests = 1
    failures = 1 if exit_code != 0 else 0
    root = ET.Element("testsuites")
    root.set("name", suite_name)
    root.set("tests", str(tests))
    root.set("failures", str(failures))
    root.set("errors", "0")

    ts = ET.SubElement(root, "testsuite")
    ts.set("name", "security_scan")
    ts.set("tests", str(tests))
    ts.set("failures", str(failures))

    if extra_properties:
        props_el = ET.SubElement(ts, "properties")
        for k, v in extra_properties.items():
            p_el = ET.SubElement(props_el, "property")
            p_el.set("name", str(k)[:200])
            p_el.set("value", str(v)[:4000])

    case = ET.SubElement(ts, "testcase")
    case.set("name", f"fail_on_{fail_on}")
    case.set("classname", "SecuritySuiteOrchestrator")
    if exit_code != 0:
        fail_el = ET.SubElement(case, "failure")
        fail_el.set("message", fail_reason or "policy failed")
        fail_el.text = (
            f"exit_code={exit_code}\n"
            f"fail_on={fail_on}\n"
            f"unified_findings_after_baseline={unified_after_baseline}\n"
            f"exploit_confirmed={exploit_confirmed}\n"
        )

    rough = ET.tostring(root, encoding="unicode")
    pretty = minidom.parseString(rough).toprettyxml(indent="  ")
    Path(path).write_text(pretty, encoding="utf-8")
