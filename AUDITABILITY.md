# Auditability (gate truth, baselines, procedural order)

This document is the **normative companion** to [REPORT_TIERS.md](./REPORT_TIERS.md): it explains **which artifacts support automated decisions** versus **human narrative**, and what the orchestrator records for evidence chains.

## Gate truth vs HTML/PDF

| Question | Answer |
|----------|--------|
| What drives **`--fail-on`** and merge gates? | **`report.json`** — unified findings **after** the baseline filter (`unified_findings_*`). |
| What are HTML/PDF for? | **Triage and storytelling** — tiered layout (`--report-tier`); not sufficient alone for CI honesty. |
| Where is this spelled in JSON? | Top-level **`auditability`** on every report (`schema_version` 1). |
| What about SARIF/JUnit? | Optional machine-readable exports; align **`--sarif-source`** with gate policy per [CI_AND_GATES.md](./CI_AND_GATES.md). |

## Fields in `report["auditability"]`

| Block | Contents |
|-------|----------|
| **`gate_truth`** | `fail_on_evaluated_against`, `primary_artifact`, reminder that **`correlation_hints`** are heuristic ([CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md)). |
| **`human_report_role`** | Explicit flag that HTML/PDF are **not** sole evidence for automated gates; **`report_tier`**. |
| **`baseline`** | When `--baseline` is set: resolved path, **`path_sha256`**, **`file_content_sha256`** (for tamper-evident baseline identity). |
| **`policy_outcome`** | `exit_code`, `fail_on`, `exit_reason`, counts after baseline. |
| **`procedural_timeline`** | Ordered list from **`phase_timings`** — phase name, `started_at`, `duration_ms` (attestable execution order). |
| **`dynamic_validation_summary`** | PoC/exploit **confirmed** vs **potential** counts when the exploit phase ran. |
| **`integrity_hooks`** | Whether **`--audit-log-jsonl`**, **`--hmac-sign-report`**, **`--sanitize-exports`** were requested. |
| **`runner_context`** | **`ci_profile`**, **`sarif_source`**. |

## Org-wide “who dismissed what”

The orchestrator records **which baseline file** was used and its **hashes**. Attributing edits to a person (PR author, ticket ID) is **process**: store baseline changes in git and reference the commit in your audit system. The **`auditability.baseline`** block is the technical hook.

## Optional append-only audit log (`--audit-log-jsonl`)

Each run appends one JSON line including **`report_sha256`**, policy fields, and now **`baseline_path_sha256`**, **`baseline_file_content_sha256`**, **`suppressed_by_baseline`**, **`unified_findings_after_baseline`**, **`auditability_schema_version`**. Use for SIEM or WORM-adjacent pipelines. **HMAC** (`--hmac-sign-report`) provides shared-secret integrity, not non-repudiation; KMS/external signing remains an operator concern.

## Pentest-grade procedure logs

**`procedural_timeline`** gives ordered phases with timestamps — suitable for mapping to a runbook. Fine-grained step-by-step exploit procedure is still reflected in **phase outputs** (e.g. PoC evidence fields) and is **partial** by design; deeper attestable steps are a product/process extension.
