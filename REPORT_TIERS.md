# Report tiers (HTML / PDF policy)

The orchestrator separates **how much narrative noise** human readers see from **what automation uses**. CI gates, SARIF, JUnit, and `--fail-on` always use the **JSON** unified model; tiers only change **HTML** and **PDF** presentation.

| Tier | Audience | Behavior |
|------|----------|----------|
| **executive** | Risk / leadership | **EXPLOITED** (PoC confirmations, live secret hits) shown in full. Other findings summarized by phase counts only. Per-tool table omitted. AI text truncated. |
| **technical** | Engineers / triage | Two bands: **Authoritative (EXPLOITED)** first, then **Potential / static**. Full tool summary table. |
| **full** | Legacy / parity | Single findings list with EXPLOITED rows first (by severity within each band), then the rest. Full tool table. |

## “Final truth” for dynamic results

- **EXPLOITED** in the unified list means: PoC phase recorded confirmation, or a finding was classified as exploited (e.g. live secrets). These rows are **authoritative** for “did we demonstrate impact?”
- **POTENTIAL** (SAST, nuclei without PoC, ZAP alerts, etc.) are **not** treated as confirmed compromise in narrative banners.
- **correlation_hints** in JSON may link PoCs to static rows — that remains **heuristic**; see [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md).

## Configuration

- CLI: `--report-tier executive|technical|full` (default: `full`).
- TOML `[defaults] report_tier = "technical"`.
- Env: `SECURITY_SCAN_REPORT_TIER`.

Embedded policy strings are stored on every JSON report as `report_policy` (and `report_tier`).

Structured **gate-truth vs narrative** metadata is stored as **`auditability`** on every JSON report — see [AUDITABILITY.md](./AUDITABILITY.md).

## Integrity hooks (optional)

- **`--audit-log-jsonl FILE`** — appends one JSON object per run with `report_path`, `report_sha256`, `exit_code`, `fail_on`, `report_tier`, etc. Use for SIEM, centralized logging, or external evidence stores.
- **`--hmac-sign-report`** — writes `security_report.json.hmac` (hex HMAC-SHA256 of the JSON bytes). Set **`SECURITY_SCAN_REPORT_HMAC_KEY`** or **`--report-hmac-key-file`**. Verify offline with the same key and file bytes.

These do **not** replace a full WORM archive or KMS-backed signing; they are **lightweight hooks** for teams that need tamper-evidence or pipeline correlation.
