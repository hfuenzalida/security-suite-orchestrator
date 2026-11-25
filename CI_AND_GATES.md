# CI profile vs full scan, SARIF/JUnit, and gates

This page is the **CI fit** contract: what pipelines should install, which artifacts encode **gate truth**, and how PR jobs differ from nightly/full scans.

## CI profile (`--ci-profile` or `[ci] profile = true`)

Intended for **merge pipelines** where runtime and flakiness should stay bounded.

| Effect | Details |
|--------|---------|
| **Extra `--skip`** | Merges `code_ai`, `recon`, `browser`, `zap`, `agents`, `exploit`, `ai` (see `secscan/ci_profile.py`). Your explicit `--skip` values are unioned — nothing is removed from your list. |
| **`--report-tier`** | Set to **`technical`**. |
| **`--fail-on`** | If still **`never`**, set to **`high`** so the job can fail on meaningful severities. |

**Full scan** (default): run all phases you did not skip manually; use for release audits, pentest-style runs, or when you need PoC / AI / recon.

**Environment:** `SECURITY_SCAN_CI_PROFILE=1` (same as flag). **TOML:** `[ci] profile = true`.

---

## PR vs nightly (recommended split)

| Job | Goal | Orchestrator flags | Tool install profile |
|-----|------|--------------------|----------------------|
| **PR / merge queue** | Fast, deterministic gate; same rows as `--fail-on` | `--ci-profile`, `--fail-on high` (or stricter), `--sarif-source unified`, baseline | **`ci-minimal`** (see below) + target URL / app under test |
| **Nightly / release** | Depth: DAST binaries, recon, optional ZAP | No `--ci-profile` (or custom `--skip`), tune timeouts | **`ci-extended`** or **`full`** on self-hosted runners |

HTML/PDF are **human** layers; **never** use them alone to decide merge. CI truth is **JSON unified + exit code**, optionally mirrored in SARIF/JUnit.

---

## Exit codes (CI honesty)

| Code | Meaning |
|------|---------|
| **0** | Run finished; **`--fail-on`** policy satisfied (and no fatal orchestrator error). |
| **1** | Policy failure (`--fail-on` tripped), invalid args, missing critical path, or other controlled failure. |

Gate dashboards should use **`--junit-output`** and/or parse **`report.json`** / unified list — not HTML success alone.

---

## What `--fail-on` actually evaluates

| Mode | Data source |
|------|-------------|
| `any`, `critical`, `high` | **Unified findings** after baseline (`collect_findings` + `filter_findings_by_baseline`). Includes secrets, SAST, deps, DAST, agents, PoC rows, etc. |
| `exploit` | **PoC phase** `phases.exploit.exploit.confirmed` count (confirmed dynamic validation). |
| `never` | Exit 0 unless another error path fires. |

So **JSON unified list** is the gate truth for severity-style policies.

---

## SARIF: `tool_native` vs `unified`

| `--sarif-source` | Contents | Matches `--fail-on any` row-for-row? |
|------------------|----------|--------------------------------------|
| **`tool_native`** (default) | Semgrep, Bandit, Nuclei only (native tool JSON). | **No** — secrets, deps, schemathesis, ZAP, etc. are not in SARIF. |
| **`unified`** | One SARIF result per **unified finding** (after baseline), same set used for `any` / `critical` / `high`. | **Yes** (for those modes). |

Use **`--sarif-source unified`** when GitHub Code Scanning or another SARIF consumer should see **the same cardinality** as your gate. Use **`tool_native`** when you want classic SAST/DAST-only SARIF aligned with upstream tool IDs.

`run.properties` includes `secscan:sarifSource` for debugging.

---

## JUnit

One logical testcase (`fail_on_<policy>`) reflects pass/fail. The **`<properties>`** block records:

- `sarif_source`, `sarif_result_count` (after SARIF write)
- `ci_profile`
- `orchestrator_version`, `report_schema_compat_version`, **`correlation_join_rules_version`**

So dashboards can correlate the XML with orchestrator behavior and baseline/correlation semantics without parsing JSON.

---

## Tool install profiles (`check_security_tools.py`)

Profiles are defined in **`secscan/ci_tool_profiles.py`** and checked by **`check_security_tools.py`** so the **install matrix stays aligned** with docs.

| Profile | Tools checked | Typical use |
|---------|---------------|-------------|
| **`ci-minimal`** | `semgrep`, `bandit`, `pip-audit`, `detect-secrets` (pip-installable) | GitHub-hosted PR gates with `--ci-profile` |
| **`ci-extended`** | minimal + `safety`, `schemathesis`, `gitleaks`, `nuclei` | Self-hosted agents with common binaries |
| **`full`** | All tools including recon, browser, ZAP/Java, Ollama | Lab / full scan |

```bash
# Human-readable list
python check_security_tools.py --profile ci-minimal

# CI gate: fail if any required tool missing
python check_security_tools.py --profile ci-minimal --strict

# Machine-readable artifact
python check_security_tools.py --profile ci-minimal --json
```

The repository workflow **`.github/workflows/security-scan.yml`** runs **`ci-minimal`** in job `ci-minimal-tools` so the profile stays green on every PR.

---

## Phase × CI artifact matrix (what to archive)

| Artifact | Carries gate truth? | Notes |
|----------|---------------------|--------|
| **`report.json`** | **Yes** (unified list, baseline, `run_manifest`) | Primary evidence for merges. |
| **`--sarif-output`** + **`--sarif-source unified`** | **Yes** (when aligned with `any`/`high`) | Code Scanning / SARIF dashboards. |
| **`--junit-output`** | **Yes** (pass/fail + metadata) | Jenkins/GitLab/GitHub test views. |
| **`--replay-bundle-output`** | Audit / reproducibility | Config + pins; not a severity gate by itself. |
| **HTML / PDF** | **No** (narrative / tiered) | Executive/author review; see [REPORT_TIERS.md](./REPORT_TIERS.md). |

---

## Recommended CI recipe (merge pipeline)

```bash
python security_scan.py --path . --url "$TARGET_URL" \
  --ci-profile \
  --fail-on high \
  --baseline baseline.json \
  --sarif-output results.sarif --sarif-source unified \
  --junit-output junit.xml \
  --output report.json
```

For a **full** assessment, drop `--ci-profile`, tune `--skip`, and keep `--sarif-source tool_native` if you only upload semgrep/bandit/nuclei to Code Scanning.

---

## GitHub Code Scanning (optional upload)

After producing SARIF (prefer **`--sarif-source unified`** for parity with `--fail-on`):

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: success() || failure()
  with:
    sarif_file: results.sarif
```

Use `if: always()` or the pattern above only when your org wants uploads on failed gates; align with security policy.

---

## Pinning and consumers

[VERSIONING.md](./VERSIONING.md) defines `ORCHESTRATOR_VERSION` and `report_schema_compat_version`. Regulated pipelines should pin the orchestrator version and treat **`report_schema_compat_version`** bumps as potential consumer updates.

See also [DISCIPLINE_ENGINEERING_GAPS.md](./DISCIPLINE_ENGINEERING_GAPS.md) §1.4 for remaining org-specific choices (nightly vs PR policy, extra stack templates).
