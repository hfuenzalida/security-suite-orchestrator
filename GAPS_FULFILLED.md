# Discipline gaps — consolidated fulfillment register

**Purpose:** Single place to **assess how many discipline gaps are fulfilled** relative to [DISCIPLINE_ENGINEERING_GAPS.md](./DISCIPLINE_ENGINEERING_GAPS.md) and [v2.md](./v2.md) (identical content).  
**Orchestrator baseline:** `0.2.9` (`ORCHESTRATOR_VERSION` in `secscan/constants.py`).  
**Scope:** Engineering *operating* discipline (reproducibility, auditability, safe ops, CI fit, maintainable code)—not Shannon Pro AI/CPG feature parity ([Shannon Gap.md](./Shannon%20Gap.md)).

---

## Scorecard *(how far along)*

| Signal | Fulfilled / completion | What it means |
|--------|------------------------|---------------|
| **§§1.1–1.6** (dimension closure) | **100%** *closure* | Every dimension is either **shipped** or an **explicit boundary** (org / product / §4 P2)—no dangling §1 backlog. |
| **§4 P0 + P1** (prioritized backlog) | **P0: 100%** · **P1 technical: ~100%** · **P1 overall: ~95%** | All historical **P0** and **P1 technical** items are implemented; **~5%** is **org lockfile/CI-matrix policy**, not missing code. |
| **§3** (professional CLI) | **5 done** · **2 partial** · **1 org-policy** | See [§3 fulfilled vs partial](#3-core-software-engineering-fulfilled-partial) below. |
| **Blended discipline progress** | **~95%** | Combines §1 closure + §4 backlog + §3/P2 moderation—see source doc *How far along are we?* |

---

## 1. Fulfilled by engineering dimension (§1)

These match **Shipped (closure)** rows in §§1.1–1.5 and the **§1.6** summary. Residual boundaries (org KMS, firewall, optional product IDs) are **classified**, not unfulfilled gaps.

### 1.1 Reproducibility — fulfilled

| # | Fulfilled capability |
|---|----------------------|
| R1 | `run_manifest` + **`replay_bundle` spec_version 2** (`tool_versions`, `environment`, `supply_chain`, `scan_path_git_relative`, `determinism_note`, optional `pip_freeze_sha256`) |
| R2 | Normative docs: [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md), [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md), [REPRODUCIBILITY.md](./REPRODUCIBILITY.md) |
| R3 | CLI: `--replay-bundle-output`, `--wipe-run-dir` |
| R4 | `phase_timings`, structured phases |
| R5 | `correlation_id`, fingerprints, baseline, **`correlation_hints`** |
| R6 | **`supply_chain.files`** hashes + reproducibility guidance |

### 1.2 Auditability — fulfilled

| # | Fulfilled capability |
|---|----------------------|
| A1 | **`auditability`** JSON (`schema_version` 1): gate truth, baseline hashes, `policy_outcome`, `procedural_timeline`, exploit summary |
| A2 | [AUDITABILITY.md](./AUDITABILITY.md); HTML audit-strip + PDF gate notice; [REPORT_TIERS.md](./REPORT_TIERS.md) |
| A3 | **`--audit-log-jsonl`** (baseline hashes, counts, `ci_profile`, `sarif_source`, …) |
| A4 | PoC evidence fields + `correlation_hints` |
| A5 | **`--hmac-sign-report`**; export/webhook redaction |

### 1.3 Safe operations — fulfilled

| # | Fulfilled capability |
|---|----------------------|
| S1 | **`REDACTION_RULESET_VERSION`**; webhook / `run_manifest` redaction; **`--sanitize-exports`**; HTML/PDF caps |
| S2 | **`--network-mode`**; [NETWORK_MODE.md](./NETWORK_MODE.md), [SAFE_OPERATIONS.md](./SAFE_OPERATIONS.md) |
| S3 | **`--include-glob`** / **`--exclude-glob`**; **`path_scope_dropped_count`** |
| S4 | **`safe_operations`**, **`temp_artifacts`**, **`--wipe-temp`** |
| S5 | [HARDENING_CHECKLIST.md](./HARDENING_CHECKLIST.md) (operator checklist shipped) |

### 1.4 CI fit — fulfilled

| # | Fulfilled capability |
|---|----------------------|
| C1 | **`--ci-profile`**, **`--sarif-source`**, [CI_AND_GATES.md](./CI_AND_GATES.md), JUnit + **`correlation_join_rules_version`** |
| C2 | `ci_gates` / unified findings for gating |
| C3 | **`ci_tool_profiles`**, **`check_security_tools --profile`**, **`ci-minimal-tools`** workflow ([`.github/workflows/security-scan.yml`](./.github/workflows/security-scan.yml)) |
| C4 | [VERSIONING.md](./VERSIONING.md), `report_schema_compat_version` |

### 1.5 Maintainable code — fulfilled

| # | Fulfilled capability |
|---|----------------------|
| M1 | Logging module; TOML + env; `secscan/` layout; tool adapters |
| M2 | **`pytest`** — **90** tests (critical path, tool run, phase status, SARIF/CI, adapters, discipline, CLI) |
| M3 | **`ToolRunPayload`**, **`attach_run_payload`** on **Phase 1–3 + DAST**; [MAINTAINABILITY.md](./MAINTAINABILITY.md) |
| M4 | `summarize_phases`, **`run.code`** |

### 1.6 Cross-cutting — fulfilled (closure themes)

| Theme | Fulfilled in orchestrator / docs |
|-------|----------------------------------|
| Correlation | [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md), `correlation_hints`, baseline merge, replay |
| Policy / gate truth | [REPORT_TIERS.md](./REPORT_TIERS.md), [AUDITABILITY.md](./AUDITABILITY.md); baseline hash in **`auditability.baseline`** |
| Operations | [HARDENING_CHECKLIST.md](./HARDENING_CHECKLIST.md), [NETWORK_MODE.md](./NETWORK_MODE.md), wipes, globs on unified findings |
| Maintainability | Phase 1–3 + DAST on `tool_run_result`; [MAINTAINABILITY.md](./MAINTAINABILITY.md) |

**§1 subtotal:** **24** numbered items across **§§1.1–1.5** + **4** cross-cutting themes in **§1.6** = **28** discrete tracked items *(aligned with [DISCIPLINE_ENGINEERING_GAPS.md](./DISCIPLINE_ENGINEERING_GAPS.md) §1 / [v2.md](./v2.md) §1).*

---

## 2. Shannon principles — fulfilled or largely addressed (§2)

Rows from the Shannon mapping table where v2 status is **Done**, **Largely addressed**, **Improved**, **Documented**, or **Discipline** (partial fulfillment counted as *addressed*, not empty).

| Principle | Fulfillment level (v2) |
|-----------|-------------------------|
| False positive tagging | **Largely addressed** — `--baseline`, triage on JSON, merge before `fail-on` |
| Ephemeral code handling | **Largely addressed** — [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md), `--wipe-temp`, `--wipe-run-dir`, temp registry |
| Self-hosted / data local | **Documented** — [NETWORK_MODE.md](./NETWORK_MODE.md), [HARDENING_CHECKLIST.md](./HARDENING_CHECKLIST.md) |
| CI/CD PR scanning | **Largely addressed** — SARIF, JUnit, `--ci-profile`, `--sarif-source`, workflow sample |
| Tool orchestration + interpretation | **Improved** — `ToolRunOutcome` on **Phase 1–3 + DAST** |
| Liveness for secrets | **Discipline** — no secret exfiltration |
| Parallelism + phase model | **Done** — `phase_timings`, TOML timeouts |
| Static–dynamic correlation | **Partial** — `correlation_id` + `correlation_hints` (heuristic layer shipped) |
| “POC or it didn’t happen” | **Partial** — PoC levels, `report_tier`, CI uses unified JSON |
| Encrypted storage / isolation | **Partial** — redaction, sanitize exports, webhook minimization |
| Audit / reproducibility | **Largely addressed** — `run_manifest`, replay bundle, audit JSONL, HMAC |
| Boundary analysis | Not fully fulfilled — see source §2 *(optional product / globs)* |

**Principles with material fulfillment in v2:** **12** of **13** rows have at least **partial** or better coverage; **1** row (boundary analysis) remains **open** in the comparison table.

---

## 3. Core software engineering — fulfilled / partial

| Area | Original gap | Fulfillment |
|------|----------------|-------------|
| **Logging** | Print-only | **Fulfilled** — stdlib logging, `--verbose`, `--log-json`, `--log-file` |
| **Configuration** | CLI-only | **Fulfilled** — TOML + env + `security_scan.toml.example` |
| **Dependencies** | Unpinned | **Fulfilled** — `requirements.txt` + `pyproject.toml` *(full-matrix lockfiles = org policy)* |
| **Portability** | Hardcoded paths | **Fulfilled** — `secscan/external_paths.py` and env overrides |
| **Automated tests** | None / thin | **Largely fulfilled** — **90** tests across critical paths |
| **Modularity** | Monolithic CLI | **Partial** — phases + reporting factored; `apply_unified_findings_to_report`; further splits optional |
| **Error semantics** | Inconsistent | **Partial** — Phase **1–3 + DAST** attach **`run`**; recon/ZAP/exploit/chain incremental (§4 P2) |

**§3 tally:** **5 fulfilled** · **2 partial** · **1** (lockfile matrix) **org policy** tied to dependencies row.

---

## 4. Prioritized backlog — fulfilled items (§4)

### P0 — 100% fulfilled (complete ≤0.2.9)

- Baseline / ignore (`--baseline`), `correlation_id` fingerprints, triage, **`--emit-baseline-suggestions`**
- Webhook + argv redaction; **`--sanitize-exports`**
- **run_manifest** + **replay_bundle** (spec v2); join-rules version
- **SARIF** + **`--sarif-source`**; **`--fail-on`** on unified findings (after baseline + path scope)
- **`--ci-profile`**, JUnit metadata, [CI_AND_GATES.md](./CI_AND_GATES.md)
- Extended: **`auditability`** JSON block; audit JSONL; HTML/PDF gate notices

**P0 bullet groups:** **6** *(plus extended audit line)* — all **implemented**.

### P1 — technical items fulfilled (complete ≤0.2.9)

- **`phase_timings`**; **`[timeouts]`** / **`SECURITY_SCAN_TIMEOUT_*`**
- **`--junit-output`**; `.github/workflows/security-scan.yml` (tests + **`ci-minimal-tools`**)
- **`--replay-bundle-output`**, **`--wipe-temp`**, **`--wipe-run-dir`**; [REPRODUCIBILITY.md](./REPRODUCIBILITY.md)
- **`check_security_tools.py`** `--profile ci-minimal|ci-extended|full` + `--strict` + `--json`
- Extended: **`--network-mode`**, **`--include-glob` / `--exclude-glob`**; **`safe_operations`** block; cross-cutting docs

**P1 technical bullet groups:** **5** *(plus extended line)* — all **shipped**. **P1 residual** (~5%): org lockfile/CI-matrix *policy* (not code).

### P2 — subset fulfilled

- **Done (fulfilled):** Phase **1–3** + **DAST** tool-run model; **`ToolRunPayload`**; **`correlation_hints`**, **`unified_report`**, critical-path + tool-run tests ([MAINTAINABILITY.md](./MAINTAINABILITY.md))

---

## 5. Aggregate counts *(for assessment)*

| Bucket | Count / status |
|--------|----------------|
| §1.1–1.5 discrete **fulfilled** rows (numbered) | **24** |
| §1.6 cross-cutting themes **closed** | **4** |
| §4 **P0** groups | **6** (+ audit extended) — **100%** |
| §4 **P1** technical groups | **5** (+ extended) — **100%** of technical scope |
| §3 areas **fully** fulfilled | **5** (logging, config, deps manifests, portability, + strong tests) |
| §3 **partial** | **2** (modularity, error semantics on remaining phases) |
| Shannon §2 principles with ≥ partial fulfillment | **12** / **13** |

**Blended overall:** **~95%** toward Shannon-*style operating discipline* (source: *How far along are we?* in [DISCIPLINE_ENGINEERING_GAPS.md](./DISCIPLINE_ENGINEERING_GAPS.md)).

---

## 6. Not in this register

- **Org-owned:** enterprise lockfile matrices, regulated pinning, KMS, firewall, retention, CI runner choice.
- **Optional product:** CPG, guaranteed SAST→PoC ID, first-class service boundaries—[Shannon Gap.md](./Shannon%20Gap.md) / §4 **P3**.
- **§4 P2 remaining:** `attach_run_payload` on recon, ZAP, exploit, chain; optional JSON Schema; extra pytest where warranted.

---

*Derived from document version **2.0** of the discipline gap analysis. Update this register when DISCIPLINE_ENGINEERING_GAPS.md / v2.md change.*
