# Discipline engineering gaps (vs Shannon Pro *operating principles*)

**Document version:** 2.0 · **Orchestrator baseline:** `0.2.9` (`ORCHESTRATOR_VERSION` in `secscan/constants.py`) · **Same content:** [v2.md](./v2.md)

This document reviews [SHANNON-PRO.md](./SHANNON-PRO.md) and extracts **enterprise-grade operating principles** (how the product is *run*, not its proprietary AI/CPG). Those principles are mapped to **gaps in this repository’s orchestrator** and concrete remediation items.

**Scope:** We are **not** aiming to replicate Shannon Pro’s analysis engine (CPG, invariant fuzzers, 13 Claude agents). We **are** aiming for the same class of **engineering discipline**: reproducibility, auditability, safe operations, CI fit, and maintainable code.

### Executive summary (v2)

The orchestrator has **crossed from “backlog-heavy” to “policy-and-edge-cases”** on several pillars: baseline-aware gating, run manifests with replay bundles, export sanitization, SARIF/JUnit/CI profiles, report tiers, audit/HMAC hooks, and a **unified** gate path aligned with optional **unified SARIF**. **§§1–1.6** document **full discipline closure** (shipped vs explicit boundaries); **§4 (P0 + P1)** tracks the executable backlog. **Blended overall progress** toward Shannon-*style operating discipline* (not AI/CPG parity) is **~95%** — see **How far along are we?** below.

### How far along are we? *(blended view → ~95%)*

Stakeholders often want one answer. This doc blends **three signals** into a single **~95%** figure for **engineering discipline** (how the tool is built, run, and gated)—**not** Shannon Pro product features ([Shannon Gap.md](./Shannon%20Gap.md)).

| Signal | What it measures | Completion (v2 / **0.2.9**) |
|--------|------------------|----------------------------|
| **§§1.1–1.6** | Operating promises by dimension: shipped work + **classified** boundaries (org / product / §4 P2) | **100%** *closure* — no half-done §1 backlog lines |
| **§4 P0 + P1** | Prioritized ship list (safety, CI honesty, operability) | **~95%** — all **P0** + P1 **technical** items; **~5%** = org lockfile/matrix **policy**, not missing code |
| **§3 + §4 P2** | Generic CLI quality (modularity, tests, **`run`** on all phases) | **~90%** blended — **90** tests, Phase **1–3 + DAST** tool-run; recon/ZAP/exploit **incremental** |

**How the ~95% is read:** §1 is **complete for its contract**; the backlog metric (§4) is **~95%**; §3/P2 **moderates** a naive “everything is 100%” reading. Together they imply **~95%** toward “credible next to enterprise pipelines” for this OSS orchestrator. The remaining **~5%** is **org-owned policy**, **optional** deeper correlation/product work, and **§4 P2** maintainability on secondary phases—not missing core safety, audit hooks, or CI honesty.

### What changed from v1 → v2 of this analysis

| Theme | v1 emphasis | v2 status |
|-------|-------------|-----------|
| **Reproducibility** | Join rules and workspace as ideas | **Normative** [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md), [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md), `run_manifest.replay_bundle`, CLI replay/wipe flags |
| **Auditability** | HTML vs CI confusion | **Report tiers**, audit JSONL, HMAC sidecar; docs spell CI truth (JSON/SARIF/JUnit) |
| **Safe ops** | Redaction wish list | **Sanitized exports**, temp/run wipes, hardening/minimal-network docs; **closure:** limits **documented** in [OPERATING_GUARANTEES.md](./OPERATING_GUARANTEES.md) (novel formats, unregistered temps) |
| **CI fit** | SARIF/JUnit “needed” | **`--ci-profile`**, **`--sarif-source`**, **`ci-minimal-tools`** CI job, [CI_AND_GATES.md](./CI_AND_GATES.md) |
| **Maintainability** | Large CLI, weak tests | **`unified_report`**, **`tool_run_result`** on **Phase 1–3 + DAST**, [MAINTAINABILITY.md](./MAINTAINABILITY.md); recon/ZAP/exploit incremental |

---

## 1. Gap analysis by engineering dimension *(discipline closure)*

This section states **full closure** for §§1.1–1.6: what the orchestrator **delivers**, what is an **explicit boundary** (documented limit, honest non-claim, or org-owned process), and what is **optional product / future refactor** (referenced in §4, not as an open “still needed” line here). The Shannon-principle table in §2 compares principles to this repo; §4 remains the **prioritized** enhancement list.

### 1.1 Reproducibility

**Target:** Same inputs and environment produce comparable runs; another engineer can replay or explain why a result differed.

| Shipped (closure) | Residual boundary *(classified — not an open §1 backlog)* |
|-------------------|-------------------------------------------------------------|
| `run_manifest` + **`replay_bundle` spec_version 2** — `tool_versions`, **`environment`**, **`supply_chain`**, **`scan_path_git_relative`**, **`determinism_note`**, optional **`pip_freeze_sha256`**; [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md), [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md), [REPRODUCIBILITY.md](./REPRODUCIBILITY.md); `--replay-bundle-output`, `--wipe-run-dir` | **Determinism:** Bit-identical reruns across machines are **not claimed**; variance is **recorded** in `determinism_note` and replay metadata — **closure** = honest, auditable replay evidence. |
| `phase_timings`, structured phases | **Retention:** Long-term artifact policy is **org**; [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md) + wipe flags define what the **tool** guarantees. |
| `correlation_id`, fingerprints, baseline, **`correlation_hints`** | **Single SAST→PoC ID:** Heuristic + hints are the **shipped** OSS discipline layer; a Shannon-style **guaranteed** cross-phase key is **optional product** scope ([Shannon Gap.md](./Shannon%20Gap.md)), not §1 debt. |
| **`supply_chain.files`** hashes + REPRODUCIBILITY guidance | **Enterprise lockfile matrix:** **Org** selects pip/poetry/uv matrix; orchestrator **pins evidence** of manifests on disk — **closure** for “what ran against what files.” |

**§1.1 closure:** Reproducibility work for **0.2.9** is **complete**: replay bundle, join-rules version, and documented limits. Relative paths in tool configs are **contributor/adapter** hygiene (see adapter docs), not an unfilled orchestrator requirement.

### 1.2 Auditability

**Target:** Decisions are traceable: what ran, what was dismissed, what failed gates, and what evidence supports “exploited” vs “potential.”

| Shipped (closure) | Residual boundary *(classified)* |
|-------------------|-----------------------------------|
| **`auditability`** JSON (`schema_version` 1): gate truth, **`baseline` hashes**, **`policy_outcome`**, **`procedural_timeline`**, exploit summary; [AUDITABILITY.md](./AUDITABILITY.md); HTML **audit-strip** + PDF gate notice; [REPORT_TIERS.md](./REPORT_TIERS.md) | **HTML-only readers:** Guided to JSON/SARIF/JUnit for **CI truth** — **closure** = tiered reporting contract; **training** is org enablement, not missing code. |
| **`--audit-log-jsonl`** (baseline hashes, counts, `ci_profile`, `sarif_source`, …) | **Baseline authorship:** Provenance is **git/PR process**; orchestrator records **hashes** for comparison — **closure**. |
| PoC evidence fields + **`correlation_hints`** | **Step-by-step pentest narrative:** Phase timeline + PoC counts are the **shipped** structured audit; **sub-step** logs are **optional product** depth. |
| **`--hmac-sign-report`**; export/webhook redaction | **KMS / non-repudiation / encrypted vaults:** **Org** security architecture; HMAC documents **integrity** with shared secret — **closure** for CLI scope. |

**§1.2 closure:** Auditability requirements for machine-readable **gate truth**, baseline evidence, and integrity hooks are **met**. Anything requiring **enterprise KMS** or **pentest lab** procedure capture beyond JSON fields is **explicitly out of scope** for this CLI.

### 1.3 Safe operations

**Target:** Defaults and paths minimize secret leakage, unsafe automation, and blast radius.

| Shipped (closure) | Residual boundary *(classified)* |
|-------------------|-----------------------------------|
| **`REDACTION_RULESET_VERSION`**; webhook / `run_manifest` redaction; **`--sanitize-exports`**; HTML/PDF caps | **Best-effort redaction** — **closure** = documented in [OPERATING_GUARANTEES.md](./OPERATING_GUARANTEES.md) (novel encodings, binaries, false negatives). |
| **`--network-mode`**; [NETWORK_MODE.md](./NETWORK_MODE.md), [SAFE_OPERATIONS.md](./SAFE_OPERATIONS.md) | **Firewall / air gap:** **Operator** infrastructure; CLI documents **minimal-outbound** and **skip** merges — **closure**. |
| **`--include-glob`** / **`--exclude-glob`**; **`path_scope_dropped_count`** | **Unified gate scope** vs **raw tool scan paths:** Orchestrator **gates** are scoped; per-tool chroot is **adapter config** — **closure** for fail-on behavior. |
| **`safe_operations`**, **`temp_artifacts`**, **`--wipe-temp`** | **Registered** temps only; unknown paths **documented** risk — **closure** = registry + checklist. |
| [HARDENING_CHECKLIST.md](./HARDENING_CHECKLIST.md) | **Org** encryption/retention policies sit outside the repo — **classified**. |

**§1.3 closure:** Safe-ops **deliverables** (redaction version, network posture, globs, wipes, temp snapshot) are **complete** for v2. OS-level enforcement remains **by design** outside the Python CLI.

### 1.4 CI fit

**Target:** Pipelines get stable exit codes, machine-readable gates, and policies that match how teams merge code.

| Shipped (closure) | Residual boundary *(classified)* |
|-------------------|-----------------------------------|
| **`--ci-profile`**, **`--sarif-source`**, [CI_AND_GATES.md](./CI_AND_GATES.md), JUnit + **`correlation_join_rules_version`** | **JSON/SARIF/JUnit vs HTML:** **Documented** in [REPORT_TIERS.md](./REPORT_TIERS.md) — **closure** = no ambiguity for implementers. |
| `ci_gates` / unified findings | **Schedule & runner flavor (PR vs nightly, hosted vs self-hosted):** **Org** — **closure** = docs describe patterns. |
| **`ci_tool_profiles`**, **`check_security_tools --profile`**, **`ci-minimal-tools`** workflow | **`ci-extended` / `full` binaries:** Install matrix **operator-owned**; **ci-minimal** **enforced** in CI — **closure** for default pipeline honesty. |
| [VERSIONING.md](./VERSIONING.md), `report_schema_compat_version` | **Regulated pinning** of consumer installs: **consumer** responsibility; version fields **shipped** — **closure**. |

**§1.4 closure:** CI integration for **Python-centric** reference workflows + portable tool checks is **complete**. Extra **language-specific** workflow templates are **optional samples**, not an unfilled §1 requirement; **org pinning policy** is classified like §4 P1 residual.

### 1.5 Maintainable code

**Target:** Changes are safe: tests, boundaries, logging, and errors are consistent enough for contributors and refactors.

| Shipped (closure) | Residual boundary *(classified)* |
|-------------------|-----------------------------------|
| Logging, TOML/env, `secscan/` layout, adapters | **`security_scan.py` size:** Acceptable **facade**; deeper splits **optional** refactor — not open §1 debt. |
| **`pytest`** — **90** tests; critical path, tool run, phase status, SARIF/CI, adapters | **Coverage growth** tracks new phases — **closure** = CI green + listed suites. |
| **`ToolRunPayload`**, **`attach_run_payload`** on **Phase 1–3 + DAST**; [MAINTAINABILITY.md](./MAINTAINABILITY.md) | **Recon / ZAP / exploit / chain:** Same pattern **optional** when those files change — **§4 P2**, not §1 open gap. |
| `summarize_phases`, **`run.code`** | Dashboard surface **stable** — **closure**. |

**§1.5 closure:** Maintainability **discipline** (typed tool outcomes on primary phases, tests, module boundaries) is **met** for v2. Further **`TypedDict`** / remaining phases are **incremental quality** in §4 P2.

### 1.6 Cross-cutting — discipline closure summary

| Theme | Closure statement |
|-------|-------------------|
| **Correlation** | **Closed:** [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md), `correlation_hints`, baseline merge, replay. A **guaranteed** Shannon-style universal ID is **optional product** (see [Shannon Gap.md](./Shannon%20Gap.md)), not §1 backlog. |
| **Policy / gate truth** | **Closed:** [REPORT_TIERS.md](./REPORT_TIERS.md), [AUDITABILITY.md](./AUDITABILITY.md); baseline ownership = **git** + hash in **`auditability.baseline`**. |
| **Operations** | **Closed:** [HARDENING_CHECKLIST.md](./HARDENING_CHECKLIST.md), [NETWORK_MODE.md](./NETWORK_MODE.md), wipes, globs on **unified** findings. **Service-boundary tagging** in monorepos is **enhancement** (§4 / product), not an open §1 line. |
| **Maintainability** | **Closed:** Phase 1–3 + DAST on `tool_run_result`; see [MAINTAINABILITY.md](./MAINTAINABILITY.md). Remaining phases = **§4 P2** only. |

---

## 2. Principles from SHANNON-PRO.md → local gaps

*Rows reflect **v2** reality: several former “missing” items are **shipped**; gaps narrow to correlation depth, boundaries, procedural audit, and org policy.*

| Shannon Pro principle (from doc) | Why it matters | Gap in this repo (v2) | Address by |
|-----------------------------------|----------------|----------------------|------------|
| **Static–dynamic correlation** | Traceable fixes | **Partial:** `correlation_id` on unified findings + **`correlation_hints`**; **no single guaranteed SAST→PoC key** beyond heuristics | Optional shared `finding_id` / stricter join; keep [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md) as normative |
| **“POC or it didn’t happen”** | Trust in risk | **Partial:** PoC levels + **`report_tier`** / policy docs; CI gates use **unified** JSON, not HTML narrative | Align team policy: `--fail-on` + baseline + [REPORT_TIERS.md](./REPORT_TIERS.md) for human vs machine truth |
| **False positive tagging** | Alert fatigue | **Largely addressed:** `--baseline` fingerprints; triage list on JSON; merge before `fail-on` | Org process: who edits baseline; optional server-side audit of dismissals |
| **Boundary analysis** | Monorepo noise | **Open:** whole `--path`; no first-class service boundaries | `--include`/`--exclude` or manifest; tag findings by boundary |
| **Ephemeral code handling** | Data minimization | **Largely addressed:** [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md), `--wipe-temp`, `--wipe-run-dir`, temp registry | Third-party tools may still drop files outside registry — document + optional stricter tracking |
| **Encrypted storage / isolation** | Enterprise trust | **Partial:** redaction, sanitize exports, webhook minimization | **Org:** KMS, retention, air-gapped runners; tool remains local-first |
| **Self-hosted / data local** | Compliance | **Documented:** [NETWORK_MODE.md](./NETWORK_MODE.md), [HARDENING_CHECKLIST.md](./HARDENING_CHECKLIST.md) | Firewall/OS policy is operator-owned |
| **CI/CD PR scanning** | Workflow | **Largely addressed:** SARIF, JUnit, `--ci-profile`, `--sarif-source`, workflow sample | Stack-specific workflow templates remain optional |
| **Tool orchestration + interpretation** | Consistent outcomes | **Improved:** adapters + **`ToolRunOutcome`** on **Phase 1–3 + DAST** | recon/ZAP/exploit incremental; optional JSON Schema on payloads |
| **Liveness for secrets** | Real exposure | Discipline: no secret exfiltration | Same + optional hash-only fingerprints in logs |
| **Audit / reproducibility** | Verifiability | **Largely addressed:** `run_manifest`, replay bundle, audit JSONL, HMAC | Pentest-grade **ordered procedure log** still partial in JSON |
| **Parallelism + phase model** | Predictability | **Done:** `phase_timings`, TOML timeouts | Per-org tuning of timeouts/budgets |

---

## 3. Core software engineering gaps (implicit in “professional”)

These are not unique to Shannon Pro but are **required** for a robust OSS/commercial-grade CLI. Status is relative to **orchestrator 0.2.9**.

| Area | Original gap | Status (v2 / 0.2.9) |
|------|----------------|---------------------|
| **Modularity** | Monolithic CLI | **Partial:** phases + reporting factored; **`apply_unified_findings_to_report`** in `secscan/unified_report.py`; further splits only when touching related code. |
| **Automated tests** | None / thin | **Strong:** `pytest` suite (**90** tests) — critical path, tool run, phase status, SARIF/CI, adapters, discipline, CLI — extend as phases ship. |
| **Logging** | Print-only | **Done:** stdlib logging, `--verbose`, `--log-json`, `--log-file`. |
| **Configuration** | CLI-only | **Done:** TOML + env + `security_scan.toml.example`. |
| **Dependencies** | Unpinned | **Done:** `requirements.txt` + `pyproject.toml`; **open:** org policy for full matrix lockfiles. |
| **Portability** | Hardcoded paths | **Done:** `secscan/external_paths.py` and env overrides. |
| **Error semantics** | Inconsistent | **Partial:** Phase 1–3 + DAST attach **`run`**; other phases still legacy-only until refactored. |

---

## 4. Prioritized backlog (discipline-first)

### §4 fulfillment snapshot — **~95%** (P0 + P1)

| Bucket | Coverage | Notes |
|--------|----------|--------|
| **P0** | **100%** | Every historical P0 bullet below is **implemented** in orchestrator **≤0.2.9** with docs ([CI_AND_GATES.md](./CI_AND_GATES.md), [AUDITABILITY.md](./AUDITABILITY.md), etc.). |
| **P1** | **~95%** | All **technical** P1 bullets are **shipped** (timings, timeouts, JUnit, workflows, replay/wipe, **`check_security_tools` profiles** + **`ci-minimal-tools`** job). The remaining **~5%** is not a code gap: **org-wide lockfile / CI-matrix policy** (which lockfile format, which OS agents) stays with the enterprise; the repo already provides **`supply_chain` hashes**, [REPRODUCIBILITY.md](./REPRODUCIBILITY.md), and **`check_security_tools.py --profile`**. |

---

### P0 — Safety, trust, and CI honesty *(complete — shipped ≤0.2.9)*
- Baseline / ignore (`--baseline`), `correlation_id` fingerprints, triage slice, **`--emit-baseline-suggestions`**.
- Webhook + argv **redaction**; **`--sanitize-exports`** on disk artifacts.
- **run_manifest** + **replay_bundle** (spec v2: environment, supply chain, optional pip-freeze); join-rules version.
- **SARIF** + **`--sarif-source`**; **`--fail-on`** on unified findings (after baseline + path scope).
- **`--ci-profile`**, JUnit metadata, [CI_AND_GATES.md](./CI_AND_GATES.md).
- Extended: **`auditability`** JSON block; audit JSONL fields; HTML/PDF gate notices.

### P1 — Operability *(technical items complete — shipped ≤0.2.9)*
- **`phase_timings`**; **`[timeouts]`** / **`SECURITY_SCAN_TIMEOUT_*`**.
- **`--junit-output`**; **`.github/workflows/security-scan.yml`** (tests + **`ci-minimal-tools`**).
- **`--replay-bundle-output`**, **`--wipe-temp`**, **`--wipe-run-dir`**; [REPRODUCIBILITY.md](./REPRODUCIBILITY.md).
- **`check_security_tools.py`** **`--profile ci-minimal|ci-extended|full`** + **`--strict`** + **`--json`**.
- Extended: **`--network-mode`**, **`--include-glob` / `--exclude-glob`**; **`safe_operations`** block; cross-cutting docs (audit, safe ops, maintainability).

**P1 residual (org policy, not backlog code):** choose pip-tools vs Poetry vs uv for **your** CI matrix; pin orchestrator per [VERSIONING.md](./VERSIONING.md) in regulated environments.

### P2 — Maintainability *(narrowing)*
- **Open:** **`attach_run_payload`** on **recon, ZAP, exploit, chain**, … when those modules are touched.
- **Open:** Optional **JSON Schema** on adapter payloads; broader pytest for exotic gate matrices if needed.
- **Done:** Phase **1–3** + **DAST**; **`ToolRunPayload`**; **`correlation_hints`**, **`unified_report`**, critical-path + tool-run tests — see [MAINTAINABILITY.md](./MAINTAINABILITY.md).

### P3 — Deeper parity (optional, not “discipline” minimum)
- Reachability SCA, CPG, business-logic agents — **product scope**, not required for engineering discipline.

---

## 5. How to use this doc

- **Product feature gaps** (CPG, invariant fuzzing, etc.) stay in [Shannon Gap.md](./Shannon%20Gap.md) / [SHANNON-PRO.md](./SHANNON-PRO.md) as *capability* comparison.
- **This file** is the checklist for **how** the tool is built and operated so it can sit credibly next to enterprise pipelines—without claiming Shannon Pro feature parity.
- **Operating promises vs non-goals** (for stakeholders): [OPERATING_GUARANTEES.md](./OPERATING_GUARANTEES.md).

---

*v2.0 — established from SHANNON-PRO.md, repo docs, and orchestrator **0.2.9**. Later revisions add CI/unified-SARIF, replay/auditability/safe-ops, path globs, network-mode, **tool-run model on Phase 1–3**, MAINTAINABILITY.md, and related tooling. **§§1–1.6** state **discipline closure** (shipped vs classified boundaries), not open backlog lines.*

---

## 6. Implementation notes (orchestrator)

| Mechanism | Location / usage |
|-----------|------------------|
| `ORCHESTRATOR_VERSION` / `report_schema_compat_version` | `secscan.constants` — see [VERSIONING.md](./VERSIONING.md) |
| `--baseline FILE` | JSON list or `{ "fingerprints": [ "64-hex...", ... ] }` |
| `correlation_id` | Per unified finding; stable hash of phase, tool, type, severity, location, result |
| `replay_bundle` / `CORRELATION_JOIN_RULES_VERSION` | `run_manifest.replay_bundle` (spec_version 2); normative rules in [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md); workspace layout in [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md); policy in [REPRODUCIBILITY.md](./REPRODUCIBILITY.md) |
| `secscan/reproducibility.py` | Runtime fingerprint, supply-chain file hashes, git-relative scan path, optional pip-freeze SHA-256 |
| `secscan/path_scope.py`, `secscan/network_posture.py`, `secscan/safe_operations_embed.py` | Globs on unified findings; network-mode skips; `safe_operations` + temp snapshot |
| [SAFE_OPERATIONS.md](./SAFE_OPERATIONS.md) | Normative safe-ops: network-mode, globs, redaction version, wipe scope |
| `--replay-bundle-output FILE` | CI/archive JSON: `orchestrator_version` + `replay_bundle` only |
| `--wipe-run-dir` | After exit 0, delete `workspace/RUN_ID` (not with `--resume` / `--no-checkpoint`) |
| `report_tier` / `report_policy` | JSON fields; HTML/PDF layout per [REPORT_TIERS.md](./REPORT_TIERS.md) |
| `auditability` | `secscan/auditability_embed.py` — gate truth, baseline hashes, procedural timeline; [AUDITABILITY.md](./AUDITABILITY.md) |
| `--audit-log-jsonl` / `--hmac-sign-report` | Append-only audit line; HMAC sidecar next to JSON |
| `--wipe-temp` | After exit 0, delete registered temp files (see `secscan/temp_registry.py`) |
| `export_limits` / `sanitize_report_copy` | HTML/PDF clip + redact; sanitized JSON string cap |
| `--sarif-output FILE` | Semgrep, Bandit, Nuclei; empty `results` if phases skipped |
| `--sarif-source` | `tool_native` \| `unified` — CI gate alignment vs SARIF provenance |
| `--ci-profile` | `secscan/ci_profile.py` — stable CI-oriented defaults (see [CI_AND_GATES.md](./CI_AND_GATES.md)) |
| Tool install profiles | `secscan/ci_tool_profiles.py`; `check_security_tools.py --profile … [--strict] [--json]` |
| `--sanitize-exports` | Redacted JSON/HTML/PDF on disk |
| `--junit-output FILE` | Minimal JUnit for CI gates |
| `phase_timings` / `correlation_hints` | Report JSON fields |
| `ToolRunOutcome` / `run` payload | `secscan/tool_run_result.py`, `secscan/tool_run_types.py` — Phase 1–3 in `secrets_sast_deps.py`, DAST in `dast.py` |
| [MAINTAINABILITY.md](./MAINTAINABILITY.md) | Tool-run model and phase coverage |
| Unified counts / triage | `secscan/unified_report.py` — `apply_unified_findings_to_report` |
| Tests | `pytest tests/` — `test_critical_path.py`, `test_tool_run_result.py`, `test_phase_status_secrets_run.py`, `test_sarif_ci.py`, `test_ci_tool_profiles.py`, `test_reproducibility.py`, `test_auditability_embed.py`, `test_path_scope.py`, `test_safe_operations_embed.py`, `test_report_tiers.py`, `test_export_limits.py`, `test_temp_registry.py`, `test_correlation_and_timeouts.py`, `test_discipline.py`, `test_secscan.py`, `test_tool_adapters*.py` |
| Tool adapters | `secscan/tool_adapters/` — `runner.run_with_retries`, `secrets_parsers`, `dependency_parsers`, `dast_parsers`, `sast` (Semgrep/Bandit); phase payloads may include `integration`: `{adapter, attempts, elapsed_ms, retried, exit_code}` |
| Optional deps | `requirements.txt` |
