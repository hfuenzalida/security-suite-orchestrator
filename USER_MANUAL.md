# Security Suite Orchestrator — User Manual

This manual explains **what the orchestrator does**, how to run a **full review**, and how to run **focused (partial) reviews** by topic using `--skip`, presets, and configuration.

**Related:** [OPERATING_GUARANTEES.md](OPERATING_GUARANTEES.md) (what is / isn’t promised), [CI_AND_GATES.md](CI_AND_GATES.md) (CI, exit codes, SARIF), [README.md](README.md) (install pointer), [legal/README.md](legal/README.md) (license & terms).

---

## 1. What this tool is

The **Security Suite Orchestrator** is a **local** multi-phase scanner: it runs **third-party security tools** (SAST, secret scanners, dependency auditors, DAST, optional browser automation, ZAP, PoC checks, optional local Ollama AI phases) and **merges results** into JSON/HTML/PDF and optional **SARIF / JUnit** for CI.

- **You** choose the codebase path, target URL (for dynamic phases), what to skip, and how strict CI should fail (`--fail-on`).
- **Gate truth** for automation is **JSON unified findings** (+ exit code), not HTML alone — see [REPORT_TIERS.md](REPORT_TIERS.md).

---

## 2. Installation and invocation

### Install (editable)

```bash
pip install -e .
security-scan --version
security-scan --help
```

### Run without installing

```bash
python security_scan.py --version
python security_scan.py --help
```

The CLI accepts an optional `run` prefix: `security-scan run …` is the same as `security-scan …`.

### Verify tools before a big run

- **Quick matrix (CI-style):** `security-scan --doctor`  
- **Explicit profile:** `security-scan doctor --profile ci-minimal` (or `ci-extended`, `full`)  
- **Script:** `python check_security_tools.py --profile ci-minimal`

See [CI_AND_GATES.md](CI_AND_GATES.md) for profiles.

---

## 3. Core concepts

| Concept | Meaning |
|--------|---------|
| **`--path`** | Root directory of the **source tree** to scan (SAST, secrets, deps, AI-on-code). Default: `.` |
| **`--url`** | **HTTP(S) target** for recon, DAST, browser, ZAP, agents, exploit. If omitted, those phases **do not run** (you’ll see a skip warning). |
| **Workspace / run id** | Checkpoints live under `--workspace` (default `scan_workspace`), in a folder per **run id** (derived from URL + path hash, or `--run-id`, or `--resume RUN_ID`). |
| **Checkpoint** | After each phase, state can be saved so `--resume` can continue. Use `--no-checkpoint` to disable. |
| **`--skip`** | Space-separated phase **tokens**; see §5. Skips are **unioned** with presets like `--ci-profile` or `--network-mode`. |

---

## 4. Execution order (phases)

Phases run in this **fixed order**. Each row lists the **`--skip` token** used to disable it.

| Order | Skip token | Needs `--url`? | Role (short) |
|------|------------|----------------|--------------|
| 1 | `code_ai` | No | Local Ollama: AI-assisted **code** threat model (Phase 0.5) |
| 2 | `secrets` | No | **Secrets:** gitleaks, detect-secrets |
| 3 | `sast` | No | **SAST:** Semgrep, Bandit |
| 4 | `deps` | No | **Dependencies:** pip-audit, safety, etc. |
| 5 | `recon` | Yes | **Recon:** nmap, subfinder, whatweb (needs URL) |
| — | `auth` | Yes | **Authenticated session** — only if `--auth-config` is set |
| — | `chain` | Yes | **Multi-step HTTP chain** — only if `--chain-config` is set |
| 6 | `dast` | Yes | **DAST:** nuclei, schemathesis, … |
| 7 | `browser` | Yes | **Playwright** browser automation |
| 8 | `zap` | Yes | **OWASP ZAP** proxy DAST |
| 9 | `agents` | Yes | **Specialized agents** |
| 10 | `exploit` | Yes | **PoC exploitation** phase |
| 11 | `ai` | No | **AI reasoning** over collected phases (Ollama) — not the same as `code_ai` |

**Notes:**

- **`auth`** / **`chain`** run only when you pass **`--auth-config`** / **`--chain-config`**; otherwise they are not entered. You can still `--skip auth` or `--skip chain` when those configs are present.
- Without **`--url`**, URL-backed phases are **skipped automatically** (with a warning), even if not listed in `--skip`.

---

## 5. Phase tokens reference

Use these exact names with `--skip` (and in TOML `skip = [...]`):

`code_ai` · `recon` · `secrets` · `sast` · `deps` · `auth` · `chain` · `dast` · `browser` · `zap` · `agents` · `exploit` · `ai`

**Example:** skip optional heavy / interactive parts:

```bash
security-scan --path . --url http://localhost:8080 --skip browser zap exploit ai code_ai
```

---

## 6. Starting a complete review

A **complete** run means: **all phases you care about**, with a **URL** if you want dynamic testing, and minimal skipping.

### 6.1 Full static + dynamic (recommended “audit” shape)

1. Install tools (`doctor` or `check_security_tools.py --profile full` on a capable machine).
2. From the repo root (or your app root):

```bash
security-scan --path . --url https://your-app.example --output security_report.json
```

3. Add **`--auth-config`** / **`--chain-config`** if you need logged-in or multi-step API flows (see your `auth.example.json`, `chain.example.json` patterns).
4. Open **`security_report.json`** (gate truth) and **`security_report.html`** (human narrative). PDF path defaults alongside JSON/HTML.

### 6.2 Full static-only (no running app)

If you have **no URL**, dynamic phases will not execute; you still get **code_ai** (unless skipped), **secrets**, **sast**, **deps**, and **ai** summarization:

```bash
security-scan --path . --output report.json
```

To avoid Ollama usage, skip both AI phases:

```bash
security-scan --path . --output report.json --skip code_ai ai
```

### 6.3 CI merge pipeline (fast, gate-friendly)

Uses **`--ci-profile`**: merges extra skips (`code_ai`, `recon`, `browser`, `zap`, `agents`, `exploit`, `ai`), sets **technical** HTML tier, and sets **`--fail-on high`** if you left `fail_on` at `never`.

```bash
security-scan run --path . --url http://localhost:8080 \
  --ci-profile --fail-on high \
  --sarif-output results.sarif --sarif-source unified \
  --junit-output junit.xml
```

Details: [CI_AND_GATES.md](CI_AND_GATES.md).

---

## 7. Partial reviews by topic

Use **`--skip`** to keep only the topics you need. The tables below list **typical** skip sets; adjust if you want to include/exclude **`code_ai`** / **`ai`** (Ollama) or **`recon`**.

### 7.1 Topic → what stays enabled

| Goal | Keep (roughly) | Typical `--skip` (when `--url` is set) |
|------|----------------|----------------------------------------|
| **Secrets only** | `secrets` | `code_ai sast deps recon auth chain dast browser zap agents exploit ai` |
| **SAST only** | `sast` | `code_ai secrets deps recon auth chain dast browser zap agents exploit ai` |
| **Dependencies only** | `deps` | `code_ai secrets sast recon auth chain dast browser zap agents exploit ai` |
| **Static trio (secrets + SAST + deps)** | `secrets`, `sast`, `deps` | `code_ai recon auth chain dast browser zap agents exploit ai` |
| **Dynamic only** (URL required) | recon + DAST stack | `code_ai secrets sast deps auth chain ai` (+ often `browser zap agents` if you want only nuclei/DAST core — tune to taste) |
| **DAST + browser + ZAP** | URL phases | Skip static: `code_ai secrets sast deps ai` (and `auth`/`chain` if unused) |
| **Minimal network / air-gapped static** | static phases | `--network-mode offline-static` (adds skips: `recon`, `code_ai`, `ai`) — see [NETWORK_MODE.md](NETWORK_MODE.md) |
| **Less outbound DNS** | — | `--network-mode minimal-outbound` (adds `recon` skip) |

**Without `--url`:** URL phases are already inactive; focus skips on **`code_ai`**, **`secrets`**, **`sast`**, **`deps`**, **`ai`**.

### 7.2 Copy-paste recipes

**Repository secret + quality gate (no Ollama):**

```bash
security-scan --path . --skip code_ai ai recon auth chain dast browser zap agents exploit --output report.json
```

**Dependency audit day:**

```bash
security-scan --path . --skip code_ai secrets sast recon auth chain dast browser zap agents exploit ai
```

**Dynamic / pentest slice (static already done elsewhere):**

```bash
security-scan --path . --url http://localhost:8080 \
  --skip code_ai secrets sast deps ai
```

(Add `--skip auth` or `--skip chain` if you do not use those configs.)

---

## 8. Configuration files and environment

### TOML

Copy [security_scan.toml.example](security_scan.toml.example) to **`security_scan.toml`** or **`secscan.toml`** in the working directory (or pass **`--config path`**).

- **`[defaults]`** — default `path`, `url`, `skip`, `fail_on`, `report_tier`, `sarif_source`, etc.
- **`[paths]`** — tool paths (ZAP, nmap) via env injection.
- **`[timeouts]`** — per-tool budgets (maps to `SECURITY_SCAN_TIMEOUT_*`).
- **`[ci] profile = true`** — same idea as `--ci-profile`.

### Environment

Prefix **`SECURITY_SCAN_`** (see [secscan/user_config.py](secscan/user_config.py)): e.g. `SECURITY_SCAN_URL`, `SECURITY_SCAN_FAIL_ON`, `SECURITY_SCAN_CI_PROFILE=1`, `SECURITY_SCAN_NETWORK_MODE=offline-static`, `SECURITY_SCAN_CONFIG` for a config path.

CLI flags override TOML and env.

### Inspect merged config (no scan)

```bash
security-scan --config-dry-run -v
```

---

## 9. Outputs and CI behavior

| Output | Flag | Notes |
|--------|------|--------|
| JSON report | `--output` | Unified findings, phases, `run_manifest`, audit fields — **primary machine truth** |
| HTML / PDF | `--html`, `--pdf` | Narrative tier: `--report-tier executive|technical|full` |
| SARIF | `--sarif-output` | Use `--sarif-source unified` to align rows with `--fail-on` — [CI_AND_GATES.md](CI_AND_GATES.md) |
| JUnit | `--junit-output` | Pass/fail testcase + properties for dashboards |
| Baseline | `--baseline` | JSON of `correlation_id` fingerprints to exclude from gates |
| Sanitized exports | `--sanitize-exports` | Redact sensitive strings in written artifacts |

**Exit codes:** `0` = success and `--fail-on` satisfied; `1` = gate/policy failure or bad args — [CI_AND_GATES.md](CI_AND_GATES.md).

---

## 10. Resume, replay bundles, hygiene

- **`--resume RUN_ID`** — continue from `workspace/RUN_ID/checkpoint.json` (same `--path`, `--url`, `--auth-config`, `--chain-config` as original).
- **`--replay-bundle-output`** — write reproducibility metadata for archives; see [REPRODUCIBILITY.md](REPRODUCIBILITY.md).
- **`--wipe-run-dir`** / **`--wipe-temp`** — delete workspace or temp artifacts after success; see [WORKSPACE_CONTRACT.md](WORKSPACE_CONTRACT.md), [HARDENING_CHECKLIST.md](HARDENING_CHECKLIST.md).

---

## 11. Subcommands and utilities

| Command | Purpose |
|---------|---------|
| `security-scan replay --help` | Replay-bundle workflow help (bundle is produced during normal runs). |
| `security-scan doctor` | Tool install matrix (profiles). |
| `--print-completion bash\|zsh\|pwsh` | Shell completion script on stdout. |

---

## 12. Document index

| Topic | Document |
|--------|----------|
| Supported use & limits | [OPERATING_GUARANTEES.md](OPERATING_GUARANTEES.md) |
| CI, SARIF, JUnit, exit codes | [CI_AND_GATES.md](CI_AND_GATES.md) |
| HTML vs CI truth | [REPORT_TIERS.md](REPORT_TIERS.md) |
| Network / safe ops | [NETWORK_MODE.md](NETWORK_MODE.md), [SAFE_OPERATIONS.md](SAFE_OPERATIONS.md) |
| Correlation / baselines | [CORRELATION_JOIN_RULES.md](CORRELATION_JOIN_RULES.md) |
| Versioning | [VERSIONING.md](VERSIONING.md) |
| CLI roadmap (professional CLI) | [CLI_ROADMAP.md](CLI_ROADMAP.md) |
| Legal / license | [legal/README.md](legal/README.md) |

---

*Orchestrator version is shown by `security-scan --version` (`ORCHESTRATOR_VERSION` in `secscan/constants.py`).*
