# Professional CLI — roadmap & progress

**Goal:** A **professional**, **expert-grade** command-line interface on top of the existing orchestrator: predictable help, stable entry points, scriptable behavior, and progressive enhancement—without replacing the engine.

**Baseline (before Phase 1): ~30%** — Full feature set via flat `argparse`; minimal `description`; `python security_scan.py` only; no `--version`; help text did not show defaults consistently.

**After Phase 1:** ~**45%** — Installable `security-scan`, `--version`, defaults in `--help`, doc epilog.

**After Phase 2:** ~**60%** — `NO_COLOR` / `CLICOLOR`, `--quiet` / `SECURITY_SCAN_QUIET`, compact stderr summary.

**After Phase 3:** ~**75%** — Grouped `--help`; optional `run` prefix; `replay` workflow stub.

**After Phase 4:** ~**85%** — `--print-completion bash|zsh|pwsh`; `--config-dry-run`.

**After Phase 5:** ~**95%** — `security-scan doctor` / `--doctor`; shared [secscan/tool_doctor.py](secscan/tool_doctor.py).

**After Phase 6 (current): ~100%** — Exit-code epilog (aligned with [CI_AND_GATES.md](CI_AND_GATES.md)); [tests/test_cli_phase6.py](tests/test_cli_phase6.py) guards help/version/flags/unknown argv.

**Current orchestrator:** `0.2.9` — see `secscan/constants.py`.

---

## Phase summary *(cumulative “professional CLI” maturity)*

| Phase | Focus | Deliverables | Cumulative % |
|-------|--------|--------------|--------------|
| **1** | **Identity & help** | Installable `security-scan` console script; `--version`; `ArgumentDefaultsHelpFormatter`; rich `epilog` with doc pointers; stable `prog` | **45%** |
| **2** | **Output discipline** | `NO_COLOR` / `CLICOLOR` respect; optional `--quiet` (errors-only to stderr); phase headers aligned with `cli_output` | **60%** |
| **3** | **Structure** | Subcommands or **topic help** (`--help` groups / `run` vs `doctor`); reduce cognitive load for 40+ flags | **75%** |
| **4** | **Expert productivity** | Optional shell completions (bash/zsh/PowerShell); `--show-config` / validate TOML without full scan | **85%** |
| **5** | **Integrated diagnostics** | Single entry to **`check_security_tools`** profiles (`security-scan doctor` or `--doctor`); link versions to report JSON | **95%** |
| **6** | **Hardening** | Exit-code epilog + tests for `--help` / `--version` / critical flags / unknown argv | **100%** |

Progress is **CLI UX only**; engine discipline remains tracked in [DISCIPLINE_ENGINEERING_GAPS.md](./DISCIPLINE_ENGINEERING_GAPS.md).

---

## Phase 1 *(complete — 45%)*

- [x] `pyproject.toml`: `[project.scripts]` → `security-scan = "security_scan:main"`
- [x] `pyproject.toml`: setuptools discovers `secscan` + top-level `security_scan` module
- [x] `--version` reporting `ORCHESTRATOR_VERSION` (and key compat tokens)
- [x] Parser: `prog=security-scan`, `ArgumentDefaultsHelpFormatter`, `epilog` with links to OPERATING_GUARANTEES, CI_AND_GATES, REPORT_TIERS
- [x] Tests: `tests/test_cli_professional.py` — `--version` exit 0; `--help` contains epilog pointers

## Phase 2 *(complete — 60%)*

- [x] **`NO_COLOR`** (non-empty disables color) and **`CLICOLOR`** (`0` off, `1` force on; else TTY) in `secscan/cli_output.py` — `refresh_cli_ansi()` for tests
- [x] **`--quiet` / `-q`** and **`SECURITY_SCAN_QUIET`** / `[defaults] quiet` in TOML — suppress `ok`/`info`/`header`; **`fail`/`warn`** → stderr; **`print_final_summary`** → compact stderr block
- [x] Tests in `tests/test_cli_professional.py`

## Phase 3 *(complete — 75%)*

- [x] **Grouped `--help`** via `add_argument_group` in [secscan/cli_run_parser.py](secscan/cli_run_parser.py): Core scan, Reports & exports, CI & gating, Replay & reproducibility, Safe operations & scope, Notifications & audit, Config & logging
- [x] Optional **`run`** prefix: `security-scan run …` ≡ bare `security-scan …` (same argv after stripping)
- [x] **`security-scan replay`** stub: workflow text + `--print-workflow`; points to `--replay-bundle-output` and REPRODUCIBILITY.md (no separate replay engine)

## Phase 4 *(complete — 85%)*

- [x] **`--print-completion bash|zsh|pwsh`** — [secscan/cli_completions.py](secscan/cli_completions.py); introspects the run parser for flags; bash/zsh suggest `run`/`replay` on first token
- [x] **`--config-dry-run`** — [secscan/cli_config_dry_run.py](secscan/cli_config_dry_run.py); resolved TOML path, `SECURITY_SCAN_*` summary, full namespace after optional CI/network transforms
- [x] Tests in `tests/test_cli_professional.py`

## Phase 5 *(complete — 95%)*

- [x] **`security-scan doctor`** — delegates to [secscan/tool_doctor.py](secscan/tool_doctor.py) (`--profile`, `--strict`, `--json`); human table respects `NO_COLOR`; JSON adds `orchestrator_version`, `cli_entry`
- [x] **`check_security_tools.py`** — thin wrapper on same module (stable scripts/CI)
- [x] **`--doctor`** on main run parser — shorthand default matrix, then exit
- [x] Completions: first-token **`doctor`** (bash/zsh/pwsh)

## Phase 6 *(complete — 100%)*

- [x] **Exit codes** in [secscan/cli_run_parser.py](secscan/cli_run_parser.py) `CLI_RUN_EPILOG` — mirrors [CI_AND_GATES.md](CI_AND_GATES.md) (0 = policy satisfied; 1 = gate/args/controlled failure)
- [x] **[tests/test_cli_phase6.py](tests/test_cli_phase6.py)** — help contains exit block; **critical long flags** subset-locked via parser introspection; `--version` shape; unknown flag → exit **2**; epilog module string; Unicode argv smoke

---

## How to install the CLI entry point

```bash
pip install -e .
security-scan --version
security-scan --help
```

Without install, the script still runs as:

```bash
python security_scan.py --version
python security_scan.py run --path . --url http://localhost:8080
python security_scan.py replay --print-workflow
eval "$(python security_scan.py --print-completion bash)"
python security_scan.py --config-dry-run --ci-profile
python security_scan.py doctor --profile ci-minimal --json
python security_scan.py --doctor
```

---

*Phase 6 shipped — professional CLI roadmap complete.*
