# Maintainability (one error model, typing, tests)

## Tool run payload (`run`)

External tools should attach a canonical **`run`** object on each tool dict:

- **`code`** — `OK`, `NONZERO_EXIT`, `TIMEOUT`, `BINARY_NOT_FOUND`, `SETUP_FAILED`, …
- **`message`** — short stderr or reason (capped in `attach_run_payload`)
- **`exit_code`** — subprocess exit code when applicable

Implementation: **`secscan/tool_run_result.py`** (`ToolRunOutcome`, `attach_run_payload`, `outcome_from_exit_code`).

Typed shape: **`secscan/tool_run_types.py`** (`ToolRunPayload`).

**`secscan/phase_status.summarize_phases`** reads `run.code` for dashboards.

## Coverage in phases

| Area | Status |
|------|--------|
| DAST (nuclei, schemathesis) | Uses `attach_run_payload` |
| Secrets, SAST, dependencies (gitleaks, detect-secrets, semgrep, bandit, pip-audit, safety) | **Wired** via `_finalize_tool` in `secscan/phases/secrets_sast_deps.py` |
| Recon, ZAP, exploit, … | Incremental when those modules are refactored |

## Tests

- **`tests/test_tool_run_result.py`** — attach / propagate semantics  
- **`tests/test_phase_status_secrets_run.py`** — `phase_status` + `run`  
- **`tests/test_critical_path.py`** — gates + unified list  

Keep **`pytest tests/`** green in CI.
