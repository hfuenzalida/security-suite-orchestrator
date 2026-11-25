# Security Scan Report

## Scope
Security review performed against `E:\Estrategias\Projects\Security Scan`.

Reviewed areas:

- Python orchestrator and supporting modules under `secscan/`
- top-level runner `security_scan.py`
- auth/session, checkpointing, export, SARIF, and chain-handling paths
- CI workflow and example config/auth material
- Rust trading component under `polymarket-lag-arb/`

This pass was a source-driven security review focused on practical exploitability and insecure defaults. It did not rely on documentation claims alone.

## Executive Summary
The scan found 10 actionable security issues:

1. High severity: 6 — **all patched**
2. Medium severity: 4 — **all patched**

Remediated themes:

- path traversal and destructive file operations from unsanitized run identifiers
- leakage of authenticated session material into reports, checkpoints, and SARIF
- cross-origin replay of cookies and auth headers
- live trading logic on stale external price data or detached execution caps
- CI least-privilege permissions and pinned dependency installs
- auth config env-based secret references and non-panicking Rust timing validation

## High Severity Findings
### 1. Path traversal in `--run-id` / `--resume` can escape the workspace — FIXED
- Affected files: `secscan/checkpoint_core.py`, `security_scan.py`
- Patch: opaque `validate_run_id` / `resolve_run_dir`; checkpoint and `--wipe-run-dir` refuse paths that escape `workspace.resolve()`.
- Regression: `tests/test_high_severity_hardening.py`

### 2. Auth cookies and headers are replayed across unrelated hosts without scope enforcement — FIXED
- Affected files: `secscan/http_session.py`, `secscan/phases/auth_session.py`, `secscan/phases/chain.py`, `secscan/phases/dast.py`, `secscan/http_client.py`
- Patch: session credentials are scoped to `allowed_hosts` derived from login/base URL; `merge_req_headers(url=...)` and nuclei/chain omit cookies for out-of-scope hosts.
- Regression: `tests/test_high_severity_hardening.py`

### 3. Auth/session secrets are persisted into checkpoints and reports in cleartext — FIXED
- Affected files: `secscan/session_sanitize.py`, `secscan/checkpoint_core.py`, `secscan/phases/auth_session.py`, `secscan/phases/chain.py`, `security_scan.py`
- Patch: auth/chain return non-secret metadata; `strip_session_secrets` runs on checkpoint write and on-disk JSON/HTML reports; resume re-runs auth/chain when credentials are absent.
- Regression: `tests/test_high_severity_hardening.py`

### 4. SARIF output can publish unsanitized secret evidence — FIXED
- Affected files: `secscan/sarif_emit.py`
- Patch: secret-bearing findings redact evidence; other evidence passes through `redact_sensitive_text`.
- Regression: `tests/test_high_severity_hardening.py`

### 5. Live Polymarket orders can execute using a static, strategy-detached max price — FIXED
- Affected files: `polymarket-lag-arb/src/price_cap.rs`, `execution.rs`, `engine.rs`, `config.rs`
- Patch: FOK buy price is `min(worst ceiling, ask + max_ask_slip, fair - min_edge)` at submit time; aborts if ask blew through the bound.
- Regression: unit tests in `price_cap.rs`

### 6. The Polymarket bot can keep trading on stale CEX data after feed failure — FIXED
- Affected files: `polymarket-lag-arb/src/feeds.rs`, `engine.rs`, `config.rs`
- Patch: `max_cex_staleness` gate in `evaluate`; RTDS end clears CEX state (fail closed).
- Regression: unit tests in `engine.rs`

## Medium Severity Findings
### 7. Chain-captured values are logged in plaintext — FIXED
- Affected files: `secscan/phases/chain.py`
- Patch: default logs are name+length only; set `SECSCAN_UNSAFE_CHAIN_DEBUG=1` for value inspection. Captured values are omitted from phase results.
- Regression: `tests/test_medium_severity_hardening.py`

### 8. CI installs mutable PyPI dependencies on PRs and does not declare least-privilege token permissions — FIXED
- Affected files: `.github/workflows/security-scan.yml`, `requirements.txt`, `requirements-ci-tools.txt`
- Patch: workflow `permissions: contents: read`, `persist-credentials: false` on checkout, exact `==` pins for app and CI-tool dependencies.
- Regression: `tests/test_medium_severity_hardening.py`

### 9. Shipped auth examples normalize plaintext credential storage — FIXED
- Affected files: `auth.example.json`, `secscan/config_io.py`
- Patch: loader resolves `${ENV_VAR}` / `${ENV_VAR:-default}`; example uses env refs for username/password/TOTP.
- Regression: `tests/test_medium_severity_hardening.py`

### 10. Invalid env timing values can panic the Rust process at startup — FIXED
- Affected files: `polymarket-lag-arb/src/config.rs`
- Patch: finite/non-negative checks plus `Duration::try_from_secs_f64` (no panic on bad floats).
- Regression: unit tests in `config.rs`

## Prioritized Remediation Order
1. Fix run-id path traversal and workspace escape first.
2. Stop persisting raw auth/session material into checkpoints, reports, and SARIF.
3. Enforce cookie/header origin scoping across auth, chain, and downstream scan phases.
4. Harden the Rust live trading path with fresh-data and bounded-price execution checks.
5. Lock down CI dependency resolution and token permissions.

## Notes
- This report is based on direct source inspection of the current tree.
- The issues above are actionable security findings, not style or maintainability suggestions.
