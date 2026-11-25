# Correlation join rules

This document is the **normative reference** for how unified findings are keyed, how baselines suppress them, and how dynamic hints relate to static rows. The orchestrator exposes `run_manifest.replay_bundle.join_rules_version` (see `secscan.constants.CORRELATION_JOIN_RULES_VERSION`); when that version changes, re-baseline if you rely on fingerprint stability across upgrades.

## Unified `correlation_id`

Every row in the **unified findings list** (used for `--fail-on`, baselines, and triage) carries a `correlation_id`: a **64-character lowercase hex** string, SHA-256 over a pipe-separated tuple:

| Field order | Source |
|-------------|--------|
| 1 | `phase` (e.g. `SAST`, `Secrets`, `DAST`) |
| 2 | `tool` (e.g. `semgrep`, `nuclei`) |
| 3 | `type` (rule id, vuln id, or category string) |
| 4 | `severity` |
| 5 | `location` (path, `file:line`, or URL fragment as emitted by the collector) |
| 6 | `result` (e.g. `POTENTIAL`, `EXPLOITED`) |

Implementation: `secscan.findings_unified.stable_correlation_id`. Empty missing fields are treated as empty strings; changing any normalized field changes the id.

**Join rule:** two artifacts refer to the “same” unified finding if and only if their `correlation_id` values are **identical** (after lowercasing for baseline file entries).

## Baseline files

Baseline JSON lists **64-hex** `correlation_id` values (or `{ "fingerprints": [ ... ] }`). A finding is **suppressed** when its `correlation_id` is in that set **before** gate evaluation (`filter_findings_by_baseline`).

**Join rule:** baseline entries match unified findings **only** by exact `correlation_id`; there is no partial or fuzzy match.

## `correlation_hints` (heuristic)

`correlation_hints` pairs PoC/exploit confirmations with SAST rows when **paths or URLs overlap** (see `secscan.correlation_bridge`). These are **not** join keys: they do not assign shared `correlation_id`s and must be verified manually.

## Replay and comparison across machines

- Paths in `location` may differ in separators; the orchestrator normalizes where it aggregates, but **identical code checked out at different paths** can yield different `correlation_id`s if `location` embeds absolute paths. Prefer scanning with stable relative paths when comparing runs.
- Use `run_manifest.replay_bundle` for **pinned tool version strings**, **config file SHA-256**, **resolved scan path**, **runtime environment**, **dependency manifest hashes**, and optional **`pip_freeze_sha256`** to interpret a report months later.

### `replay_bundle.spec_version`

- **`2` (current):** Adds `environment`, `supply_chain`, `scan_path_git_relative`, `determinism_note`, and optional `pip_freeze_sha256`; `scan_path_resolved` is always absolute. See [REPRODUCIBILITY.md](./REPRODUCIBILITY.md).

`join_rules_version` still governs **correlation_id** / baseline semantics only; replay metadata can grow without changing unified finding keys.

See also [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md) and [REPRODUCIBILITY.md](./REPRODUCIBILITY.md).
