# Safe operations (defaults, scope, redaction, cleanup)

This document ties together [OPERATING_GUARANTEES.md](./OPERATING_GUARANTEES.md), [NETWORK_MODE.md](./NETWORK_MODE.md), [HARDENING_CHECKLIST.md](./HARDENING_CHECKLIST.md), and the structured **`safe_operations`** object on every JSON report.

## What the orchestrator enforces vs what is operator-owned

| Topic | In-tool | Operator / platform |
|-------|---------|---------------------|
| **Secret pattern redaction** | Best-effort patterns in exports/webhooks; **`REDACTION_RULESET_VERSION`** in `run_manifest` | Formal classification, DLP, encryption at rest |
| **Network isolation** | **`--network-mode`** merges documented `--skip` presets | OS/container firewall, air gap — see NETWORK_MODE.md |
| **Monorepo / service scope** | **`--include-glob`** / **`--exclude-glob`** filter **unified findings** (after collection) | CI matrix, repo layout policy |
| **Temp cleanup** | **`--wipe-temp`** removes **registered** paths only | Disk hygiene, VM snapshots |
| **Checkpoint cleanup** | **`--wipe-run-dir`** after success | Retention policy |

## `--network-mode`

| Value | Extra `--skip` merged |
|-------|----------------------|
| **`default`** | None |
| **`minimal-outbound`** | `recon` (reduces DNS-driven recon) |
| **`offline-static`** | `recon`, `code_ai`, `ai` |

Union with your explicit `--skip` and with **`--ci-profile`** (all are merged).  
Env: **`SECURITY_SCAN_NETWORK_MODE`**.

## Path scope (`--include-glob` / `--exclude-glob`)

- Patterns use **`fnmatch`** against paths **relative to `--path`** (after resolving file locations from `location` fields).
- **`file:line`** locations are handled; **URL** locations (typical DAST) are **not** dropped when includes are set — so service-scoped static scans can still keep DAST rows.
- Repeat flags for multiple patterns. Env: **`SECURITY_SCAN_INCLUDE_GLOBS`**, **`SECURITY_SCAN_EXCLUDE_GLOBS`** (comma-separated).

The report records **`path_scope_dropped_count`** when globs are active.

## `report["safe_operations"]`

Includes **`network_mode`**, path scope lists, **`redaction.ruleset_version`**, export/wipe flags, **`temp_artifacts`** (registered count + sample basenames), and reminders about firewall and temp scope.

## Redaction ruleset

When **`REDACTION_RULESET_VERSION`** bumps, pattern sets changed — review [OPERATING_GUARANTEES.md](./OPERATING_GUARANTEES.md) and retest export flows if you rely on specific redaction behavior.
