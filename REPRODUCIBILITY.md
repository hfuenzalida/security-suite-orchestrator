# Reproducibility and supply-chain pins

This document complements [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md) and [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md). It describes **what the orchestrator records** so you can compare runs, audit environments, and align dependency locks across CI matrices.

## What “reproducible” means here

End-to-end **determinism** is **not** claimed: external tools, network targets, timing, and machine-specific paths all affect outputs. The orchestrator **does** emit enough metadata to **explain** why two runs differ and to **replay** the same logical configuration when combined with your repo and tooling.

## `run_manifest.replay_bundle` (spec_version 2)

Every JSON report includes `run_manifest.replay_bundle` with:

| Field | Purpose |
|-------|---------|
| `join_rules_version` | Bumps when correlation/baseline **semantics** change ([CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md)). |
| `config_sha256` | Hash of the effective TOML config file (if any). |
| `scan_path_resolved` | Absolute `--path` for traceability. |
| `scan_path_git_relative` | Path of `--path` relative to `git` root when inside a repo — **advisory** for human diffing; **does not** alter `correlation_id`. |
| `environment` | `platform`, Python version/implementation (no secrets). |
| `supply_chain.files` | SHA-256 of manifests under `--path`: `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock` (each key only set if the file exists). |
| `tool_versions` | Best-effort `--version` lines for Python, Semgrep, Bandit, Gitleaks, Nuclei, pip-audit, detect-secrets, safety, schemathesis. |
| `determinism_note` | Short reminder that tools/network are not fully deterministic. |
| `pip_freeze_sha256` | **Optional** — SHA-256 of `pip freeze` for the **current interpreter** (see below). |

Use `--replay-bundle-output FILE` to archive only `orchestrator_version` + `replay_bundle` for compliance storage.

## Optional full environment pin (`pip freeze`)

When you need a **complete** Python dependency fingerprint (e.g. regulated audits):

```bash
python security_scan.py --path . --url "$URL" --replay-include-pip-freeze --output report.json
```

Or set **`SECURITY_SCAN_REPLAY_PIP_FREEZE=1`**. This runs `pip freeze` once and stores a **SHA-256** of the output (not the raw list — avoids leaking internal package names in shared logs if you copy only the hash).

**Cost:** slower startup; use for nightly or release jobs, not every PR, unless your policy requires it.

## Lockfile strategy (org policy)

The orchestrator hashes **committed** manifest files; it does not generate locks. Recommended patterns:

1. **pip-tools** — `pip-compile requirements.in -o requirements.txt` (or platform-specific outputs); commit the lock; CI installs with `pip install -r requirements.txt`.
2. **Poetry / PDM / uv** — commit `poetry.lock` / `uv.lock`; `supply_chain.files` will include their hashes when present under `--path`.
3. **Matrix builds** — use the same lock per job or separate reports per OS with `replay_bundle.environment.platform` to explain intentional drift.

## Path-stable `correlation_id` comparisons

`correlation_id` includes the **`location`** string from each tool. If tools emit **absolute** paths, two checkouts at different directories produce **different** IDs for the same logical finding.

Mitigations:

- Prefer scans where tools emit **repo-relative** paths (tool configuration).
- Compare using the same **resolved** `--path` and same **git commit** (`run_manifest.git.commit`).
- Use `replay_bundle.scan_path_git_relative` to confirm you scanned the intended subtree.

## Retention

Long-term artifact retention is **organizational** (SIEM, object storage, encryption). The workspace contract and `--wipe-*` flags describe **local** cleanup only; see [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md).
