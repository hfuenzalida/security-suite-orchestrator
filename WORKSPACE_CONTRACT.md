# Workspace and temp contract

This describes how the orchestrator uses on-disk **workspace** directories for checkpoints and how that interacts with reproducibility and cleanup.

## Layout

- **Workspace root** — from `--workspace` (default: `scan_workspace`), always **resolved** to an absolute path. Exposed as `report._workspace` and under `run_manifest.replay_bundle.workspace.root`.
- **Run id** — folder name under the workspace: from `--run-id`, or `--resume`, or `default_run_id(scan_path, url)` (host-derived + path hash). Exposed as `report._run_id` and `replay_bundle.workspace.run_id`.
- **Checkpoint** — `WORKSPACE_ROOT / RUN_ID / checkpoint.json` (see `secscan.checkpoint_core`). When checkpoints are enabled, phase state is written here for **resume**. Path is listed as `replay_bundle.workspace.checkpoint_json`.

## Lifecycle

| Mode | Behavior |
|------|----------|
| Default | Checkpoint file is written/updated as phases complete. |
| `--no-checkpoint` | No `checkpoint.json`; nothing persisted under `RUN_ID` for resume (other tools may still write elsewhere). |
| `--resume RUN_ID` | Loads existing checkpoint; must match `--path`, `--url`, `--auth-config`, `--chain-config` per `validate_resume`. |

## Comparability across machines

- **Same logical run** should use the same `--run-id` (or same `--url` + `--path` so the default id matches) and the same **resolved** `--path` string when possible.
- **Git state** is captured in `run_manifest.git` when the scan path is inside a repo; use commit + `replay_bundle.config_sha256` + tool versions + `replay_bundle.supply_chain` + `replay_bundle.environment` to compare reports. **`replay_bundle.scan_path_git_relative`** helps confirm the scanned subtree without changing `correlation_id` (see [REPRODUCIBILITY.md](./REPRODUCIBILITY.md)).

## Cleanup

- **`--wipe-run-dir`** — After a **successful** run (`exit 0`), deletes `WORKSPACE_ROOT / RUN_ID` if checkpoints were used and the run was **not** a resume. Use to minimize retained state after scans (e.g. CI). Ignored when `--no-checkpoint` or `--resume` is used, or when the run fails.

- **`--wipe-temp`** — After **exit 0**, deletes **registered** ephemeral files (not the whole temp directory): nuclei multi-target list files, Playwright auth storage JSON paths, `xss_exploit_*.png`, `browser_screenshot.png`, etc. Runs **after** HTML/PDF are written so reports can embed screenshots first. Does not remove arbitrary files created by unmanaged tools. See [HARDENING_CHECKLIST.md](./HARDENING_CHECKLIST.md).

## Secrets and retention

Checkpoints may contain **phase outputs** (including tool JSON). Treat the workspace as **sensitive** unless you have confirmed otherwise. For stricter hygiene, combine `--wipe-run-dir` with `--sanitize-exports` on artifacts you share. This is **not** a substitute for full disk encryption or org retention policies.
