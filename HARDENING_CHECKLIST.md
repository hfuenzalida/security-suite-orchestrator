# Hardened defaults checklist

Use this when running the orchestrator in CI, on shared runners, or before sharing reports outside a trusted zone.

## Before you scan

| Item | Recommendation |
|------|------------------|
| **Scope** | Point `--path` at the repo or service root you intend to audit; avoid `$HOME` or broad drives. Use **`--include-glob` / `--exclude-glob`** to narrow **unified findings** to a subtree (see [SAFE_OPERATIONS.md](./SAFE_OPERATIONS.md)). |
| **Network** | Optional **`--network-mode minimal-outbound`** or **`offline-static`** to merge extra `--skip` presets ([NETWORK_MODE.md](./NETWORK_MODE.md)). |
| **Target** | Set `--url` only to systems you own or have written permission to test. |
| **Secrets in repo** | Prefer scanning a clean checkout; rotate any credentials that were ever committed. |
| **Config files** | Restrict file permissions on `auth.example.json`-style files copied to real paths (`auth.json`, `chain.json`). |

## Network posture

| Item | Recommendation |
|------|------------------|
| **Minimal exposure** | See [NETWORK_MODE.md](./NETWORK_MODE.md) for a “no network except X” posture. |
| **Webhooks** | Use `--notify-webhook` only with HTTPS endpoints you control; payloads are redacted but not zero-risk. |
| **Tool updates** | Third-party binaries (`nuclei -update`, `pip install`) are out-of-band; run from a locked-down build image when possible. |

## Outputs and sharing

| Item | Recommendation |
|------|------------------|
| **Exports** | Use **`--sanitize-exports`** for JSON/HTML/PDF you email or upload; full in-memory report is unchanged. |
| **Human reports** | HTML/PDF apply length limits and pattern redaction on evidence fields; JSON may still contain long tool blobs unless sanitized. |
| **Baseline** | Store baseline fingerprint files in version control with review, not world-writable paths. |
| **Temp artifacts** | Use **`--wipe-temp`** after successful runs to remove registered files (screenshots, nuclei target lists, auth storage paths). Combine with **`--wipe-run-dir`** to drop checkpoint dirs. See [WORKSPACE_CONTRACT.md](./WORKSPACE_CONTRACT.md). |

## Integrity (optional)

| Item | Recommendation |
|------|------------------|
| **Audit trail** | `--audit-log-jsonl` for append-only run metadata; `--hmac-sign-report` for tamper-evidence on JSON (shared secret). |

## What the tool does *not* guarantee

See [OPERATING_GUARANTEES.md](./OPERATING_GUARANTEES.md): redaction is best-effort, the orchestrator is not a formally verified enclosure, and **`--wipe-temp`** only removes **registered** paths (known mkstemp/screenshot locations), not every file third-party tools might create.
