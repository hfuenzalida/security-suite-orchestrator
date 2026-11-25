# “No network except X” mode (documentation)

The orchestrator does not enforce a kernel firewall; this document describes a **practical minimal-network posture** you can implement with OS firewalls, container network policies, or air-gapped VMs.

## CLI presets (`--network-mode`)

The **`--network-mode`** flag (or **`SECURITY_SCAN_NETWORK_MODE`**) merges **additional** `--skip` phases to reduce outbound DNS and LLM calls — see [SAFE_OPERATIONS.md](./SAFE_OPERATIONS.md). This does **not** replace host firewall rules; it complements them. Values: **`default`** | **`minimal-outbound`** | **`offline-static`**.

## Typical allowed destinations (X)

| Destination | Why |
|-------------|-----|
| **Scan target** | `--url` host (HTTP/HTTPS) — DAST, browser, ZAP, PoC, recon against that host. |
| **Local Ollama** | Default `http://127.0.0.1:11434` (or your `OLLAMA_HOST`) for AI phases. |
| **Loopback services** | Optional local proxies or test stacks on `localhost`. |

## What to block or avoid

| Traffic | Notes |
|---------|--------|
| **Public package / template CDNs** | `pip install` / `nuclei -update` during the scan — run those in a separate build step with a mirror if needed. |
| **External DNS exfil** | Recon tools may query DNS; use a resolver policy if required. |
| **Telemetry** | Disable third-party phone-home in tools where configurable. |

## Suggested `--skip` for stricter offline scans

Depends on what you consider “offline”:

- **No outbound internet, target + Ollama only:** you can still run SAST/secrets/deps against `--path` without network if tools and databases are local. Skip phases that **require** external hosts: e.g. `--skip recon` (subfinder/whatweb often need DNS), or run without `--url` to skip all URL-based phases.
- **No Ollama:** `--skip code_ai ai` to avoid local LLM calls.

## Environment variables

| Variable | Role |
|----------|------|
| `OLLAMA_HOST` | Point AI phases at a specific host (default loopback). |
| `SECURITY_SCAN_*` | See `secscan/user_config.py` — timeouts and paths without widening network scope. |

## CI vs laptop

- **CI:** Prefer a dedicated network namespace or firewall group that allows only the target’s IP and `127.0.0.1`.
- **Laptop:** Same idea using OS firewall “allow list” profiles for the duration of the scan.

This is **policy and infrastructure**, not a single CLI flag: the CLI stays flexible; your environment enforces the boundary.
