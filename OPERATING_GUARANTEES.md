# Operating guarantees (Security Suite Orchestrator)

This document states **what the maintainers aim to provide** and **what is explicitly out of scope**, so teams can decide fit for production use without marketing ambiguity.

## What we commit to (design intent)

| Area | Guarantee |
|------|-----------|
| **Local-first** | The CLI is built to run tools on your machine (or CI) with you controlling network access to targets and tool updates. |
| **Deterministic reporting shape** | JSON report top-level fields (`phases`, `phase_status`, `run_manifest`, unified finding lists when enabled) are **versioned with the orchestrator** (`ORCHESTRATOR_VERSION` / `secscan.constants`). `run_manifest.report_schema_compat_version` tracks breaking JSON shape changes; `run_manifest.replay_bundle.join_rules_version` tracks [CORRELATION_JOIN_RULES.md](./CORRELATION_JOIN_RULES.md) semantics. See [VERSIONING.md](./VERSIONING.md). |
| **CI semantics** | `--fail-on`, baselines, and exit codes are intended to be **predictable** for the documented modes; when behavior changes, it is treated as a **compatibility** concern. **HTML/PDF `report_tier`** only changes human narrative — gates use JSON/unified findings. |
| **Secret hygiene** | Webhooks and optional `--sanitize-exports` apply **best-effort redaction** on structured payloads. This reduces accidental leakage; it is **not** a guarantee against all side channels or user misconfiguration. |
| **Adapter validation (SAST)** | Semgrep and Bandit JSON outputs are parsed through **validated adapters** (`secscan.tool_adapters.sast`). Malformed or unexpected shapes yield explicit tool errors in the report instead of silent mis-counts. |

## What we do not guarantee

| Area | Non-guarantee |
|------|----------------|
| **Finding correctness** | The orchestrator does not prove exploitability. Tool findings (SAST/DAST/deps) remain **vendor/tool claims**; false positives and false negatives are expected. |
| **Completeness** | No claim of coverage parity with commercial AST/CPG products, reachability-aware SCA, or manual penetration testing. |
| **Availability of third-party tools** | Binaries (`nuclei`, `gitleaks`, `zap`, etc.) may be missing, outdated, or behave differently per platform; the orchestrator **reports tool errors** but does not certify installs. |
| **Redaction completeness** | Redaction uses pattern-based stripping on strings (incl. JWT/PEM-like patterns and long hex/base64 chunks in exports). **False positives** may obscure harmless long tokens in evidence. **Secrets in binary attachments, screenshots, or novel formats** may not be caught. |
| **Export string caps** | With **`--sanitize-exports`**, JSON strings are capped (default 4000 chars) after redaction. HTML/PDF use separate per-field limits via `secscan/export_limits.py`. |
| **Security of the orchestrator itself** | This repository is not positioned as a formally verified or certified product (Common Criteria, etc.). Treat updates like any other dependency. |

## Versioning & compatibility

- **Orchestrator version** is exposed in JSON (`run_manifest.orchestrator_version`) and `secscan.constants.ORCHESTRATOR_VERSION`.
- **Report schema** may evolve in minor ways; consumers should tolerate unknown keys and pin orchestrator versions for strict pipelines.

## Support model

This project is **best-effort open-source tooling**: issues and PRs are welcome; there is **no** committed SLA, indemnity, or warranty. For regulated environments, use your own risk assessment and internal support processes.

**License, disclaimers, privacy, commercial options:** [legal/README.md](./legal/README.md) (default grant: [LICENSE](./LICENSE)).

---

*For engineering backlog vs product scope, see [DISCIPLINE_ENGINEERING_GAPS.md](./DISCIPLINE_ENGINEERING_GAPS.md). Operational checklist: [HARDENING_CHECKLIST.md](./HARDENING_CHECKLIST.md).*
