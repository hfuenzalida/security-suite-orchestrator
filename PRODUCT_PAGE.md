# Security Suite Orchestrator — Product page

*Use this file as the long description for Gumroad (or similar). Short public summary: copy the first two sections.*

---

## One-liner

**Run SAST, secrets, dependency audits, and DAST from one CLI** — with JSON / SARIF / JUnit built for real CI gates, plus optional local AI phases and reproducibility-friendly run metadata.

---

## What you get

| You buy | What it means |
|--------|----------------|
| **A maintained security orchestration workflow** | One entrypoint coordinates multiple industry tools (e.g. Semgrep, Bandit, gitleaks, nuclei, optional ZAP, Playwright, and more — depending on what you install). |
| **CI-honest outputs** | Unified findings, `--fail-on` policies, SARIF (including **unified** mode for gate parity), JUnit, exit codes documented for pipelines. |
| **Operator-grade docs** | User manual, CI/gates contract, safe-ops and network modes, replay bundle hooks for evidence — aimed at teams that ship, not slide decks. |

**License:** The software is provided under the [MIT License](LICENSE). You receive the same rights MIT grants (use, modify, distribute) subject to that license. This product listing may bundle **packaging, support, or updates** — read “What this purchase includes” on your order.

---

## Who this is for

- **Engineering leads** who want merge pipelines that fail on **meaningful** severities, not HTML alone.  
- **Security-minded developers** who need **local-first** runs and optional **air-gapped / minimal-network** modes.  
- **Small teams** without budget for a full ASPM suite but who outgrew one-off scripts.

**Not a fit if:** you need a managed SaaS scanner, a formal SOC2-certified product out of the box, or guaranteed exploit proof for every finding — the orchestrator **coordinates tools**; it does not replace pentesters or enterprise AST/CPG platforms (see [OPERATING_GUARANTEES.md](OPERATING_GUARANTEES.md)).

---

## Suggested price (example)

| SKU | Example price | Positioning |
|-----|----------------|-------------|
| **Professional digital pack** | **$99 one-time** | Packaged release + documentation + optional limited support window *(you define support in checkout)* |

Adjust the number for your market; $99 works when the **bundle** (support, updates channel, video walkthrough) is clear.

---

## What to include in the Gumroad download (recommended)

1. **Source or release archive** (aligned with the version you support).  
2. **`USER_MANUAL.md`** — how to run full vs partial scans (`--skip`, CI profile).  
3. **`LICENSE`** + link to [legal/README.md](legal/README.md).  
4. **Quick start** (1 page): Python version, `pip install`, `security-scan doctor`, one example CI snippet.  
5. **Optional:** changelog or “supported version” note so buyers know what they bought.

---

## Requirements (buyer-facing)

- **Python 3.11+**  
- **Third-party scanners** installed separately (the orchestrator reports missing tools clearly; see `check_security_tools.py` / `security-scan doctor`).  
- **Target app URL** for dynamic phases (DAST, browser, ZAP, etc.); static-only runs are supported with path-only workflows.

---

## Honest limitations

- Findings come from **underlying tools** — false positives and false negatives are expected.  
- **Gate truth** for automation is **JSON / SARIF / JUnit + exit codes**, not HTML/PDF alone.  
- **Optional AI phases** need a **local Ollama** (or skipped via `--skip code_ai` / `ai`).  
- **No warranty** of fitness for a particular compliance regime — use your assessors for regulated environments.

Full detail: [OPERATING_GUARANTEES.md](OPERATING_GUARANTEES.md), [DISCLAIMER.md](legal/DISCLAIMER.md).

---

## FAQ

**Is this the same as public source?**  
MIT allows redistribution. Your listing should state what **extra** the buyer gets (support, curated release, onboarding) so the price is justified.

**Refund policy?**  
Set Gumroad’s refund window and policy to match how you deliver (digital goods, support time). Keep it visible at checkout.

**Enterprise / invoice / DPA?**  
Gumroad is often indie-friendly; larger buyers may need invoices, vendor review, and custom terms — handle outside Gumroad or upgrade to a B2B-friendly channel when revenue justifies it.

**Security vulnerabilities?**  
See [SECURITY.md](SECURITY.md); replace the contact placeholder before publishing.

---

## Support line (edit before publish)

> **Support:** *[your email or Gumroad message policy — e.g. “Email replies within 3 business days for 30 days after purchase.”]*

---

*Internal note: replace bracketed placeholders; align price and support promises with [legal/COMMERCIAL_OFFERING.md](legal/COMMERCIAL_OFFERING.md) after counsel review.*
