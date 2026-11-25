# Privacy notice

*The following is provided for convenience and does not constitute legal advice. Customize for your entity and jurisdiction if you distribute the Software or offer services around it.*

## Local-first operation

By default, the Security Suite Orchestrator is intended to run **on your machine or in your CI environment**. **Processing of source code, configuration, and scan outputs** generally stays **under your control**, subject to your own policies and infrastructure.

The maintainers of this repository **do not receive** your code, scan results, or logs **solely because you run the open-source Software** from this repo.

## Optional network activity

Depending on configuration, the Software or bundled tools may:

- **Contact targets you specify** (e.g. URLs for DAST) or **download updates** for third-party components;
- Use **optional integrations** you configure (e.g. webhooks, remote APIs, package indexes for dependency audits).

**You** decide targets, credentials, webhooks, and network posture. Review [NETWORK_MODE.md](../NETWORK_MODE.md), [SAFE_OPERATIONS.md](../SAFE_OPERATIONS.md), and your organization’s data-handling rules.

## Webhooks and exports

If you enable **webhooks** or export reports to shared systems, **payloads may contain** findings, URLs, paths, or fragments that **your policies** should treat as sensitive. The Software includes **best-effort redaction** options; redaction is **not** claimed to be complete in all cases. See [OPERATING_GUARANTEES.md](../OPERATING_GUARANTEES.md).

## Optional Python dependencies

Installing optional extras (e.g. `pip install '.[full]'`) may pull in third-party libraries (see `pyproject.toml`). Those libraries have **their own licenses and privacy practices**. The core package declares **no runtime `dependencies`** in `[project]`; optional components are **your choice**.

## Telemetry

**This open-source project does not embed vendor analytics or phone-home telemetry** in the orchestrator **as shipped in this repository**. If you fork or wrap the Software, disclose your own practices.

## Contact

For **commercial** privacy questions (e.g. paid support or a managed offering), use the contact placeholders in [COMMERCIAL_OFFERING.md](./COMMERCIAL_OFFERING.md) after you replace them with your details.
