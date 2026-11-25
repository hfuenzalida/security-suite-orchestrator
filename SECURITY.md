# Security policy

## Supported versions

Security fixes are applied to the **latest minor release** in this repository’s default branch unless otherwise noted. **Pin** the orchestrator version in production pipelines; see [VERSIONING.md](./VERSIONING.md).

## Reporting a vulnerability

**Please do not** open a public GitHub issue for **undisclosed** security vulnerabilities in this codebase.

Instead, report privately to: **[SECURITY_CONTACT_EMAIL]**

Include:

- Description of the issue and potential impact
- Steps to reproduce (proof-of-concept if safe)
- Affected version(s) or commit hash if known

**Replace `[SECURITY_CONTACT_EMAIL]`** with a monitored address (or a vendor disclosure form URL) before publishing this file publicly.

## Scope

**In scope:** Security defects in **this repository’s** Python code and documented CLI behavior (e.g. unsafe defaults, injection in orchestrator-controlled paths, credential handling bugs in the Software itself).

**Typically out of scope:** Findings in **third-party scanners** (report to those projects); **misconfiguration** of targets or credentials; **social engineering**; issues that require **already-compromised** hosts.

## Disclosure

We aim to **acknowledge** valid reports within a **reasonable** timeframe and coordinate **public disclosure** after a fix is available, respecting reporter preferences where possible.

## Safe harbor

If you follow this policy and act in good faith, we will **not** pursue legal action for accidental, good-faith research—**subject to applicable law** and our ability to make such commitments (replace this paragraph with counsel-approved wording for your entity).

*The safe harbor sentence is a template; many projects link to a vulnerability disclosure program policy instead.*
