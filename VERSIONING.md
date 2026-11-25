# Versioning and compatibility

## `ORCHESTRATOR_VERSION` (`secscan.constants`)

Semantic intent (**MAJOR.MINOR.PATCH**):

| Bump | When |
|------|------|
| **PATCH** | Bug fixes, logging, redaction tuning, docs — **default** JSON shape unchanged for consumers that ignore unknown keys. |
| **MINOR** | New optional report fields, new CLI flags with safe defaults, new phases behind `--skip`, additive SARIF/JUnit properties. |
| **MAJOR** | Removing or renaming top-level JSON keys, changing `--fail-on` semantics, incompatible SARIF structure. |

Every JSON report includes `run_manifest.orchestrator_version` and `run_manifest.report_schema_compat_version`.

## `REPORT_SCHEMA_COMPAT_VERSION`

Bumped only when **documented, stable** report fields change in a breaking way (e.g. removing `phases`, renaming `unified_fingerprints_triage`). Minor releases often leave this unchanged while `ORCHESTRATOR_VERSION` still increments.

Consumers should:

1. Pin the CLI / package version in CI.
2. Treat unknown keys as forward-compatible.
3. On upgrade, read release notes and this file for `REPORT_SCHEMA_COMPAT_VERSION` changes.

## Release discipline

When bumping **`ORCHESTRATOR_VERSION`**:

- Update **`pyproject.toml`** version to match.
- Summarize user-visible changes (CLI, JSON, SARIF, exit codes) in release notes or changelog.
- If report JSON shape changes incompatibly, bump **`REPORT_SCHEMA_COMPAT_VERSION`** and call it out explicitly.

This project does not guarantee a separate LTS branch; **pin versions** in regulated environments.
