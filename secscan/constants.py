ORCHESTRATOR_VERSION = "0.2.9"

# Increment when JSON report shape breaks consumers (top-level required fields, renamed keys).
# Patch/minor orchestrator releases may keep this stable; see VERSIONING.md.
REPORT_SCHEMA_COMPAT_VERSION = "1"

# Bump when CORRELATION_JOIN_RULES.md semantics for correlation_id / baselines change.
CORRELATION_JOIN_RULES_VERSION = "1"

ENV_PREFIX = "SECURITY_SCAN_"

# Bump when secscan/redaction.py pattern set changes materially.
REDACTION_RULESET_VERSION = "2"
