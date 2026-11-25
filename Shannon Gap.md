What we have ✅ vs. What Shannon has that we're missing ❌
Missing features
Gap	Shannon does	Impact
Subfinder	Subdomain enumeration — finds hidden subdomains before scanning	Medium
WhatWeb	Deep tech fingerprinting (CMS, framework, version detection)	Low
Parallel agents	5 vulnerability agents + 5 exploit agents run simultaneously	Performance only
AI reads source code	Claude reads your actual .py/.js files to trace data flows and understand business logic — the biggest differentiator	HIGH
Authenticated scanning	Full session support: SSO, TOTP/2FA, API key auth — maintains cookies across all phases	High
Request chaining	Multi-step exploit sequences (get CSRF token → use it → submit payload)	High
Code Property Graph (Pro)	AST + control flow + data dependence graphs for deep taint analysis	Pro only
SCA reachability (Pro)	Confirms if a vulnerable dependency is actually callable from your code	Pro only
Business logic testing (Pro)	AI discovers app-specific invariants and generates custom fuzzers	Pro only
Crash recovery / resume	Temporal workflow — if scan crashes mid-run it resumes from last checkpoint	Low
________________________________________
Honest coverage estimate
Tier	Coverage
Shannon Lite	~70%
Shannon Pro	~35%
________________________________________
The one gap that matters most
AI that reads source code directly. Shannon's core value is that Claude reads your actual files, traces request.args["id"] → cursor.execute(query), understands your auth middleware, and generates payloads that target your specific code patterns. Our AI reasoning only analyzes tool output (the JSON findings list).
This is achievable with your local Ollama setup. Want me to build a Phase 0.5 — AI Code Analysis that feeds your actual source files to the local LLM and produces a pre-scan threat model before the tools run?
