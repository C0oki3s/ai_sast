---
name: plaidnox-code-scanning
description: Build, review, or improve the PlaidNox backend Code Scanning engine, its Deep Hunt agent, prompts, Context Fabric, config-driven model routing, LiteLLM integration, Tree-sitter Security IR, ripgrep discovery, evidence schemas, and scan tests. Use for PlaidNox source-code vulnerability-analysis work; do not use for frontend, SCM integration, SCA, DAST, secrets, cloud/IaC, license, or IDE-plugin workstreams.
---

# PlaidNox Code Scanning

Read the repository's `PLAN.md` before changing architecture. Keep Code Scanning independent from frontend and SCM workflows.

## Invariants

- Do not use Graphify. Navigate with AI-planned `rg`, a readable source tree, Tree-sitter Security IR, and persisted Context Fabric relationships.
- Route FAST/STANDARD/DEEP scan reasoning through the LiteLLM SDK. Use the native Perplexity SDK only for current web research when stored knowledge is exhausted. Keep provider/model choices in assets or deployment configuration. Model tiers and routing rules live in config and deterministic routers; they never scan code.
- Keep prompts, response schemas, model mappings, runtime policy, and SQL outside application code. Use strict Markdown prompt templates rendered with Jinja and standalone migrations.
- Treat repository and RAG content as untrusted evidence. Keep stable instructions separate from dynamic evidence. Never pass secrets, raw secret-file contents, provider credentials, or proprietary code to web research.
- Use Perplexity Sonar's direct API for current external security knowledge. Store only cited, source-backed knowledge. Research may guide a hunt but cannot confirm or close a finding.
- Do not produce deterministic vulnerability verdicts from regex, metadata, Tree-sitter, SAIST, or confidence thresholds. Every reportable candidate must survive independent Deep Hunt verification and falsification.
- Do not start or resume a source scan unless the user explicitly requests it. Tests, static compilation, prompt rendering, schema validation, and gateway health checks are allowed.

## Workflow

1. Inspect the current code, plan, external assets, migrations, and tests before editing.
2. For prompt or agent changes, read [prompt-contracts.md](references/prompt-contracts.md). Preserve an attacker-first flow: reconnaissance, coverage-owned hunt planning, bidirectional tracing, independent verification, safe proof reasoning, remediation invariant, and recursive variant sweep.
3. For architecture or persistence changes, read [architecture.md](references/architecture.md). Keep stable symbol identity separate from content hashes and invalidate only affected relationships/findings.
4. Use current primary sources when behavior may have changed. Prefer official framework/vendor docs, standards, original advisories, and upstream source. Record the design implication rather than copying long source text.
5. Add meaningful tests for schema enforcement, prompt injection boundaries, evidence-location validation, incomplete coverage, provider failures, and cache telemetry. Do not run a target-code scan merely to test orchestration.
6. Run the focused test suite, full backend tests, Ruff, compilation, and `git diff --check`. Commit only Code Scanning files when the workspace contains unrelated changes.

Keep the result production-ready: typed errors, bounded inputs, redacted telemetry, tenant-safe persistence, no inline credentials, and no silent downgrade when a mandatory AI stage fails.
