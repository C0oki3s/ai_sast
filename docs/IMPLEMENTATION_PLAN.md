# Code Scanning ordered implementation plan

This plan covers the standalone Code Scanning engine. SCM, SCA, secrets,
outdated software, IaC/cloud, license risk, DAST, and IDE plugins are tracked in
`PRODUCT_WORKSTREAMS.md` and do not enter this runtime until Code Scanning meets
its end-to-end exit condition.

## 1. Secure local scan foundation — implemented

- Read-only local source snapshot input.
- Protected project configuration and business/security context.
- Readable source tree and compact Security IR.
- Externalized Jinja prompts, schemas, routing policy, runtime settings, SQL, and
  provider configuration.
- Mandatory AI reconnaissance, task planning, candidate discovery, PlaidNox
  Deep Hunt, falsification, and root-cause variant sweeps.
- JEV knowledge action, Perplexity research with source validation, durable
  knowledge reuse, and prompt-cache telemetry.
- Optional DataDog SAIST AI candidate adapter.
- JSON, SARIF 2.1.0, Markdown, and repository-context reports.

Exit condition: met by unit/E2E fixtures; repeated real-repository acceptance
evidence remains required before production release.

## 2. ripgrep + Tree-sitter Code Intelligence — active

- Make AI-created `rg` queries the primary discovery and navigation path.
- Use Tree-sitter to persist only the Security IR needed for symbols, imports,
  calls, routes, guards, sources, sinks, and focused context expansion.
- Do not persist a complete AST or build whole-program dataflow by default.
- Add precise compiler/LSP indexes and targeted taint/dataflow only when the AI
  identifies a flow question that cannot be resolved from the Security IR.
- Keep symbol identity stable across content changes.
- Enforce project excludes and maximum file sizes in inventory, IR, discovery,
  context compilation, and model input.
- Build generic snapshot overlays and dependency-aware invalidation with no SCM
  concepts in the Code Scanning core.
- Persist exact finding dependencies automatically from verified evidence.

Exit condition: mutation tests prove that a changed callee revalidates callers
and linked findings, unrelated code is reused, and the model-call audit shows
that broad source contents were not resent.

## 3. PostgreSQL ORM persistence — foundation added, migration active

- SQLAlchemy 2.x typed Code Scanning model and database settings.
- Psycopg 3 production driver.
- Reviewable PostgreSQL DDL under `assets/migrations/postgresql/`.
- Typed repositories and units of work for snapshots, IR, knowledge, hunt
  plans/tasks, model audit, cache metrics, findings, and dependencies.
- Replace runtime SQLite stores after repository parity tests.
- Real PostgreSQL concurrency, migration, rollback, and restore tests.

Exit condition: concurrent workers safely lease tasks, retry idempotently, and
reconstruct a finding from PostgreSQL after interruption.

## 4. AI hunt completeness and remediation

- LLM search-plan creation from architecture, business context, threat context,
  hunt tasks, and current knowledge; query patterns are never hardcoded in code.
- Targeted context expansion through Tree-sitter definitions, callers, callees,
  imports, routes, guards, and affected controls.
- Coverage accounting for each task and reachable attack surface; incomplete
  coverage makes the scan incomplete.
- Actual LiteLLM model selection for FAST/STANDARD/DEEP tiers.
- Full secret redaction gateway before every provider boundary.
- Typed stage errors and incomplete-scan behavior for required AI failures.
- Evidence quality checks, safe reproduction narratives, business impact, and
  repository-convention-aware remediation.
- Explicit patch proposal and rescan verification; no silent repository writes.

Exit condition: every accepted or rejected candidate has a complete audit trail,
and incomplete coverage can never produce a passing scan.

## 5. End-to-end validation

- Repeatable acceptance scans against `C0oki3s/NSTCTF` plus multi-language
  fixtures with known positives, variants, and clean controls.
- Measure coverage, validated recall, false positives, duplicates, IR/context
  reuse, prompt-cache reuse, tokens, latency, and cost by stage.
- Test prompt injection, redaction, malformed output, provider failure, stale
  knowledge, worker crash, and database recovery.
- Production worker image, migration job, configuration reference, and runbook.

Exit condition: a clean deployment can migrate PostgreSQL, scan an immutable
local snapshot, resume interruption, and emit complete reports without SCM.

## 6. Production controls

- Sandboxed read-only workers and explicit research-gateway egress.
- Queue leases, timeouts, quotas, tenant isolation, encryption, retention,
  deletion, artifact lifecycle, and disaster recovery.
- OpenTelemetry traces/metrics, redacted logs, cost ceilings, and alerts.
- Signed and versioned policy and runtime assets.

Exit condition: isolation, auditability, replay safety, recovery, performance,
and cost limits are demonstrated in staging.

## After completion

Begin SCM Integration as a separate service and package. Code Scanning remains
an immutable-snapshot analysis API with no provider-specific orchestration.
