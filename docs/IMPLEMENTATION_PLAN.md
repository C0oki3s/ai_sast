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

## 3. PostgreSQL ORM persistence — implemented

### 3a. Typed production foundation — implemented

- SQLAlchemy 2.x typed models, Psycopg 3 configuration, tenant-scoped
  repositories, explicit units of work, and reviewable PostgreSQL DDL.
- Durable codebases, immutable snapshots, Security IR, scan runs, hunt plans,
  leased hunt tasks, knowledge, findings, evidence, and exact symbol
  dependencies.
- Stable symbol identity excludes content and line numbers; body changes alter
  the content hash while preserving the dependency key.
- Compare-and-swap task leases are portable across the SQLite repository test
  adapter and PostgreSQL and are safe to retry.
- Covered by `tests/test_persistence.py` and the configured-persistence cases
  in `tests/test_pipeline.py`.

### 3b. Context Fabric and knowledge runtime migration — implemented

- `ContextFabric` and `SecurityKnowledgeStore` are persistence-neutral typed
  contracts. The Deep Hunt agent and knowledge coordinator no longer depend on
  concrete SQLite classes.
- With `PLAIDNOX_DATABASE_URL` configured, the CLI uses
  `PostgresContextFabricStore` and `PostgresKnowledgeStore` for bases,
  overlays, reverse-dependency invalidation, context packets, security memory,
  finding links, sourced knowledge, usage audit, and cached hunt plans.
- The local SQLite stores remain development adapters only. The production
  path does not open or reconstruct a SQLite store, including the final
  context-recording step.
- Knowledge usage and plan/task writes are content-addressed and idempotent.
  Context overlays persist as immutable child snapshots and reuse the same
  Security IR identity scheme as the scan pipeline.
- Covered by `tests/test_persistence_adapters.py`,
  `tests/test_context_fabric.py`, and `tests/test_knowledge.py`.

### 3c. Real PostgreSQL verification — implemented

- `docker/postgres-test/docker-compose.yml` starts disposable PostgreSQL 16
  using the checked-in migration rather than ORM `create_all`.
- `tests/test_persistence_postgresql.py` verifies concurrent leasing,
  expiration/reclaim, finding reconstruction, and full transaction rollback
  through `PLAIDNOX_TEST_DATABASE_URL`, which is intentionally separate from
  the production database variable.
- The full ordinary test suite exercises the same repositories through an
  in-memory SQLite test adapter; PostgreSQL-only tests skip when their explicit
  test URL is absent.

Exit condition: met. Concurrent workers lease safely, retries are idempotent,
findings reconstruct with evidence and dependencies after interruption, and
the production runtime uses PostgreSQL for Context Fabric and security
knowledge whenever production persistence is configured.

## 4. AI hunt completeness and remediation — implemented

- LLM search-plan creation from architecture, business context, threat context,
  hunt tasks, and current knowledge; query patterns are never hardcoded in code
  — implemented (`_create_recon_search_plan`, `_create_search_plan` in `ai.py`).
- Targeted context expansion through Tree-sitter definitions, callers, callees,
  imports, routes, guards, and affected controls — implemented as automatic
  fixed-window expansion (`_source_window`, `_security_ir_context`) plus a
  genuinely on-demand, AI-requested expansion path. `hunt()` runs the
  `security_review` verdict call in a bounded loop (`runtime/agent.json`'s
  `context_expansion_max_rounds`, default 2, so up to 3 total calls); every
  round must still return a full, schema-valid verdict from only the evidence
  already supplied, but may also name `context_requests` (kind: definition /
  callers / callees / imports / route / window, plus path/symbol/line range)
  describing the smallest additional evidence that would resolve an open
  gate. `_resolve_context_request()` answers each request purely from the
  already-built `StructuralGraph` (no new Tree-sitter parsing), is tolerant of
  resolution failures (`{"resolved": False, "reason": ...}` rather than
  raising), and the resolved answers are echoed back as `context_expansions`
  in the next round's evidence so the AI does not re-request them. The
  `deep_hunt_review.json` schema's `context_requests` field is required (an
  empty array, not an optional field, to satisfy LiteLLM strict
  structured outputs) and capped at 5 requests per round via
  `context_expansion_max_requests_per_round`. Metadata-only reviews
  (`metadata_exposure_review`) are forbidden from requesting expansion — since
  no source was ever disclosed to them — and `hunt()` raises `AIResponseError`
  if one tries. Covered by `tests/test_ai.py`
  (`test_ai_review_resolves_an_on_demand_context_request_before_the_final_verdict`,
  `test_ai_review_stops_requesting_context_at_the_configured_round_limit`,
  `test_metadata_review_rejects_an_on_demand_context_request`).
- Coverage accounting for each task and reachable attack surface; incomplete
  coverage makes the scan incomplete — implemented. `PolicyDecision.INCOMPLETE`
  is a new decision distinct from `WARN`; `SastPipeline.scan_snapshot` sets it
  whenever any AI stage failure counter is nonzero and the finding-based policy
  would otherwise have been `PASS` (`pipeline.py`). `ai_scan_incomplete` is
  always reported in scan metrics. `cli.py --enforce` now fails closed on
  `INCOMPLETE` the same way it does on `BLOCK`.
- Actual LiteLLM model selection for FAST/STANDARD/DEEP tiers — implemented for
  the PlaidNox Deep Hunt review call. `runtime/models.json` carries a new
  `agent_model_by_tier` map; `JevRouter.classify()`'s `RouteDecision.model_tier`
  is threaded from `pipeline.py`'s `verify()` into `PlaidNoxDeepHuntAgent.hunt()`
  / `.review()`, which resolve the tier to a concrete model per call
  (`_model_for_tier`) instead of a single fixed `self.model`. Recon, planning,
  discovery, variant sweeping, and consolidation remain on the default model —
  JEV routing is candidate-scoped and does not naturally apply to those
  scan-level stages.
- Full secret redaction gateway before every provider boundary — implemented.
  `redaction.py` is the single shared `redact`/`redact_payload` implementation;
  `PlaidNoxDeepHuntAgent._structured_response()` (the one chokepoint for every
  Deep Hunt generative call) now redacts the entire payload recursively before
  rendering a prompt, and `LiteLLMKnowledgeProvider.research()` (the Perplexity
  research provider boundary) redacts its query/context the same way. The
  duplicated `_redact()` in `saist.py` was removed in favor of the shared
  module.
- Typed stage errors and incomplete-scan behavior for required AI failures —
  implemented. `errors.py` introduces a shared `AIStageError(RuntimeError)`
  root; `AIConfigurationError`/`AIResponseError` (`ai.py`), `JevError`
  (`jev.py`), and `SAISTError` (`saist.py`) all inherit from it. The broad
  `except Exception` catches in `pipeline.py` and `ai.py` are deliberately kept
  (narrowing them to only the typed hierarchy was evaluated and rejected: a
  real LiteLLM/SDK call can raise exception types outside this hierarchy, and
  crashing an entire scan on one candidate's unrecognized exception would lose
  every other finding in that scan, which is worse than tolerating and
  classifying it). Every catch site now classifies
  `isinstance(exc, AIStageError)` and records an "unexpected failure" signal
  distinct from a recognized AI-stage failure:
  `ai_context_unexpected_failures`, `ai_discovery_unexpected_failures`,
  `ai_review_unexpected_failures`, `ai_variant_unexpected_failures`, and
  `ai_consolidation_unexpected_failure` are new `ScanResult.metrics` fields
  alongside the existing error-type/message fields, so the audit trail can
  tell a recognized, expected AI/tool-chain failure apart from an
  unclassified exception that likely signals a real code defect worth
  investigating. Covered by `tests/test_pipeline.py`
  (`test_pipeline_flags_unrecognized_discovery_failures_as_unexpected`,
  `test_pipeline_flags_unrecognized_context_failures_as_unexpected`,
  `test_pipeline_does_not_flag_a_recognized_ai_stage_error_as_unexpected`,
  `test_pipeline_does_not_flag_a_recognized_consolidation_error_as_unexpected`).
- Evidence quality checks, safe reproduction narratives, business impact, and
  repository-convention-aware remediation — implemented
  (`_validate_deep_hunt_result`'s 8 verification gates plus evidence-location
  bounds-checking).
- Explicit patch proposal and rescan verification; no silent repository writes
  — implemented, scoped after an explicit discussion to propose-only plus an
  ephemeral rescan (never a write to the scanned path, no git/PR integration).
  It is opt-in: `SastPipeline.scan_snapshot`'s new `propose_patches` parameter
  (wired to `plaidnox-sast scan-local --propose-patches`) defaults to `False`
  since it is an additional generative stage per finding with a different
  risk/cost profile than the rest of the scan. When enabled, it runs once per
  consolidated finding, after consolidation and sorting:
  `PlaidNoxDeepHuntAgent.propose_patch()` asks the model for the smallest
  unified diff touching only the finding's own evidence files (a new
  `patch_proposal` operation / `schemas/patch_proposal.json`, mirroring the
  `supported`/`rejection_reason` shape of the Deep Hunt verdict — the model
  must either propose a diff or give an evidence-backed reason it declined).
  `_validate_patch_proposal` independently re-derives the diff's own
  `+++ b/<path>` headers and rejects a proposal whose declared
  `files_changed` don't match, or that references a path outside the
  repository, closing off invented files. `PlaidNoxDeepHuntAgent.verify_patch()`
  then applies the diff with the system `patch` utility inside a
  `tempfile.TemporaryDirectory` copy of the snapshot (`root` itself is never
  opened for writing), rebuilds the Security IR for that copy, and reruns
  `hunt()` against it; the patch counts as verified only if the same
  candidate no longer verifies against the patched copy. A patch that fails
  to apply, or whose rescan errors, is reported as unverified rather than
  raising, consistent with the tolerate-and-classify design from the typed
  stage errors above; `ai_patch_proposals`, `ai_patch_verified`,
  `ai_patch_unverified`, `ai_patch_proposal_failures`, and
  `ai_patch_unexpected_failures` are new `ScanResult.metrics` fields, and the
  proposal/verification are attached to `finding.metadata["patch_proposal"]`
  / `["patch_verification"]` rather than applied anywhere. Patch-proposal
  failures do not affect `ai_scan_incomplete` — it is a best-effort add-on to
  an already-complete verified finding, not a required stage. Covered by
  `tests/test_ai.py` (`test_ai_proposes_a_patch_and_verifies_it_fixes_the_finding`,
  `test_ai_patch_proposal_rejects_a_diff_whose_headers_do_not_match_files_changed`,
  `test_ai_patch_proposal_declines_without_a_reason_is_rejected`,
  `test_verify_patch_reports_an_unapplied_patch_without_touching_the_repository`,
  `test_verify_patch_skips_the_rescan_when_no_patch_was_proposed`) and
  `tests/test_pipeline.py` (`test_pipeline_does_not_propose_patches_unless_enabled`,
  `test_pipeline_proposes_and_verifies_patches_when_enabled`,
  `test_pipeline_flags_unrecognized_patch_proposal_failures_as_unexpected`).
  Known limitation: the rescan reuses the finding's original evidence line
  range against the patched copy, so a patch that shifts line numbers without
  fixing the vulnerability can be misjudged; tracking hunk offsets was left
  out of this first scope.

Exit condition: every accepted or rejected candidate has a complete audit trail,
and incomplete coverage can never produce a passing scan — met for the
in-process pipeline (proven by `tests/test_pipeline.py`'s
`test_pipeline_marks_the_scan_incomplete_when_contextual_ai_discovery_fails`
and `test_pipeline_never_reports_a_candidate_without_an_ai_verdict`); the
optional patch proposal/rescan verification stage is additive and does not
change this exit condition.

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
