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
- Capability-chain pivoting — implemented. A confirmed finding is not treated
  as a terminal endpoint: `hunt`'s verification gate 5 now also requires a
  `gained_capability` (an open, non-exhaustive `upper_snake_case` label from
  `_partials/capability_taxonomy.md`, e.g. `SERVER_SIDE_REQUEST`,
  `IDENTITY_CONTROL`, `TOKEN_MINTING`), validated by
  `_validate_deep_hunt_result` and persisted onto
  `finding.metadata["deep_hunt"]`. After each round's findings are
  independently verified, `PlaidNoxDeepHuntAgent.chain_capability_pivots`
  (`ai.py`) asks a dedicated `capability_chain` prompt/schema operation
  whether any finding's gained capability reaches a further security boundary
  elsewhere in the repository, reusing the same generic `_create_search_plan`
  rg-query generator and `_candidate_from_ai_item` parser as `sweep_variants`.
  Pivot hypotheses are never asserted directly — `pipeline.py`'s round loop
  feeds them back into `work_queue` as ordinary `Candidate`s, so each one
  passes through the full independent JEV-routing + Deep Hunt review pipeline
  before it can become a finding, and the loop terminates via the pre-existing
  `seen_candidates` fingerprint-dedup set (no new round cap needed). The
  `capability_chain` prompt explicitly forbids asserting a pivot that depends
  on unverifiable live infrastructure, runtime identity, or deployment facts —
  keeping this in scope as static analysis, not DAST/cloud-posture inference.
  New `ScanResult.metrics` fields: `ai_capability_chain_candidates`,
  `ai_capability_chain_failures`, `ai_capability_chain_unexpected_failures`,
  `ai_capability_chain_rounds`. Covered by `tests/test_ai.py`
  (`test_capability_chain_skips_findings_with_no_gained_capability`,
  `test_capability_chain_searches_from_the_gained_capability`,
  `test_capability_chain_records_provider_failure_without_crashing`,
  `test_deep_hunt_review_requires_gained_capability_when_supported`) and
  end-to-end by `tests/test_pipeline.py`
  (`test_pipeline_chains_a_gained_capability_into_a_new_independently_verified_finding`,
  asserting a capability-bearing finding spawns a pivot that is itself
  independently re-verified into a second, distinct finding, and that the
  loop ends once the pivot's own review names no further capability).
- JEV knowledge action, Perplexity research with source validation, durable
  knowledge reuse, and prompt-cache telemetry.
- Optional DataDog SAIST AI candidate adapter.
- JSON, SARIF 2.1.0, Markdown, and repository-context reports.
- Reasoning effort tiered by operation — implemented. `runtime/agent.json`'s
  new `reasoning_effort_by_operation` map assigns a `low`/`medium`/`high`
  reasoning budget per `prompt_operation` (recon and consolidation stages run
  cheap, Deep Hunt verification and capability chaining run at `high`).
  `_structured_response` (`ai.py`) looks up `prompt_operation` in this map,
  defaulting unlisted operations to `low` rather than the previous single
  hardcoded `"low"` used for every call. Covered by `tests/test_ai.py`
  (`test_structured_response_uses_the_reasoning_effort_configured_for_the_operation`,
  `test_structured_response_falls_back_to_low_effort_for_an_unlisted_operation`).
- Paginated caller/callee/route context requests — implemented. On-demand
  `context_requests` of kind `callers`, `callees`, and `route` previously
  silently truncated to the first 5 matches with no signal to the model that
  more existed. The schema (`deep_hunt_review.json`) now carries a required
  `offset` field, `_resolve_context_request` (`ai.py`) pages results using a
  configurable `context_request_edge_page_size` (`runtime/agent.json`, default
  20) and returns `total`/`returned`/`truncated` alongside the page, and
  `context_expansion_protocol.md` instructs the model to either page forward
  or record an explicit `evidence_gaps` entry rather than treating a truncated
  page as exhaustive. Covered by `tests/test_ai.py`
  (`test_resolve_context_request_paginates_callers_and_reports_truncation`,
  `test_resolve_context_request_route_reports_not_truncated_when_all_results_fit`).
- Deterministic obligation-level search-plan coverage — implemented. Coverage
  validation previously only checked that every hunt-task ID appeared in some
  query's `task_ids`, which passed even if a task's individual
  `coverage_obligations` went unaddressed. `search_query_plan.json` now
  requires each query to declare `direction`
  (`forward`/`backward`/`boundary`/`variant`/`inventory`), `purpose`
  (`entry_point`/`origin`/`effect`/`control`/`caller`/`callee`/`writer`/`reader`/`missing_branch`/`indirect_dispatch`/`alternate_implementation`),
  and `coverage_refs`. `_create_search_plan` (`ai.py`) builds a stable
  `task_id::obligation::index` ref for every task's `coverage_obligations`,
  passes that index to the model as `coverage_obligation_refs`, and now
  fails closed if any obligation ref goes unreferenced by every query's
  `coverage_refs`, or if a query references a ref ID that doesn't exist in
  the index (a hallucinated obligation can no longer silently count as
  covered). `direction`/`purpose` lay the descriptive groundwork for the
  still-deferred forward/sink/boundary hunt split without requiring it yet.
  Covered by `tests/test_ai.py`
  (`test_create_search_plan_requires_every_coverage_obligation_to_be_referenced`,
  `test_create_search_plan_rejects_an_unknown_coverage_ref`,
  `test_create_search_plan_succeeds_when_every_coverage_obligation_is_referenced`).
- Coverage-aware, production-area-balanced repository-context sampling —
  implemented. `build_repository_context` previously fed the model
  `graph.routes[:repository_route_limit]`/`graph.symbols[:repository_symbol_limit]`/
  `graph.files[:repository_ir_file_limit]`, a first-N slice that silently
  starved every production area but whichever sorted first in the underlying
  list once a repository exceeded the configured limit. `_balanced_area_sample`
  (`ai.py`) buckets each list by top-level path segment and round-robins
  across areas up to the limit, so a repository larger than the limit still
  gets representation from every area instead of exhausting the limit inside
  the first one. `build_repository_context` now also emits a
  `repository_context_coverage` block (`routes`/`symbols`/`security_ir_files`,
  each with `included`/`total`/`truncated`/`areas_with_omitted_context`) in
  the request payload, and `repository_context/system.md` instructs the model
  to treat an omitted area as unresolved coverage requiring a follow-up hunt
  task, never as evidence the area is clean. Covered by `tests/test_ai.py`
  (`test_balanced_area_sample_returns_everything_when_under_the_limit`,
  `test_balanced_area_sample_round_robins_instead_of_starving_later_areas`,
  `test_build_repository_context_reports_sampling_truncation_by_area`).
- Removed the discovery-stage `confirmed` boolean — implemented. Candidate
  discovery, variant sweep, and capability-chain pivoting each previously
  asked the model to self-assert `confirmed: true/false` on every hypothesis,
  and `_candidate_from_ai_item` (`ai.py`) silently dropped any item where
  `confirmed` was falsy — a deterministic pre-Deep-Hunt verdict this project's
  standing rule forbids, and one that could discard a plausible but
  uncertain hypothesis before it ever reached independent verification. The
  field is removed from `vulnerability_discovery.json`, `variant_sweep.json`,
  and `capability_chain.json`; `_candidate_from_ai_item` no longer gates on
  it, so every evidenced hypothesis becomes a `Candidate` and flows into the
  same independent PlaidNox Deep Hunt review that alone can confirm or reject
  it. `vulnerability_discovery/system.md` was reworded to stop instructing
  the model to withhold a candidate by setting `confirmed=false`, directing
  it instead to record what's unresolved in `evidence_basis.missing_evidence`
  and still surface the candidate. Covered by `tests/test_ai.py`
  (`test_candidate_from_ai_item_does_not_require_a_confirmed_field`).
- Additional on-demand context-request kinds — implemented (scoped to the 3
  kinds backed by data/infra that already exists; the other 9 proposed kinds
  — `writers`, `readers`, `middleware_chain`, `config`, `manifest`,
  `implementation`, `store_flow`, `environment_binding`,
  `authorization_context` — need a repository/data model that doesn't exist
  yet and are deferred). `deep_hunt_review.json`'s `context_requests.kind`
  enum gains `sibling_handlers`, `search`, `knowledge`, alongside two new
  always-required (per OpenAI strict mode) string fields, `pattern` and
  `query`, left at their empty-string default by kinds that don't use them.
  `_resolve_context_request` (`ai.py`) gains three keyword-only parameters —
  `source_excludes`, `max_file_bytes`, `knowledge_store` — threaded through
  from `hunt()`'s call site (`self.source_excludes`, `self.max_file_bytes`,
  `self.knowledge_coordinator.store if self.knowledge_coordinator else
  None`). `sibling_handlers` groups `security_graph.routes` by `path` and
  returns the other routes registered in the requested file (excluding the
  one at `symbol`), paginated like `callers`/`callees`/`route`. `search` runs
  one ad-hoc `RipgrepDiscovery` pattern query scoped by the existing
  `source_excludes`/`max_file_bytes` policy and the same sensitive-path
  filter already used by recon search execution, returning paginated
  path/line matches only (a caller resolves a specific match's content with a
  follow-up `window` request, keeping the two-step protocol consistent).
  `knowledge` looks up `query` against the durable `KnowledgeStore` already
  populated during recon (`knowledge_coordinator.store.search(query)`) — a
  read-only lookup against existing stored knowledge, deliberately not a new
  live web-research trigger mid-review, since `KnowledgeCoordinator.resolve`
  needs `repository`/`scan_id`/`task`/`repository_context` that `hunt()`
  does not have available at its `Candidate`/`Finding` call site.
  `context_expansion_protocol.md` documents all three kinds and the
  required-but-unused-fields convention to the model. Covered by
  `tests/test_ai.py`
  (`test_resolve_context_request_sibling_handlers_excludes_the_requested_route_and_paginates`,
  `test_resolve_context_request_sibling_handlers_reports_unresolved_when_no_siblings_exist`,
  `test_resolve_context_request_search_finds_matches_in_the_repository`,
  `test_resolve_context_request_search_reports_unresolved_for_an_empty_pattern`,
  `test_resolve_context_request_search_reports_unresolved_when_nothing_matches`,
  `test_resolve_context_request_knowledge_returns_stored_entries`,
  `test_resolve_context_request_knowledge_reports_unresolved_without_a_configured_store`,
  `test_resolve_context_request_knowledge_reports_unresolved_for_an_empty_query`).
- Expanded `HuntTask` reference fields with runtime ID validation —
  implemented. `HuntTask.inventory_refs`, `.sensitive_effect_refs`, and
  `.authentication_path_refs` already existed as free-text string arrays with
  no check that a value named anything real — the model could reference a
  file, sensitive effect, or authentication path that was never in the
  repository context it was given. New `_validate_hunt_plan_references`
  (`ai.py`) builds the real ID sets straight from the same
  `AIRepositoryContext` the hunt-plan request was built from —
  `source_inventory[].path`, `sensitive_effects[].effect_id`,
  `authentication_paths[].name` — and `plan_tasks` calls it right after
  parsing the model's tasks (before persisting the plan), raising
  `AIResponseError` and naming the task and the offending ref on the first
  unknown one, so a hallucinated reference fails the plan instead of being
  silently trusted. `entry_points` was left out of scope: unlike the three
  `_refs` fields, it's a required free-text field with no `_refs` suffix and
  predates the richer dict-shaped `repository_context.entry_points`, so
  constraining it now would be guessing at intent rather than fixing a real
  gap. `hunt_plan/system.md` was reworded to tell the model each `_refs`
  field must copy an exact ID from the supplied repository context (or stay
  empty) rather than invent one. Covered by `tests/test_ai.py`
  (`test_validate_hunt_plan_references_accepts_refs_present_in_the_repository_context`,
  `test_validate_hunt_plan_references_rejects_an_unknown_inventory_ref`,
  `test_validate_hunt_plan_references_rejects_an_unknown_sensitive_effect_ref`,
  `test_validate_hunt_plan_references_rejects_an_unknown_authentication_path_ref`,
  `test_plan_tasks_rejects_a_hunt_plan_with_a_hallucinated_inventory_ref`).
- Simplified discovery schema: dropped `remediation` — implemented, scoped
  down from the original proposal. `severity` and `vulnerability_class`
  stay in `vulnerability_discovery.json`/`variant_sweep.json`/
  `capability_chain.json` because they are load-bearing before Deep Hunt
  ever runs: `JevRouter.classify` (`jev.py`) reads `candidate.severity` for
  tier escalation and feeds `candidate.vulnerability_class` into the JEV
  routing payload, so removing either would require a JEV routing redesign
  first. `remediation` had no such dependency — Deep Hunt review always
  overwrites `finding.remediation` for a supported candidate
  (`pipeline.py`'s `verify()`), and a rejected candidate's discovery-stage
  `Finding` is discarded entirely, so the discovery-stage value was never
  authoritative. Removed `remediation` from the three schemas'
  `properties`/`required` (kept `set(properties) == set(required)` for
  OpenAI strict mode); `_candidate_from_ai_item` (`ai.py`) no longer reads
  `item["remediation"]` into `metadata["ai_remediation"]`;
  `vulnerability_discovery/system.md` no longer instructs the model to
  produce a remediation. `validation.py`'s `FindingValidator.validate`
  already fell back to `defaults["provisional_remediation"]` when
  `candidate.metadata.get("ai_remediation")` was absent, so no change was
  needed there — that fallback simply always applies pre-Deep-Hunt now.
  `finding.remediation` itself, and the separate `finding_consolidation`/
  `finding_group_narratives` schemas that set it post-Deep-Hunt, were left
  untouched since they operate on already-verified `Finding`s, not
  discovery candidates. Covered by `tests/test_ai.py`
  (`test_candidate_from_ai_item_does_not_populate_a_remediation_metadata_key`,
  plus the existing `test_candidate_from_ai_item_does_not_require_a_confirmed_field`
  and discovery-flow test updated to assert `"ai_remediation" not in
  candidates[0].metadata`).

Exit condition: met by unit/E2E fixtures; repeated real-repository acceptance
evidence remains required before production release.

## 2. ripgrep + Tree-sitter Code Intelligence

### 2a. Generic incremental core — implemented

- AI-created `rg` queries are the primary discovery and navigation path. The
  executor contains no vulnerability search expressions; it only validates and
  executes bounded model-produced queries.
- Tree-sitter persists a compact syntax Security IR for files, stable symbols,
  imports, and calls. AI reconnaissance supplies repository-specific entry
  points, input surfaces, sensitive effects, controls, trust boundaries, and
  security invariants. These roles are not inferred from hardcoded framework or
  vulnerability patterns.
- A full AST and whole-program dataflow graph are not persisted. An AI review
  can request a bounded bidirectional call-flow slice only when a concrete flow
  question remains open.
- Symbol identity remains stable across body and line changes; content hashes
  independently trigger invalidation.
- The external language inventory covers the primary supported languages and
  common build/dependency manifests. Project exclusions and exact maximum file
  sizes apply to inventory, Tree-sitter IR, `rg`, source windows, context
  expansion, and patch evidence.
- Content-addressed bases and overlays propagate changes through reverse call
  dependencies without introducing SCM concepts into Code Scanning.
- Verified evidence is linked automatically to exact stable symbol
  dependencies.
- Per-segment discovery and variant calls receive focused source plus a compact
  repository context; they no longer resend the repository-wide source tree,
  inventory, or Security IR. Every LiteLLM call records only a content-free
  payload hash, character counts, tier, operation, and broad-context flag for
  audit and cost analysis.

The exit condition is met by
`tests/test_context_fabric.py::test_changed_callee_keeps_identity_and_revalidates_unchanged_caller`,
`tests/test_context_fabric.py::test_unrelated_change_reuses_linked_finding_context`,
`tests/test_ai.py::test_ai_builds_context_then_discovers_evidenced_candidates`,
`tests/test_ai.py::test_ai_can_request_a_bounded_call_flow_only_when_needed`,
and the source-policy cases in `tests/test_graph_jev.py` and `tests/test_ai.py`.

### 2b. Optional precision adapters — deferred follow-on

- Add compiler/LSP semantic indexes for languages where they materially improve
  symbol resolution beyond Tree-sitter.
- Add targeted, language-specific taint/dataflow adapters for an AI-identified
  flow question that cannot be proven from the bounded Security IR slice.
- A bounded call-flow slice is structural navigation, not a taint proof. Until
  an adapter exists for a required flow, the review must preserve the evidence
  gap or mark required coverage incomplete; it must never treat missing
  precision as proof that the code is safe.

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
  gate. A `flow` request returns a bounded bidirectional call neighborhood and
  its definitions. `_resolve_context_request()` answers each request purely from the
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
- JEV decision-plane hardening (3 concrete defects fixed plus scope-driven
  retrieval, `context_profile` decomposition, capability-chain frontier
  prioritization, and retry routing, scoped to changes with no design
  ambiguity; the remaining JEV-as-decision-plane redesign — structured
  knowledge cards and scan-budget allocation — is scoped separately and not
  yet built). This completes all 4 of the "jobs" JEV was scoped to as a
  decision plane (model routing, context routing, knowledge routing,
  frontier routing):
  - `JevClient.decide_questions` (`jev.py`) now routes `state` through
    `redact_payload` before sending it to the remote JEV endpoint. JEV is a
    generative-provider boundary like any other and `redaction.py`'s own
    contract says every such payload must pass through it first; this
    boundary had silently never done so. Covered by
    `tests/test_graph_jev.py::test_jev_client_redacts_secrets_from_state_before_sending`.
  - `JevKnowledgeRouter.classify` (`knowledge.py`) sent
    `repository_context.get("repository")` to JEV, but
    `AIRepositoryContext.to_dict()` has no `repository` key (it's
    `codebase`) — the field was always `null`, silently starving the
    `knowledge_scope` decision of the one fact it most needs. Fixed to read
    `codebase`. Covered by
    `tests/test_knowledge.py::test_jev_knowledge_router_sends_the_codebase_identifier`.
  - `KnowledgeCoordinator.resolve_many` (`knowledge.py`) batched every
    pending `research_web` query in a hunt task into a single research call,
    then attached the same combined `entries` list to every one of those
    queries — a query about JWT audience verification could receive research
    results that actually answered a different, unrelated query in the same
    task, contaminating the evidence a later Deep Hunt round reasons from.
    Fixed by calling `research_provider.research` once per distinct pending
    query, so a query's results are only ever the results for that query.
    This trades the prior single-call-per-task cost optimization for
    correctness; reintroducing batched research with per-query attribution
    (e.g. a `query_id`-tagged response schema) is a valid future enhancement
    but out of scope here. Covered by
    `tests/test_knowledge.py::test_fresh_research_queries_are_resolved_independently_per_hunt_task`
    and
    `tests/test_knowledge.py::test_resolve_many_does_not_attribute_one_querys_research_to_another`.
  - `knowledge_scope` (JEV's `repository`/`business_domain`/`framework`/
    `vulnerability_class`/`advisory` classification, `knowledge.py`) was
    decided but then ignored: both `KnowledgeCoordinator.resolve` and
    `resolve_many` ran the same fixed `task.title + task.objective +
    vulnerability_themes` search terms against `KnowledgeStore.search`
    regardless of which scope JEV chose, so a `repository`-scoped and an
    `advisory`-scoped decision retrieved identically. Added a
    `_retrieval_terms(scope, query, task, repository_context)` helper that
    maps each scope to the fields that actually carry that kind of fact
    (`repository` → `repository_context["codebase"]`/`architecture`;
    `framework` → `architecture`/`entry_points` text, there being no
    dedicated framework/version field in `repository_context.json`;
    `business_domain` → `business_invariants`; `vulnerability_class` →
    `vulnerability_themes`; `advisory` → `vulnerability_themes` +
    `external_services`), falling back to the raw query when nothing scope-
    relevant is known. Wired into both `resolve` and `resolve_many`'s
    `retrieve_database` branches, replacing the previous scope-blind terms.
    Covered by `tests/test_knowledge.py::test_retrieval_terms_uses_repository_scoped_task_facts`,
    `test_retrieval_terms_uses_framework_scoped_repository_facts`,
    `test_retrieval_terms_uses_business_domain_scoped_facts`,
    `test_retrieval_terms_uses_vulnerability_class_scoped_facts`,
    `test_retrieval_terms_uses_advisory_scoped_facts`,
    `test_retrieval_terms_falls_back_to_the_query_when_nothing_is_known`,
    and the integration test
    `test_resolve_retrieves_with_scope_shaped_terms`.
  - `context_profile` (`routing/jev.json`) was a single mutually exclusive
    choice (local/cross_file/stateful/external_knowledge/mixed), but more
    than one axis is routinely relevant at once, and the value was never
    actually consumed anywhere downstream — only echoed into
    `finding.metadata["context_profile"]` for reporting. Replaced with 5
    independent NOUL (no/unlikely/likely/yes) signals —
    `needs_cross_file`, `needs_state_reconstruction`,
    `needs_external_semantics`, `needs_environment_context`,
    `needs_deep_falsification` — plus a 1-5 `analysis_complexity` score.
    `JevAnswer`'s existing `{choice, confidence}` wire contract is reused
    unchanged (no new JEV question type was invented; this is the only
    contract this codebase has ever proven against the real endpoint).
    `RouteDecision.profile` is gone; the 6 new fields live on
    `RouteDecision` directly, are threaded into `finding.metadata` as
    `jev_needs_*`/`jev_analysis_complexity`, and are surfaced in SARIF as
    `jevNeeds*`/`jevAnalysisComplexity` properties
    (`jev.py`, `models.py`, `validation.py`, `reporters.py`).
    `JevRouter._local_classify`'s fallback sets all 5 signals to `likely`
    and complexity to 4 for CRITICAL/HIGH severity, `unlikely`/2 otherwise
    — preserving today's severity-based behavior when JEV is absent.
    These signals are now wired into two real behaviors rather than left
    as unused diagnostics:
    - `AIAgent.hunt`'s context-expansion budget
      (`_context_expansion_max_requests` in `ai.py`) grows by
      `context_expansion_signal_bonus_requests` (2) per breadth signal
      (`needs_cross_file`/`needs_state_reconstruction`/
      `needs_external_semantics`/`needs_environment_context`) reporting
      `likely`/`yes`, capped at `context_expansion_max_requests_per_round_ceiling`
      (13, both new `runtime/agent.json` keys). This only ever grows the
      budget above the prior static base of 5, never below it.
    - `_structured_response`'s reasoning effort can be escalated above the
      operation's static `reasoning_effort_by_operation` default (never
      below it — `_stronger_effort` in `ai.py`) via
      `_hunt_effort_override`, which escalates to `high` when
      `analysis_complexity >= 4` or `needs_deep_falsification` is
      `likely`/`yes`. Note: `security_review`/`metadata_exposure_review`
      are already statically configured at `high`, so this override is
      currently inert for `hunt()`'s own call site — lowering that static
      baseline so the escalation has a production effect is a deliberate
      cost/rigor trade-off left for the user to decide, not bundled into
      this change.
    Covered by `tests/test_graph_jev.py::test_jev_escalates_ssrf_to_deep`,
    `test_jev_uses_high_confidence_remote_route`,
    `test_jev_falls_back_when_confidence_is_low`, and (in `test_ai.py`)
    `test_stronger_effort_escalates_above_the_configured_default`,
    `test_stronger_effort_never_downgrades_the_configured_default`,
    `test_hunt_effort_override_is_none_without_a_route`,
    `test_hunt_effort_override_escalates_for_a_high_complexity_route`,
    `test_hunt_effort_override_escalates_for_a_falsification_flagged_route`,
    `test_hunt_effort_override_is_none_for_a_low_complexity_uncontested_route`,
    `test_structured_response_escalates_reasoning_effort_when_jev_route_demands_it`,
    `test_context_expansion_max_requests_defaults_without_a_route`,
    `test_context_expansion_max_requests_grows_with_breadth_signals_and_is_capped`,
    `test_hunt_caps_context_expansion_requests_per_round_by_default`, and
    `test_hunt_expands_more_context_per_round_when_jev_route_flags_broad_evidence_need`.
  - Capability-chain frontier prioritization: `chain_capability_pivots`
    (`ai.py`) treated every verified finding with a non-empty
    `gained_capability` uniformly — no ranking and no budget cap — so a
    finding set with many capable roots could spend unbounded AI search
    budget chasing pivots from all of them at once. Added
    `routing/capability_chain_frontier.json` (a single `pivot_priority`
    choice question: `low`/`standard`/`high`), `FRONTIER_PRIORITY_WEIGHT`,
    `FrontierDecision`, and `JevFrontierRouter` (`jev.py`) — mirroring
    `JevRouter`'s "always-works" pattern (optional client, deterministic
    `_local_prioritize` severity-based fallback: CRITICAL/HIGH → `high`,
    else `standard`) rather than `JevKnowledgeRouter`'s externally-gated
    pattern, since budget-capping must apply deterministically whether or
    not JEV is configured. `PlaidNoxDeepHuntAgent` gained a
    `frontier_router` attribute (defaulting to a local-only
    `JevFrontierRouter()`) and a `configure_capability_frontier` setter,
    wired in `cli.py` alongside the existing `configure_knowledge` call.
    `chain_capability_pivots` now ranks capable findings by
    `FRONTIER_PRIORITY_WEIGHT[JevFrontierRouter.prioritize(...).priority]`
    (stable sort, so equal-priority findings keep their original order) and,
    when the capable list exceeds the new `capability_chain_max_frontier`
    (5, `runtime/agent.json`), keeps only the top-N ranked findings in the
    `capability_payload` sent to every search segment — this only ever
    narrows which findings are chased, it never changes verification: every
    finding that already passed Deep Hunt stays a reported finding
    regardless of frontier ranking. Covered by
    `tests/test_graph_jev.py::test_frontier_priority_weight_orders_low_below_standard_below_high`,
    `test_frontier_router_locally_prioritizes_high_severity_capabilities_as_high`,
    `test_frontier_router_locally_prioritizes_other_severities_as_standard`,
    `test_frontier_router_uses_high_confidence_remote_route`,
    `test_frontier_router_falls_back_when_confidence_is_low`, and (in
    `test_ai.py`)
    `test_capability_chain_caps_and_prioritizes_findings_when_over_budget`.
  - Retry routing: `hunt`'s context-expansion round loop (`ai.py`) exhausts
    its budget after `context_expansion_max_rounds` (2) rounds and, if a
    genuine evidence gap remains (`review.context_requests` still
    non-empty), previously just returned whatever `review` it had —
    Deep Hunt had already expanded context twice with no further decision
    point, exactly the scenario the original JEV proposal calls out for a
    retry decision. Added `routing/retry_route.json` (a single `next_action`
    choice question: `retry_same_model`/`escalate_model`/`expand_context`/
    `mark_unresolved`), `RetryDecision`, and `JevRetryRouter` (`jev.py`) —
    same "always-works" pattern as `JevRouter`/`JevFrontierRouter` (optional
    client, deterministic `_local_decide` fallback: escalate the model tier
    if the candidate was never routed to DEEP, else expand context if a
    request is still pending, else mark unresolved). `hunt`'s round-loop
    body was extracted into `_run_hunt_round` (used unchanged by both the
    normal loop and the new retry path, so nothing about the existing
    request shape changed) and a new `_apply_retry_route` consults
    `self.retry_router` — a new `retry_router` attribute (defaulting to a
    local-only `JevRetryRouter()`) with a `configure_retry_route` setter,
    wired in `cli.py` alongside the frontier router — exactly once after
    the round loop ends with a pending gap, bounded to at most one
    additional `_run_hunt_round` call regardless of the chosen action, so
    retry routing can never grow unbounded. `escalate_model` forces
    `ModelTier.DEEP` and `"high"` reasoning effort for that one round;
    `expand_context` (also covering the proposal's `external_research`,
    since which specific context a pending request resolves to is already
    deterministic per-kind dispatch in `_resolve_context_request`, not a
    JEV decision) resolves the pending `context_requests` before the extra
    round; `retry_same_model`/`mark_unresolved` change nothing about
    routing, with `mark_unresolved` skipping the extra round entirely. The
    state sent to JEV (`_retry_facts`) is investigation-progress facts only
    — `model_tier`, `rounds_used`, `context_requests_pending`,
    `resolved_requests`, `unresolved_gates` (from `gate_results`), and
    `evidence_gaps`/`confidence_history` — never source code. Covered by
    `tests/test_graph_jev.py::test_retry_router_locally_escalates_a_candidate_never_routed_to_deep`,
    `test_retry_router_locally_expands_context_for_a_deep_candidate_with_a_pending_request`,
    `test_retry_router_locally_marks_unresolved_when_deep_and_nothing_pending`,
    `test_retry_router_uses_high_confidence_remote_route`,
    `test_retry_router_falls_back_when_confidence_is_low`, and (in
    `test_ai.py`)
    `test_ai_review_stops_requesting_context_at_the_configured_round_limit`
    (updated to assert the bounded extra round and the escalated model),
    `test_ai_review_retry_route_does_not_add_a_second_extra_round`,
    `test_ai_review_retry_route_skips_the_extra_round_when_jev_marks_unresolved`.
  - Structured knowledge claim cards: `JevKnowledgeRouter.classify` sent
    JEV only stored-knowledge *metadata* (`knowledge_id`, `topic`,
    `ecosystem`, `framework`, `source_url`, `source_updated_at`,
    `confidence`) — never what a stored entry actually says — so JEV could
    not genuinely judge `USE_DATABASE` vs `RETRIEVE_DATABASE` vs
    `RESEARCH_WEB` sufficiency from a title and a source URL alone. Added a
    `claims: list[str]` field to `KnowledgeEntry` (short, plain factual
    statements the entry asserts, not the full `content` body) and threaded
    it through every layer that produces or stores knowledge: `normalised()`
    strips/truncates each claim to `knowledge_claim_characters` (240,
    `runtime/agent.json`) and caps the list to `knowledge_max_claims` (6);
    `JevKnowledgeRouter.classify`'s `stored_knowledge` payload now includes
    `"claims": item.claims` per entry; `LiteLLMKnowledgeProvider.research`'s
    LLM schema (`schemas/knowledge_research.json`) requires a `claims` array
    (1-6 items, 240 chars each) per returned entry, with the research prompt
    (`prompts/operations/knowledge_research/system.md`) instructing the
    model to extract them; both storage backends persist and round-trip
    claims — SQLite (`sql/knowledge/upsert.sql`, `search.sql`,
    `migrations/0003_security_knowledge.sql`, JSON-encoded as a `TEXT`
    column) and PostgreSQL (`migrations/postgresql/0001_code_scanning_core.sql`
    adds `claims JSONB NOT NULL DEFAULT '[]'::jsonb`,
    `persistence/models.py`'s `SecurityKnowledgeRecord` adds a `JSON`-typed
    `claims` column, `persistence/repositories.py`'s `KnowledgeInput`/
    `_knowledge_value` and `persistence/adapters.py`'s
    `PostgresKnowledgeStore` carry it through unchanged). `claims` is
    deliberately excluded from `content_hash` (claims summarize `content`,
    they are not new identity), so re-upserting identical topic/content/
    source with different claims still dedupes to the same row. Covered by
    `tests/test_knowledge.py::test_knowledge_entry_normalised_strips_and_caps_claims`,
    `test_knowledge_store_round_trips_claims`,
    `test_jev_knowledge_router_sends_stored_claims_not_just_metadata`,
    `test_perplexity_sonar_research_keeps_only_returned_citations` (extended
    to assert `claims`), and
    `tests/test_persistence_adapters.py::test_postgres_knowledge_store_round_trips_claims`.
  - Scan-budget allocation: `JevRouter.classify` (`pipeline.py`) already
    routes each candidate to FAST/STANDARD/DEEP independently based on its
    own severity/signals, but nothing bounded how many candidates could land
    on the most expensive DEEP tier in a single scan — a candidate set with
    unusually many CRITICAL/HIGH findings (or a JEV instance that is simply
    generous with DEEP) could still reach "200 x strongest model x high
    reasoning," the exact cost blowup the original JEV proposal calls out.
    Added a scan-wide `deep_hunt_budget_max` cap (60, `runtime/agent.json`):
    each round now classifies every queued candidate up front (`round_routes`,
    replacing per-candidate classification inside the worker closure) before
    dispatching to the `ThreadPoolExecutor`, so the cap can be enforced
    deterministically and sequentially rather than racing a shared counter
    across worker threads. If the round's DEEP-tier candidates exceed the
    scan's remaining budget, they are ranked by the existing
    `priority_score(severity, confidence, depth)` helper (already used for
    final finding ordering, reused rather than inventing a second scoring
    scheme) and the lowest-priority overflow is demoted to STANDARD tier
    (`dataclasses.replace` on the `RouteDecision`, appending "; demoted by
    scan deep-hunt budget" to `reason` so `jev_used` tracking — which checks
    `reason.startswith("JEV ")` — stays correct for JEV-originated routes).
    This is deliberately *not* a new JEV question: JEV already made the
    narrow per-candidate depth decision, so capping the aggregate spend is
    pure deterministic composition over already-decided routes, matching the
    "narrow decisions, deterministic code composes the results" principle
    the proposal itself opens with — the same shape already used by
    `JevFrontierRouter`'s top-N capability-frontier cap. The budget is
    scan-wide (not per-round): `deep_budget_used` accumulates across the
    discovery/variant-sweep/capability-chain rounds of a single
    `scan_snapshot` call, since new candidates keep entering `work_queue`
    across rounds and the cost concern is the whole scan, not one round of
    it. Demotion never removes a candidate from disposition — every
    candidate still gets a Deep Hunt verdict, just at a cheaper tier, so this
    only ever narrows *which* candidates get the strongest model, exactly
    like the frontier cap only narrows which pivots get chased first. New
    `jev_deep_budget_demotions` metric on `ScanResult`. Covered by
    `tests/test_pipeline.py::test_pipeline_demotes_the_lowest_priority_excess_deep_routes_to_respect_the_scan_budget`
    and
    `test_pipeline_does_not_demote_deep_routes_within_the_configured_budget`.

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

## Parallel SCM workstream

SCM Integration is active in the separate `plaidnox_scm` package. Code
Scanning remains an immutable-snapshot analysis API with no provider-specific
orchestration. SCM implementation status and delivery order are maintained in
`docs/PRODUCT_WORKSTREAMS.md`.
