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
  passes through the full independent tier-routing + Deep Hunt review pipeline
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
- Local knowledge routing (stored -> broadened search -> web), Perplexity research with source validation, durable
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
  ever runs: `CandidateRouter.classify` (`routers.py`) reads `candidate.severity` for
  tier escalation and feeds `candidate.vulnerability_class` into the
  routing rules, so removing either would require a routing redesign
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

## 2. Graphify-backed investigations — in progress

The accepted target is [Graphify-backed investigations](../PLAN.md#graphify-backed-investigations-for-code-scanning):
Graphify supplies versioned structural navigation; the AI planner groups
security surfaces into bounded investigations; PlaidNox Deep Hunt retains final
verdict ownership. The structural adapter, snapshot-delta contract, and first
graph-backed context queries are implemented in `graphify_adapter.py` and
`graph_context.py`. The versioned Investigation contract, tenant-scoped ORM
ledger, PostgreSQL migration, and first AI planner slice are implemented. The
planner receives one bounded Graphify neighborhood and cannot preserve model-
invented graph references. Surface enumeration/batching, scan-runtime
checkpointing, and opt-in investigation execution are implemented. Each
investigation is checked against current file hashes, reviewed through an
external prompt/schema contract, and candidate locations are grounded only to
its immutable source windows. Accepted hypotheses enter the existing
independent Deep Hunt verifier; Graphify itself never supplies a finding
verdict. Investigation execution remains opt-in with
`--graphify-investigations`; shadow planning alone remains non-authoritative.
When PostgreSQL persistence is configured, investigation lifecycle transitions
are compare-and-swap persisted (`planned → running → candidate/no_candidate/
unresolved/failed`). Structured discovery responses use the existing LiteLLM
response checkpoint, so completed calls replay without provider calls. Typed
Graphify context expansion is bounded to one delta continuation, at most three
requests and a configured source-character budget; repeat/empty context cannot
trigger another model call. Exact-snapshot persisted Tree-sitter summaries are
loaded into Graphify planning only for paths in the bounded graph neighborhood,
with external limits and explicit syntax-only provenance. Typed relationship
requests use configured CALLS/REFERENCES/IMPORTS edge kinds. If Graphify returns
no relationship, a bounded AI-provided literal may use fixed-string `rg` under
the same admitted-file policy; the result is source-grounded fallback evidence
and does not manufacture a graph edge. Repository reconnaissance's open-ended
`sensitive_effects` now explicitly covers state/persistence, outbound network,
filesystem, and rendering/template/PDF effects with exact source locations.
Source excerpts are rechecked against the current
snapshot and redaction output before every model request. Context request yield,
continuation count, and characters are reported. Typed request-to-graph mappings
live in `runtime/graph_context_queries.json`, separate from resolver execution.
The validated aggregate candidate/disposition result is also checkpointed per
investigation identity and evidence hash; it replays without graph queries or
model calls, then transitions the current scan's ORM lifecycle independently.
Failed or contract-invalid investigations do not write this result checkpoint.
An unresolved question or failed execution remains visible in
coverage and makes an opt-in Graphify investigation run incomplete. Tests are
in `tests/test_graph_investigation_hunt.py`, the pipeline/ORM integration test
`test_pipeline_executes_graphify_investigations_through_shared_deep_hunt_and_persists_state`,
`tests/test_graph_planner.py`,
`tests/test_graph_surface_planning.py`, and `tests/test_pipeline.py`. Switch the
default only after seeded-root recall, grounding, incremental invalidation, and
checkpoint resume reach parity. Direct delta-to-investigation invalidation is
now available as `affected_investigation_ids()` in
`graphify_adapter.py`: it identifies investigations depending on changed source
files, nodes, edges, and newly changed edges attached to their target nodes,
without treating the global snapshot marker as a dependency on every task.
`tests/test_graphify_adapter.py` verifies affected versus unrelated work and
removed-edge dependencies. Cross-snapshot planning reuse, graph invalidation,
and finding dependency carry-forward are implemented and persistence-tested.
Graphify remains opt-in pending real acceptance evidence for seeded recall,
finding preservation, grounding, coverage gaps, interruption/resume, and cost.

The sections below describe the current Tree-sitter/`rg` runtime and its
already implemented contracts. They are migration inputs, not the new target.

### Current workset and source-slice implementation

The current runtime analyzes region-owned obligations through bounded
`SecurityWorkset` batches. During the migration, `DiscoveryRegion` remains
source-window transport. `Investigation` becomes the new coverage identity.

A workset is the coverage and review identity. Its bounded `SecuritySlice` may
contain source and IR evidence from several files, exact source provenance,
relevant controls/effects, and explicit unresolved relationships. Per-symbol
`SecuritySummary` facts are content-versioned and composable. Large repository
size should raise index cost and possible workset count, but must not create one
model call per file or arbitrary source region.

The rollout is staged. **Stage 1 is implemented** in `plaidnox_sast.worksets`:
versioned workset/slice/summary dataclasses, JSON Schemas, an adapter from
current region payloads, explicit unresolved-edge and completeness fields,
source/fact redaction, and lossless configured batching. Tests are in
`tests/test_worksets.py`. **Stage 2 is partially implemented:** the graph planner
builds route-registration worksets with bounded source slices and unique
referenced definitions, and creates compositional structural summaries with
unique call resolution and explicit unresolved-call records. It intentionally
does not make every function a review workset. This remains syntax evidence:
it does not claim middleware roles, runtime reachability, taint, or exploitability.
It also emits generic `symbol_registration` worksets for top-level calls that
reference uniquely indexed symbols. These preserve exact call/source evidence
while leaving the registration role and runtime execution unresolved; no
framework-specific job catalogue is embedded. Route/registration slices expose
callable-signature syntax as a boundary observation with trust and reachability
left unresolved. Per-symbol summaries include call-site text and uniquely
resolved symbol IDs, but do not claim data flow or side effects.
Repository-context reconnaissance receives an area-balanced, bounded inventory
with explicit omissions; incremental runs include only surfaces intersecting
changed or affected paths.
Live discovery adapts planned source regions into bounded workset batches. An
unambiguous route or top-level registration match can add indexed definitions
from related files while preserving the complete discovered region. If a graph
workset needs multiple batches or contains an excluded or sensitive source,
discovery uses the region adapter and records the deferral. The task plan still
owns obligations; graph relationships remain syntax evidence with unresolved
edges. Deep Hunt verifies candidates using its existing evidence packet contract.

AI-derived repository-context annotations now accept optional exact source
locations for input surfaces, trust boundaries, entry points, sensitive effects,
authentication paths, and authorization decisions. Runtime grounding verifies
repository containment, membership in the current Tree-sitter file index,
content-hash agreement with the immutable snapshot, one-based line bounds, and
an optional verbatim quote. Incremental carry-forward is limited to a matching
record identity whose source location still verifies against the current
snapshot. Per-location provenance and aggregate metrics make failures visible.
This proves source-location identity only; it does not validate the model's
semantic claim or treat annotations as security verdicts. Tests are in
`tests/test_ai.py` (`test_repository_annotation_locations_*`).

Live discovery now groups source regions by canonical structural surface into
`SecurityWorkset` units. Configured lossless slice batches are the model review
units, source excerpts are sent once within their slices, and candidate
locations are grounded only against windows in that batch or newly resolved
Context Broker evidence. Matching route/registration worksets add exact
cross-file source windows without treating indexed references as confirmed
runtime calls or security controls. Checkpoints are scoped to workset evidence hash and
batch index; telemetry separates source regions, unique worksets, and review
batches. Planned multi-batch obligations are now reconciled across all assigned
batches before global coverage accounting. An unresolved answer, missing answer,
or missing planned batch cannot be hidden by a clean sibling batch; telemetry
records reconciled, unresolved, and missing batch work. Every selected workset
batch now also receives a required open-ended surface-review obligation with a
stable workset identity, so a clean answer from one batch cannot complete a
multi-batch surface. The task plan retains hunt-specific obligations. Coverage
of trust-boundary and sensitive-effect surfaces that produce no search-hit
region is supplied by AI reconnaissance annotations and remains subject to the
pinned acceptance scan. Tree-sitter
indexed HTTP routes and top-level symbol registrations in admitted source scope
now seed regions even when `rg` returns no hit; already covered source is reused.
Registration roles, runtime reachability, and security semantics remain
unresolved until AI review and Deep Hunt verification. The indexed workset
inventory is built once per discovery pass and reused for context enrichment.
Prompt and checkpoint versions were advanced for the expanded contract.

**Stage 3 is partially implemented:** summaries are persisted per immutable
base snapshot in the SQLite Context Fabric and ORM-backed PostgreSQL adapter,
with idempotent writes and conflict detection. Existing snapshot call edges
provide reverse-dependency fanout. Summary and dependency IDs share persisted
stable symbol IDs, verified by tests that walk a caller from a changed callee.
SQLite and PostgreSQL overlays store only changed summary records and deletion
tombstones; effective readers merge parent snapshots with sparse deltas. The
PostgreSQL schema adds a dedicated overlay-summary table and tenant-scoped ORM
resolution. Tests cover changed callee fanout, updated caller relationships,
line-only provenance shifts, and deleted symbols. Live Graphify planning now
loads persisted summaries for the current Context Fabric base/overlay, scopes
them to graph-neighborhood source paths, and caps the planner payload through
runtime assets. Summary facts remain syntax observations, not security claims.

Next: validate Graphify's structural extraction and stable PlaidNox IDs on the
existing regression corpus and run the real paired acceptance suite. Preserve
persisted summaries and overlays until Graphify-backed context retrieval and
investigation invalidation pass release acceptance.
SCIP, Joern, and OpenGrep remain optional future evidence adapters.
No indexer, CPG engine, or deterministic scanner is a final verdict authority.
All reportable candidates still require independent PlaidNox Deep Hunt
verification and evidence validation. Third-party rule content is not imported.

Execution health and coverage are distinct report concepts. A failed mandatory
stage is unsuccessful execution. Parser/language gaps and unresolved graph edges
are explicit coverage limitations; they do not claim the corresponding paths are
safe.

Scale acceptance uses synthetic, deterministic fixtures around 2k, 20k, and
100k LOC with a fake model gateway. Record Graphify index/update time,
surfaces, investigations, prompt bytes, fanout, cache reuse, memory, and model
calls. Gate on
correct known-vulnerability recall and contract validity before optimizing
parallelism or adding optional external tools.

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
and the source-policy cases in `tests/test_routing.py` and `tests/test_ai.py`.

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
  `agent_model_by_tier` map; `CandidateRouter.classify()`'s `RouteDecision.model_tier`
  is threaded from `pipeline.py`'s `verify()` into `PlaidNoxDeepHuntAgent.hunt()`
  / `.review()`, which resolve the tier to a concrete model per call
  (`_model_for_tier`) instead of a single fixed `self.model`. Recon, planning,
  discovery, variant sweeping, and consolidation remain on the default model —
  Tier routing is candidate-scoped and does not naturally apply to those
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
  root; `AIConfigurationError`/`AIResponseError` (`ai.py`) and `SAISTError` (`saist.py`) all inherit from it. The broad
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
- Routing is deterministic and config-driven. `routers.py` holds `CandidateRouter`
  (severity -> depth/model tier), `FrontierRouter` (pivot priority), `RetryRouter`
  (escalate model / expand context / mark unresolved) and, in `ai_sast`,
  `ModelExecutionRouter` (per-operation override, else `agent_fallback_model_by_tier`).
  Knowledge routing is inline in `KnowledgeCoordinator` (stored hit -> broadened local
  search -> web research). Every generative call goes through LiteLLM with models chosen
  from `runtime/models.json`; there is no remote decision service. The scan-wide deep
  budget demotes the lowest-priority excess DEEP routes (`deep_budget_demotions` metric).
  Covered by `tests/test_routing.py`, `tests/test_knowledge.py` and `tests/test_pipeline.py`.

Exit condition: every accepted or rejected candidate has a complete audit trail,
and unresolved required canonical coverage can never produce a successful scan — met for the
in-process pipeline (proven by `tests/test_pipeline.py`'s
`test_pipeline_marks_the_scan_incomplete_when_contextual_ai_discovery_fails`
and `test_pipeline_never_reports_a_candidate_without_an_ai_verdict`); the
optional patch proposal/rescan verification stage is additive and does not
change this exit condition.

## 5. End-to-end validation — foundation implemented, evidence pending

Scan20 follow-up fixes are implemented and covered by automated tests: discovery
candidates can be grounded in immutable source windows returned by the Context
Broker (with a regression test proving a cross-file candidate reaches the
verification queue); route regions receive a local projection of only their
matching hunt tasks; each expansion is capped at three ranked context requests;
and operational completion is recorded separately from resolved coverage.
Deep Hunt output is compacted by the external schema and Markdown prompt, with
a 5,000-token operation ceiling. A later successful unit supersedes only a
retryable attempt with the same operation and stable work identity. Reported
ripgrep totals now combine reconnaissance and optimized-discovery counters,
with per-stage breakdowns. These changes pass the full automated suite; they
still require the pinned cold NSTCTF acceptance run below.

The Scan20 discovery contract replaces model-directed `coverage_complete` /
`next_focus` recursion. Structural regions now carry stable obligation IDs;
every initial response dispositions each obligation; only `NEEDS_CONTEXT`
reaches the Context Broker; and only a nonempty, previously unseen evidence
delta permits a bounded continuation. Candidate evidence is merged before
verification and compiled into `CandidateEvidencePacket`. Acceptance reports
must include region/call ratio, obligation outcomes, Context Broker yield,
blocked empty continuations, initial versus continuation input size, semantic
candidate merges, and verification dispositions. The cold NSTCTF gate is at
most 40 discovery calls, at most 1.5 calls per region, at most 15 executed
continuations, duplicate candidate ratio below 40%, zero discovery failures,
and a finding equivalent to the seeded root cause/invariant/capability. Warm
checkpoint benchmarking follows the cold correctness run.

Scan23 follow-up (implemented locally; source-scan acceptance pending):
scan health now uses global canonical obligation reconciliation rather than
raw per-region unresolved counts. Each invariant/effect/coverage item receives
its own canonical identity so a sibling region resolving one item does not
mask a different unresolved item. Obligations carry REQUIRED or SUPPORTING
importance; only unresolved REQUIRED canonical work affects scan health, while
all raw region results remain available as telemetry. Candidate discovery now
groups paraphrased hypotheses by immutable source root plus open-taxonomy
effect/capability family IDs and preserves member hypotheses in the single
Deep Hunt evidence packet. Conflicting nonempty family IDs never merge.
Typed Context Broker operations consult Security IR references and route spans
first, with ripgrep as an explicit fallback; reference matches do not claim
dataflow direction that the IR does not prove. Covered by
`tests/test_coverage.py`, `tests/test_fingerprint.py`, and the graph-first
resolver tests in `tests/test_optimized_discovery.py`. The next pinned cold
NSTCTF scan must verify that all required canonical obligations reach a
terminal result and that the Scan23 findings remain intact.

- Repeatable acceptance scans against `C0oki3s/NSTCTF` plus multi-language
  fixtures with known positives, variants, and clean controls.
- Measure coverage, validated recall, false positives, duplicates, IR/context
  reuse, prompt-cache reuse, tokens, latency, and cost by stage.
- Test prompt injection, redaction, malformed output, provider failure, stale
  knowledge, worker crash, and database recovery.
- Production worker image, migration job, configuration reference, and runbook.

Implemented artifacts: `acceptance.py` plus its external JSON Schema and
example manifest; the `evaluate-acceptance` CLI; checksum-verified migration
runner; immutable snapshot queue and worker; hardened Docker image/example;
the scan-local checkpoint journal; and the acceptance and operations runbooks.
The checkpoint persists redacted LLM input context, schema, execution route,
pending failure state, and successful structured output before moving to the
next operation. A rerun therefore resumes at the first unfinished model call
and replays prior completed calls without spending model tokens. Automated tests exercise the
evaluator, migration ordering/checksums, interruption-safe leases, retry
limits, scan finalization, model budgets, and failure paths without starting a
source scan.

Pending evidence: repeated pinned NSTCTF and multi-language acceptance scans,
human-reviewed expectation manifests, clean-environment bring-up, and a
disposable PostgreSQL backup/restore drill. This section is not marked complete
until those artifacts exist.

Exit condition: a clean deployment can migrate PostgreSQL, scan an immutable
local snapshot, resume interruption, and emit complete reports without SCM.

## 6. Production controls — implemented, staging proof pending

- Sandboxed read-only workers and explicit research-gateway egress.
- Queue leases, timeouts, quotas, tenant isolation, encryption, retention,
  deletion, artifact lifecycle, and disaster recovery.
- OpenTelemetry traces/metrics, redacted logs, cost ceilings, and alerts.
- Signed and versioned policy and runtime assets.

Implemented controls include tenant-scoped queue leases and heartbeats,
idempotency, bounded retries and subprocess timeouts, concurrent/daily/monthly
quotas, production TLS validation, mounted secrets, privacy-safe audit events,
artifact encryption/expiry metadata, deletion requests, scan completion state,
per-scan/per-model budgets, OpenTelemetry instrumentation, signed expiring
asset bundles, and a non-root read-only worker deployment example.

The release exit remains open until AWS staging demonstrates blocked default
egress with gateway-only provider access, encrypted artifact deletion,
backup/restore and disaster recovery, lease reclamation after forced worker
termination, actual telemetry export, sustained load, and LiteLLM-side hard
cost enforcement.

Exit condition: isolation, auditability, replay safety, recovery, performance,
and cost limits are demonstrated in staging.

## Parallel SCM workstream

SCM Integration is active in the separate `plaidnox_scm` package. Code
Scanning remains an immutable-snapshot analysis API with no provider-specific
orchestration. SCM implementation status and delivery order are maintained in
`docs/PRODUCT_WORKSTREAMS.md`.

GitHub provider behavior already lives in `PlaidNox/plaidnox-github-bot`.
Webhook signatures, installation tokens, check runs, inline comments, and
stale-HEAD publication must remain there. `plaidnox_scm` implements the
authenticated provider-neutral `POST /v1/reviews` contract consumed by that
bot and must not duplicate its provider adapter.
