# PlaidNox Code Scanning implementation plan

## Product boundary

This repository is currently building **Code Scanning only**: static source-code
understanding, AI-created hunt tasks, contextual vulnerability discovery,
adversarial validation, evidence, findings, and reports.

The scanner accepts an immutable local source snapshot plus an explicit codebase
identity and revision. It does not own GitHub, GitLab, pull requests, merge
requests, comments, checks, webhooks, cloning, or CI installation. Those belong
to the later SCM Integration workstream described in
`docs/PRODUCT_WORKSTREAMS.md`.

Dependency scanning, secret scanning, cloud and container scanning, IaC,
license risk, outdated-software management, DAST, and IDE plugins are also
separate products. They may reuse shared evidence and policy contracts after
Code Scanning reaches its end-to-end exit condition, but none is part of the
current scanner runtime.

## Engineering rules

These rules are mandatory for every PlaidNox Code Scanning change.

1. **No inline model assets.** Markdown prompt templates, JSON response schemas,
   model-tier mappings, classification criteria, and remediation instructions
   live in versioned assets under `src/plaidnox_sast/assets/`.
2. **PostgreSQL is the production database.** Runtime persistence uses
   SQLAlchemy 2.x ORM repositories. Ordered PostgreSQL DDL remains in standalone
   migration files so operators can review and apply it independently. SQLite
   is an explicit local/test adapter and is not the production architecture.
3. **No secrets in context or model input.** Secrets stay in a secret manager or
   process environment and are redacted before code is stored, cached, logged,
   or sent to any model.
4. **Production naming and boundaries.** Domain names describe Code Scanning,
   not a provider or an SCM: `Codebase`, `CodeSnapshot`, `ContextBase`,
   `ContextOverlay`, `SecurityContextPacket`, `HuntTask`,
   `PlaidNoxDeepHuntAgent`, and `VerifiedFinding`.
5. **Stable code identity.** A symbol identity cannot include its content hash.
   Identity is stable across edits; the content hash is a separate version
   property used for invalidation and caching.
6. **Readable code intelligence.** Graphify is the target provider for
   versioned structural code navigation. Models receive a bounded neighborhood
   and exact source windows. PlaidNox retains investigation-scoped security
   annotations and finding dependencies with source provenance.
7. **No deterministic vulnerability verdicts.** Parsers, metadata scanners,
   SAIST imports, ripgrep discovery, and Tree-sitter Security IR produce
   candidates and context. Every
   reportable source-code vulnerability must survive independent AI-based
   attacker-path review, falsification, and evidence validation.
8. **Open-ended vulnerability discovery.** No allowlist limits the hunt to a few
   CWE categories. The LLM creates tasks from architecture, business workflows,
   trust boundaries, data, code, previous evidence, and sourced knowledge.
9. **Memory is evidence, not authority.** Threat statements, security memories,
   earlier verdicts, and web research are scoped, versioned, sourced, auditable,
   and reversible. None can silently confirm or close a finding.
10. **Knowledge retrieval is deterministic.** For every hunt question the coordinator tries
    exact stored reuse, then broader database retrieval, then current web research.
11. **Scan reasoning uses LiteLLM; web research uses Perplexity directly.** Stable Markdown
    templates rendered with Jinja instructions and schemas form the cacheable
    prefix for FAST/STANDARD/DEEP scan calls. Dynamic task and source context
    comes last. LiteLLM owns prompt caching and cache telemetry for scan
    reasoning. Current web research uses the native Perplexity Sonar API with a
    separately scoped credential, and only cited, schema-validated knowledge is
    persisted. Security verdicts are never reused merely because a prompt was cached.
12. **Safe static operation.** Code Scanning does not install dependencies,
    execute repository scripts, run builds, or import target code. Any later
    execution-based validation must use an isolated product/runtime boundary.
13. **ORM-owned runtime queries.** Product code uses typed ORM repositories and
    transactions. It does not concatenate SQL or embed ad-hoc schema/query text.
    Database migrations remain separate deployable files.
14. **Every stage is observable.** Stage failures have typed errors, scan and
    task identifiers, bounded retries, and redacted telemetry. Broad exception
    handling cannot silently downgrade a required review.
15. **Graphify is navigation, not a verdict.** Integrate its structural
    extractor through a source-policy-bound adapter. Do not call Graphify's
    direct-provider semantic extraction on customer code. Keep the existing
    Tree-sitter/AI-planned `rg` path as a tested fallback during migration;
    no graph edge alone confirms or dismisses a vulnerability.

## Code Scanning architecture

Graphify-backed, model-centric investigations are the accepted next runtime.
The adapter, data, coverage, migration, and acceptance contracts are below in
[Graphify-backed investigations](#graphify-backed-investigations-for-code-scanning).

```text
immutable source snapshot + business/security context
  -> source-policy-bound Graphify structural graph and incremental update
  -> security surface inventory + AI Investigation planner
  -> graph-first Context Broker and bounded exact source windows
  -> LLM Hunt; typed graph/source request only for new evidence
  -> grounded candidate clustering by root, effect, and capability
  -> independent PlaidNox Deep Hunt and adversarial falsification
  -> recursive variants, verified findings, coverage, and reports
```

Graphify provides structural navigation and provenance, not security verdicts.
PlaidNox creates security annotations only where an investigation needs them.
The current Tree-sitter/`rg` workset and region pipeline remains operational
until Graphify-backed investigations meet recall, grounding, scale, and resume
gates. `rg` stays a bounded AI-directed fallback. Do not build a second general
code graph or expand the region-wide obligation matrix as the target design.
SCIP, Joern, CodeQL, and OpenGrep are deferred evidence adapters rather than
required infrastructure. Secrets, dependency CVEs, and other product scans
remain separate workstreams.

### Scale and coverage semantics

Index coverage, investigation coverage, and execution health are separate dimensions.
`SUCCESSFUL` / `UNSUCCESSFUL` describe whether required scanner stages executed
correctly. Coverage reports admitted files, observed surfaces, planned and terminal
investigations, unsupported languages, and unresolved graph/context edges.
A known parser or graph limitation is a coverage gap; a crashed required stage
is an execution failure. A low finding count never implies successful coverage.

## Durable Context Fabric

The system persists expensive understanding rather than duplicating raw Git
storage:

1. **Code references** — snapshot identity, Graphify version and stable
   PlaidNox node IDs, source hashes, locations, and exact evidence dependencies.
2. **On-demand security annotations** — attacker control, exposure, guards,
   trust boundaries, effects, and assumptions for investigated paths, each
   scoped, source-grounded, and invalidatable.
3. **Threat context** — versioned assets, actors, trust boundaries, data classes,
   security invariants, integrations, and business abuse paths with provenance.
4. **Security memory** — explicit or confirmed reusable context scoped to a
   tenant, application, codebase, framework, or vulnerability class.
5. **Finding memory** — stable fingerprints, exact symbol/path dependencies,
   assumptions, evidence, falsification, lifecycle, and fix verification.
6. **Security knowledge** — source-backed framework behavior, advisories,
   weakness research, and business-abuse techniques with retrieval history.

A new source snapshot creates a generic `ContextOverlay`, independent of an SCM.
Changed source and graph edges invalidate dependent investigations, annotations,
and findings. Unaffected context is reused only when its evidence versions still
match. An accepted overlay is reconciled into a new immutable base.

## PostgreSQL and ORM boundary

The production persistence design is specified in
`docs/POSTGRESQL_ORM_PLAN.md`. Code Scanning owns only tables prefixed
with `code_scanning_`. Future SCM, SCA, secrets, DAST, cloud/IaC, license, and IDE
products must use their own schemas/tables and cannot add provider fields to the
Code Scanning core.

The production data model covers:

- codebases and immutable snapshots;
- source files, stable symbols, relationship edges, and threat statements;
- context memories and sourced security knowledge;
- scan runs, hunt plans, hunt tasks, model invocations, and cache metrics;
- findings, evidence, and exact context dependencies.

Large raw artifacts and full source archives belong in encrypted object storage;
PostgreSQL keeps identities, hashes, structured context, evidence, provenance,
and artifact references.

## Ordered delivery phases

### Phase 1 — secure local vertical slice

Status: foundation implemented; production hardening remains.

- Safe local source snapshot intake.
- Readable tree and compact Tree-sitter Security IR.
- External prompts, schemas, routing, runtime settings, and migrations.
- AI-generated hunt plan and broad open-taxonomy discovery.
- Knowledge routing, sourced Perplexity research, and durable RAG.
- Mandatory PlaidNox Deep Hunt and recursive variant sweeps.
- JSON, SARIF, Markdown, and repository-context outputs.

Exit: a local snapshot can be scanned without executing target code; every
reported finding has redacted code evidence and a completed Deep Hunt verdict.

### Phase 2 — Code Intelligence correctness

Status: generic incremental core implemented; precision adapters deferred.

- Stable semantic symbol identities are independent of content and line numbers;
  body changes update content hashes and invalidation state.
- Source/configuration recognition is externalized across supported languages
  and common manifests. Explicit excludes and exact maximum file sizes apply at
  inventory, IR, ripgrep, source-read, context-expansion, and model-input
  boundaries.
- Model-planned `rg` is the primary discovery path. Tree-sitter supplies the
  cached syntax Security IR. Repository-specific security roles remain AI
  derived rather than encoded as vulnerability/framework searches.
- Content-addressed bases and dependency-aware overlays propagate changed
  callees to callers and linked findings without adding SCM behavior.
- Discovery and variant calls use focused Security IR slices and compact
  repository context. Content-free model-call audits prove that they do not
  resend the broad source inventory, source tree, or repository-wide IR.
- AI reviews can request bounded call-flow expansion only when needed.
- **Contract foundation implemented:** `worksets.py` defines versioned
  `SecurityWorkset`, `SecuritySlice`, and per-symbol `SecuritySummary` models;
  `security_worksets_from_regions` adapts existing region evidence into
  surface-owned slices. External JSON schemas and `runtime/security_worksets.json`
  define the data contract and batch budgets. Optimized discovery now reviews
  lossless bounded batches produced by this region adapter. Matching route and
  registration worksets can now add Tree-sitter evidence from related files;
  the task plan still owns coverage obligations.
- **Tree-sitter workset planning partially connected to discovery:**
  `security_worksets_from_graph` emits stable route-registration worksets and
  includes uniquely resolved referenced definitions as bounded evidence slices.
  It checks source versions and records syntactic call/reference observations;
  it does not infer callback roles, middleware attachment, reachability, or
  taint. It deliberately does not make every function a review workset.
  `security_summaries_from_graph` builds content-hashed per-symbol summaries,
  resolves only unique syntactic call targets, and records unresolved calls
  rather than treating them as safe. Focused tests cover planning and stale
  source rejection. Summaries are now persisted per immutable Context Fabric
  snapshot in SQLite and the ORM-backed PostgreSQL store; repeated writes are
  idempotent and conflicting data for the same snapshot is rejected. Existing
  snapshot call edges continue to drive reverse-dependency invalidation. Summary
  and dependency IDs now use the same stable symbol identity as persisted edges,
  so reverse-dependency fanout can join them without path/name translation.
- Keep `DiscoveryRegion` only as a source-window transport type in the target
  architecture; do not let region count define coverage identity.
- **Partially implemented:** route worksets with uniquely referenced definitions
  plus structural per-symbol summaries are derived from current Tree-sitter
  facts. Generic top-level calls that reference uniquely indexed symbols also
  produce `symbol_registration` worksets; their role and execution remain
  explicitly unresolved. This can surface worker, event, and callback
  registrations without embedding framework names or claiming they execute.
  Route and registration slices now carry callable-signature observations,
  while symbol summaries retain call-site text, uniquely resolved target IDs,
  and explicit limitations. Input trust, call semantics, and side effects remain
  unresolved; these are retrieval facts for later AI reasoning, not security
  conclusions. Next extend indexed surfaces to explicit state/network/filesystem/
  rendering effects using parser facts or AI-derived annotations with
  provenance. Keep obligations scoped to canonical surfaces; do not repeat
  repository-wide questions per region.
  Repository-context reconnaissance now receives a compact, area-balanced
  inventory with exact primary source windows, related symbol IDs, unresolved
  edges, and explicit omission counts. Incremental context includes only
  surfaces intersecting changed/affected paths. Live discovery batches
  region-derived worksets and adds graph-derived cross-file evidence for
  unambiguous route/registration matches. Persisted summary reuse has not yet
  been connected to that live planner. Deep Hunt
  receives canonical candidates after discovery and retains its verification
  gates.
- **AI-derived annotation location grounding implemented:** repository-context
  records for input surfaces, trust boundaries, entry points, sensitive effects,
  authentication paths, and authorization decisions may carry exact source
  locations. The runtime checks repository containment, indexed file identity,
  source content hash, line bounds, and any supplied quote, then records per-
  location provenance and aggregate grounding metrics. On incremental updates,
  prior locations are carried forward only for the same record identity and
  only while their indexed source version still matches. Grounding verifies
  location provenance only; semantic claims remain unvalidated context and
  never act as vulnerability verdicts or effective-control proof. Covered by
  `tests/test_ai.py` annotation-grounding tests.
- **Live workset-batched discovery implemented (first orchestration stage):**
  optimized discovery adapts planned source regions into canonical structural
  worksets; configured lossless batches become review units. Each request sends
  bounded excerpts once and candidate grounding accepts only exact source
  windows present in that batch or newly resolved Context Broker evidence.
  An unambiguous route or top-level registration match adds Tree-sitter slices
  from referenced definitions across files while preserving the full discovered
  region. Excluded or sensitive sources and multi-batch graph worksets use the
  region adapter with explicit deferral telemetry. Indexed relationships remain
  syntax observations with unresolved edges, never security verdicts.
  Checkpoints are scoped to workset evidence hash and batch index, and telemetry
  separates source regions, unique worksets, and review batches. Coverage now
  reconciles every planned multi-batch obligation before global sibling
  reconciliation: a clean batch cannot hide an unresolved or missing batch,
  and missing planned batch indices remain required coverage gaps. The existing
  task plan still owns hunt-specific coverage. Every selected workset batch now
  also has a required open-ended surface-review obligation owned by its stable
  workset identity; multi-batch reconciliation requires all assigned batch
  answers. Tree-sitter indexed HTTP routes in the admitted analysis scope now
  seed exact bounded review regions even without an `rg` hit; already covered
  route ranges are reused, and uncovered ranges are added without making
  syntax-based verdicts. Generic top-level symbol registrations with indexed
  references now also seed review regions without an `rg` hit. Their runtime
  role remains unresolved until AI review, and the same workset inventory is
  reused for context enrichment. Coverage of other surface classes and richer
  workset-owned obligations remain follow-on work. Covered by
  `tests/test_coverage.py`, `tests/test_optimized_discovery.py`,
  `tests/test_worksets.py`, and the adapter tests in `tests/test_ai.py`.
- **Contract batching implemented:** slice batches obey external count/serialized
  character budgets, preserve every slice, report remaining-slice counts, and
  fail explicitly when an individual slice cannot fit. Unresolved graph edges
  stay visible and make the slice/workset incomplete; required evidence is never
  silently truncated.

Exit met: mutation tests prove that changed callees revalidate callers and
linked findings, unrelated changes omit those findings and code slices, and
per-segment model calls avoid repository-wide context.

Deferred Phase 2b: compiler/LSP semantic adapters and true language-specific
taint/dataflow are optional precision layers. The current call-flow expansion is
structural navigation, not taint proof; unresolved required flows remain explicit
evidence gaps or incomplete coverage.

### Graphify-backed investigations for Code Scanning

#### Decision and boundary

Graphify becomes the repository-navigation provider for PlaidNox Code Scanning. PlaidNox remains the security reasoner and verifier. This is a migration target, not a claim that the current scanner already uses Graphify. The existing Tree-sitter, `rg`, region/obligation, Context Fabric, checkpoint, and Deep Hunt implementation stays operational until the replacement passes the same security and resume tests. SCM, SCA, secrets, DAST, and frontend work remain separate.

```text
immutable source snapshot
  -> admitted-file inventory and Graphify structural extraction/update
  -> versioned graph with source-grounded, provenance-labelled nodes/edges
  -> security-surface inventory and AI investigation planner
  -> persistent investigation queue
  -> graph-first Context Broker + bounded exact source windows
  -> LLM Hunt with typed context requests and delta-only continuation
  -> grounded candidate clustering by root, effect, capability, and evidence
  -> independent PlaidNox Deep Hunt, falsification, and variant search
  -> verified findings, coverage, execution health, and reports
```

Graphify answers what code exists and which relationships its extractor observed. Its `EXTRACTED`, `INFERRED`, and `AMBIGUOUS` labels remain visible. An extracted call edge is structural evidence, not proof of runtime reachability or a security property. Ambiguous or missing edges become explicit context gaps. PlaidNox's model assigns attacker influence, controls, invariants, sensitive effects, and capabilities for the investigated path. PlaidNox grounds each cited line and claimed relationship against the immutable snapshot before reporting a finding.

#### Graphify adapter contract

The adapter accepts only files admitted by PlaidNox's existing source policy: repository containment, symlink handling, exclusions, size limits, language inventory, and sensitive-file exclusions. It invokes Graphify's structural extractor without its direct-provider semantic extraction. Its cache lives outside the immutable source snapshot, and source hashes are checked before and after extraction. All generative calls in the scan remain behind PlaidNox's configured model boundary. The adapter is pinned to a tested Graphify version and emits a typed error on extraction failure; it cannot silently return an empty graph as a clean scan.

It exposes `snapshot_id`, `extractor_version`, `file_hashes`, stable PlaidNox node IDs, exact source locations, edge kind/provenance, unresolved relationships, neighborhood/path queries, and changed/removed node and edge sets. Raw Graphify IDs are not durable identity: a local fixture showed symbol IDs include the extraction directory name. PlaidNox normalizes identity from repository-relative source identity and symbol semantics, keeps content hashes separate, and records ambiguity when a symbol cannot be matched across revisions. Evidence windows are rechecked against source hashes before model input or finding persistence.

Incremental updates must produce invalidation fanout for changed callers, route attachments, controls, investigations, and finding dependencies. Unaffected investigations can reuse context only when every dependent source/edge version matches. PR/MR overlays remain owned by the separate SCM integration; the Code Scanning engine accepts a generic immutable snapshot and optional parent snapshot.

#### Investigation contract

`Investigation` replaces `DiscoveryRegion` as the planned security-review identity. A record contains a stable investigation ID, codebase/snapshot, target reference, reason, security questions, graph node and edge references with provenance, exact source windows, prior evidence, threat/business context references, unresolved relationships, evidence hash, status, and checkpoint reference. A source region becomes a transport for exact code, never the unit of scan completeness.

A security-surface inventory covers observed external entry points, registered callbacks/jobs, identity boundaries, state changes, and external effects without declaring them safe or vulnerable. Source locations must match the immutable graph snapshot before they can seed planning. Connected, source-grounded surfaces can be batched for AI planning using architecture and business context, with no fixed CWE or framework allowlist. Every admitted surface is assigned an investigation or an explicit unsupported/omitted reason. A clean answer for one investigation cannot close another or an existing finding.

The initial hunt receives a bounded graph neighborhood and the smallest complete source windows. A continuation requires a typed context request and new, material evidence from the broker; unchanged context never earns another model call. `rg` is a bounded, AI-directed fallback for graph gaps. The broker returns source snippets and relationship provenance together, so the model does not need an extra request merely to read a match. Checkpoints persist each completed investigation, context expansion, candidate review, and sweep, keyed by source/graph evidence and prompt contract versions.

#### Verdicts and coverage

The model can return `NO_CANDIDATE`, `CANDIDATE`, or `NEEDS_CONTEXT` for one investigation. The coordinator records `UNRESOLVED` when required evidence cannot be obtained and `FAILED` when an execution unit fails. `NO_CANDIDATE` is a bounded review result, not proof that surrounding code is safe. Candidate clustering preserves distinct attack branches and capabilities. Every reportable candidate still receives independent attacker-path verification, adversarial falsification, exact grounding, and recursive variant search.

Report execution status separately from coverage: `SUCCESSFUL` or `UNSUCCESSFUL` describes required stage execution; coverage reports admitted files, observed surfaces, planned/terminal investigations, unsupported areas, and unresolved graph/context relationships. A parser limitation is a coverage gap; a crashed required stage is an execution failure. Verified findings survive either status. Merge policy remains a separate SCM concern.

#### Immediate migration sequence

1. **Adapter foundation implemented:** `graphify_adapter.py` calls Graphify's structural extractor on policy-admitted files, normalizes raw IDs, validates source paths/lines, preserves edge provenance, reports unindexed files, and compares immutable snapshots for added/changed/deleted files, nodes, and edges. `graphifyy==0.8.14` is a pinned optional dependency. Focused tests and a real local extractor smoke test pass. Duplicate-symbol identity, cross-file edge precision, cache reuse, and reverse-fanout tests remain before runtime adoption.
2. **First graph-first Context Broker slice implemented:** `graph_context.py` resolves exact definitions, callers, callees, references, and one-hop neighborhoods with provenance and truncation telemetry. Source windows are bounded, redacted, and hash-checked. Add route attachments, readers/writers where Graphify actually represents them, path lookup, and AI-directed `rg` fallback without treating an empty graph lookup as proof of safety.
3. **Typed investigation contract and persistence slice implemented:** `investigations.py` validates versioned records against a JSON Schema, keeps stable investigation identity separate from evidence hashes, checks repository-relative source windows, and rejects payloads containing unredacted secrets. Tenant-scoped ORM storage, idempotent save, revision-checked lifecycle transitions, checkpoint references, and PostgreSQL migration `0006_investigations.sql` are in place. Focused tests cover evidence changes, tenant isolation, resume transitions, and unsafe inputs. Surface planning and its mapping/gap ledger persist through migration `0008_graph_surface_planning.sql`; group progress is persisted independently from immutable coverage identity.
4. **Source-grounded surface mapping and connected grouping implemented:** `graph_targets.py` maps configured repository-context collections onto Graphify nodes only when source location and file hash match the immutable snapshot. Ambiguous, stale, unverified, unmapped, and location-free records remain explicit coverage gaps. `group_connected_graph_targets` groups mapped surface records by shared/directly connected nodes without treating edges as security verdicts. Focused tests cover mapping, gaps, stable keys, graph grouping, and snapshot mismatch. The mapper/grouper run only with the explicit Graphify shadow-planning option.
5. **Graphify AI investigation planning implemented (opt-in):** `GraphInvestigationPlanner` builds a size-bounded neighborhood around one target or a connected target group, provides redacted exact source windows and typed graph provenance, asks the configured LiteLLM agent for open-ended security questions, and rejects invented node/edge references. Group size and model input are externally bounded; mapped surface metadata is checked against target nodes and snapshot hashes before model input; the legacy single-target API and telemetry field remain compatible. Focused tests cover one-call group planning, disconnected/oversized groups, stale source rejection, grounding, and LiteLLM routing. Shadow planning is available in `scan-local`; investigation execution through Deep Hunt remains.
6. **Surface planning and ORM resume coordinator implemented (opt-in):** `GraphSurfacePlanningCoordinator` maps repository-context surfaces, groups connected source-grounded targets, and makes one grouped planner call per group. Unmapped/stale records stay in the result and over-bound groups become explicit planning gaps without being sent to a model. `InvestigationOrmStore` commits each completed Investigation in its own tenant-scoped ORM unit of work; on retry it reuses the stored plan for the same scan, graph snapshot, and group key without another planner call. The mapping/grouping ledger and explicit gaps are persisted before planner calls and finalized only after all groups finish; an interrupted run leaves a resumable `planning` record. PostgreSQL migration `0008_graph_surface_planning.sql` and ORM tests cover persistence, gaps, interruption/restart, and completion.
7. **Opt-in scan shadow bridge implemented:** `scan-local --graphify-shadow-planning` extracts the policy-admitted snapshot, builds the Graphify Context Broker, maps/groups surfaces, and asks the configured LiteLLM planner for bounded investigation plans. Graphify results and mapping/planning gaps are reported separately; the legacy discovery and Deep Hunt path remains authoritative. Investigation records bind to the durable Code Scanning snapshot FK while preserving Graphify's extractor/content identity separately as `graph_snapshot_id`. Planner responses are checkpointed by graph snapshot, stable group, planning context, and the enclosing prompt/source scope. Coverage output reports bounded per-surface/per-group dispositions and omissions, while ORM records persist pending/planning/planned/reused/failed/gap states. Focused tests cover restart reuse, planning interruption, progress persistence, snapshot identity, and default-off behavior.
8. **Investigation execution implemented (opt-in):** each persisted Graphify Investigation now runs through the external attacker-first discovery contract, exact source-window grounding, bounded graph-context continuation, candidate clustering, and the shared independent Deep Hunt verifier. A validated investigation result is checkpointed only after the whole unit succeeds; PostgreSQL lifecycle state is transitioned per scan, and failures remain visible as unresolved/failed coverage. Tests cover stale/tampered evidence, out-of-window candidates, delta-only context, checkpoint replay, and the pipeline/ORM path through shared Deep Hunt (`tests/test_graph_investigation_hunt.py`, `tests/test_checkpoint.py`, and `test_pipeline_executes_graphify_investigations_through_shared_deep_hunt_and_persists_state`).
9. **Fake-gateway scale fixtures implemented:** the synthetic 100k-LOC fixture covers 800 source-grounded entry points over 800 graph nodes and 700 edges. Connected grouping produces 100 bounded investigations with 100 fake planner calls, no mapping/planning gaps, per-call input below the configured limit, and total planner input smaller than the repository source. The fixture uses a fake model gateway and does not run a real scan. Before switching defaults, continue validating seeded-root recall, no lost findings, groundable evidence, zero silent omissions, restart behavior, prompt cost, and graph update correctness with explicitly requested real scans. Remove duplicate Tree-sitter workset/index layers only after parity.
10. **Cross-snapshot planning reuse and graph invalidation implemented (opt-in):** prior investigations are looked up within the tenant and codebase, newest-first, by stable surface-group identity. A prior plan is reusable only when its target node set, referenced node source hashes, complete observed one-hop relationships, exact source-window file hashes, and configured planning-context fingerprint all match the new snapshot. Legacy records without the new relationship/context fingerprints are replanned. Reuse rebases snapshot provenance and creates a fresh `planned` investigation identity with no old checkpoint reference; hunt execution and independent verification always run again. Same-scan resume applies the same evidence/context compatibility checks. `affected_investigation_ids()` now accepts a Graphify snapshot to compute bounded incoming-edge dependency fanout using configured depth/node limits; an exhausted bound conservatively invalidates every investigation rather than claiming unaffected status. PostgreSQL repository lookup is tenant/codebase scoped. Focused tests cover compatible reuse across a changed unrelated file, changed business context forcing a new planning call, reverse-edge fanout and fail-closed bounds. Full tests and Ruff pass. No real scan was run; Graphify remains opt-in.
11. **Prior Graphify snapshot persistence and delta-aware planning implemented (opt-in):** persist Graphify metadata, source hashes, nodes, and edges in normalized Code Scanning ORM tables, keyed by scan and tenant/codebase, with PostgreSQL migration `0010_graphify_snapshots.sql`. Each scan loads the latest prior graph, computes added/changed/removed files, nodes, and edges, calculates bounded reverse-dependency invalidation, then stores the current immutable graph. Invalidated prior investigations cannot reuse their model-authored plan; unaffected compatible plans still may. Reports expose prior graph identity and delta/invalidation counts. Restart persistence, tenant isolation, immutable retry, and end-to-end pipeline delta tests pass. No repository source is stored in the graph tables, only structural labels, source locations, and hashes.
12. **Unaffected terminal negative investigations reused (opt-in):** when a prior scan completed successfully under the same prompt manifest, and the current Graphify/source/context compatibility checks accept the investigation, a terminal `no_candidate` result is carried forward without another hunt call. Invalidated investigations are never eligible. Identical-source retries reuse the immutable investigation record without attempting an invalid lifecycle transition. Runtime behavior is controlled by `reuse_compatible_no_candidate_investigations`; pipeline/ORM tests prove unchanged work skips the hunt and changed source reruns it. Verified findings are deliberately not carried forward yet.
13. **Next:** carry forward verified findings only after dependency, evidence-location, graph relationship, report schema, workflow, and source-hash compatibility are proven; create a new per-scan report snapshot while retaining canonical finding history. Keep Graphify opt-in until seeded-root recall, stale-finding invalidation, and checkpoint-resume parity are tested; do not run an acceptance scan without an explicit user request.

SCIP, Joern/CPG, CodeQL, OpenGrep, and whole-program dataflow are deferred optional evidence providers. Add one only when measured recall or precision shows a gap. Secrets and dependency CVEs remain separate product workstreams.

Primary research references:
- [Wiz Atlas architecture](https://www.wiz.io/blog/atlas-ai-vulnerability-researcher)
  (vendor-described CPG attack-surface mapping, scoped stages, adversarial review).
- [LLMxCPG paper](https://www.usenix.org/conference/usenixsecurity25/presentation/lekssays)
  and [implementation](https://github.com/qcri/llmxcpg) (CPG query/slice then LLM).
- [IRIS at ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/hash/582d4e27fa24168f3af1f4582655034b-Abstract-Conference.html)
  (LLM-inferred taint specifications plus static and contextual analysis).
- [Infer compositional analysis](https://engineering.fb.com/2017/09/06/android/finding-inter-procedural-bugs-at-scale-with-infer-static-analyzer/)
  and [Glean](https://engineering.fb.com/2024/12/19/developer-tools/glean-open-source-code-indexing/)
  (procedure summaries, persistent facts, incremental indexing).
- [Joern CPG](https://docs.joern.io/code-property-graph/) and
  [SCIP indexers](https://sourcegraph.com/docs/code-navigation/writing-an-indexer)
  (candidate structural/symbol adapters to evaluate, not yet selected dependencies).

### Phase 3 — PostgreSQL ORM persistence

Status: implemented and verified against the checked-in PostgreSQL migration.

- Establish SQLAlchemy models, scoped sessions, typed repositories, and unit of
  work boundaries for Code Scanning.
- Apply independently reviewable PostgreSQL migrations.
- Run Context Fabric, knowledge, hunt plans/tasks, findings, evidence, and
  exact symbol dependencies through PostgreSQL repositories in production.
- Persist each invocation's scan parameters and final result summary, plus a
  versioned per-scan finding snapshot containing classification references,
  redacted affected code, Deep Hunt gates, and taint-path code/evidence. A
  rescan of the same revision receives a distinct scan ID and preserves its
  own result history.
- Add tenant isolation keys, optimistic concurrency, timestamps, retention
  state, indexes, transaction tests, and backup/restore verification.
- Keep SQLite only for isolated unit tests or an explicitly labelled local mode.

Exit: two scanner workers can safely process independent tasks against the same
PostgreSQL database, retry without duplicates, and recover after interruption.

### Phase 4 — complete AI hunt and evidence lifecycle

- Move to investigation-owned coverage with one bounded initial hunt, typed
  graph/source requests, and continuation only after new material evidence.
  Retain the region pipeline until equivalent coverage and recall are proven.
- Merge equivalent root-cause evidence before Deep Hunt and compile a canonical
  evidence packet containing attacker origins, boundary, invariant, downstream
  trust branches, effects, gained capabilities, trace, and gaps.
- Account for every admitted security surface with a planned investigation or
  an explicit unsupported/omitted reason. Track unresolved evidence separately
  from failed execution.
- Route FAST/STANDARD/DEEP to actual LiteLLM model policies rather than metadata.
- Expand secret redaction before every provider boundary.
- Persist exact finding dependencies on symbols, paths, controls, memories,
  threat statements, knowledge entries, prompts, and model executions.
- Add reviewer-independent evidence quality checks, safe PoC narratives,
  remediation suggestions, and fix-rescan verification.
- Keep every candidate AI-tested; no category or confidence shortcut bypasses
  Deep Hunt.

Exit: each finding can be reconstructed from immutable evidence and all context
that influenced it; every rejected candidate has a falsification record.

### Phase 5 — end-to-end product validation

Status: implementation foundation complete; live acceptance evidence pending.

- Run repeatable acceptance scans against `C0oki3s/NSTCTF` and additional
  multi-language fixtures with seeded and non-seeded weaknesses.
- Measure discovery coverage, validated recall, false-positive rate, duplicate
  rate, context reuse, cache reuse, tokens, latency, and cost by stage.
- Test prompt-injection resistance, secret redaction, malformed model output,
  provider outages, stale research, interrupted scans, and database recovery.
- Package a worker image and migrations; document configuration and operations.

Implemented in this phase:

- schema-validated acceptance manifests and repeatable report scoring for
  recall, precision, duplicates, incomplete scans, cache tokens, model tokens,
  and reported cost;
- ordered, checksum-verified PostgreSQL migrations and a one-shot migration
  command;
- a non-root worker image, immutable snapshot queue/worker commands, and
  acceptance/operations runbooks;
- failure-injection unit coverage for budgets, malformed configuration,
  provider-boundary accounting, lease recovery, retries, and scan
  finalization.
- a snapshot-scoped local checkpoint journal that writes redacted LLM context,
  response schema, routing/execution metadata, and each successful structured
  response at the model-call boundary. Completed calls replay without provider
  cost; an interrupted or failed call remains pending and is retried after a
  restart. Discovery segments, candidate verdicts, and recursive sweeps retain
  their higher-level checkpoints as well.

Still required for the release exit: run the pinned NSTCTF and reviewed
multi-language acceptance set repeatedly through LiteLLM, record reviewer
validated expectations, and execute the clean-environment deployment and
database recovery drill. These scans are deliberately not started by tests or
deployment commands.

Exit: a clean environment can migrate PostgreSQL, start a worker, scan an
immutable snapshot, resume an interrupted scan, and produce reviewable findings
and reports with no SCM dependency.

### Phase 6 — production controls

Status: controls implemented; staging demonstration pending.

- Sandboxed read-only workers with blocked default egress and explicit research
  gateway access.
- Queue leases, task timeouts, quotas, tenant isolation, encryption, retention,
  deletion, audit logs, and disaster recovery.
- OpenTelemetry traces and metrics with redacted logs and per-model cost limits.
- Signed and versioned policy/config bundles independent of scanner releases.

Implemented in this phase:

- tenant-scoped, concurrency-limited queue leases with heartbeats, timeouts,
  bounded attempts, daily job quotas, monthly cost quotas, and idempotent
  enqueue requests;
- production PostgreSQL TLS enforcement, mounted-secret support, redacted and
  content-hashed audit events, encrypted-artifact metadata, expiry/deletion
  records, and scan completion state;
- per-scan and per-model LiteLLM usage budgets plus privacy-safe OpenTelemetry
  instrumentation;
- signed, expiring asset manifests verified before enqueue, worker startup, or
  direct scanning;
- a read-only, non-root, capability-free worker deployment example with an
  internal network and read-only snapshot mount.

The staging exit remains open until infrastructure demonstrates network egress
policy, encrypted storage deletion, backup/restore, lease recovery under
process termination, telemetry export, sustained performance, and hard
LiteLLM gateway cost ceilings.

Exit: isolation, replay safety, recovery, audit provenance, performance, and
cost ceilings are demonstrated in staging.

## Deferred work

SCM Integration has been explicitly started as the independent
`plaidnox_scm` package while Code Scanning continues through its remaining
phases. The package boundary remains strict: SCM consumes immutable Code
Scanning APIs and does not add provider or PR/MR behavior to the scanner.
`PlaidNox/plaidnox-github-bot` owns GitHub webhook verification, installation
authentication, check runs, inline comments, and stale-HEAD publication. The
`plaidnox_scm` package owns only the provider-neutral authenticated review API,
immutable source-broker boundary, PR/MR review orchestration, baseline
classification, and merge policy. Do not recreate GitHub webhook or Checks API
code in this repository.
SCA, secrets, cloud/IaC, license risk, outdated software, DAST, and IDE plugins
remain separately planned products and do not block either workstream.
