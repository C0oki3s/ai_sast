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
6. **Readable code intelligence.** Persist a deterministic source tree, symbols,
   definitions, references, calls, entry points, controls, sources, and sinks.
   Agents receive an AI-selected Security IR slice and readable tree before source.
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
15. **No Graphify dependency.** Code discovery and navigation use AI-planned
    ripgrep, the readable source tree, Tree-sitter Security IR, and persisted
    Context Fabric relationships. This rule applies to every PlaidNox project.

## Code Scanning architecture

```text
immutable source snapshot + codebase/revision + business/security context
  -> safe source inventory and readable tree
  -> Tree-sitter extracts a compact symbol and security relationship index
  -> LLM creates repository-specific reconnaissance searches from observed structure
  -> bounded search execution returns evidence without built-in security patterns
  -> create or incrementally update Context Fabric
  -> LLM reconnaissance and architecture model
  -> LLM hunt-task plan with complete source/path ownership
  -> knowledge action per task (stored -> broadened -> web)
       -> reuse exact knowledge | retrieve broader knowledge | research current web
  -> Context Compiler selects minimum complete evidence slice
  -> structural DiscoveryRegions with explicit security obligations
  -> one initial AI discovery review per region
  -> per-obligation disposition
       -> terminal | typed Context Broker request
  -> delta-only continuation only when new evidence was acquired
  -> canonical candidate/evidence merge by root + control + invariant + capability
  -> CandidateEvidencePacket
  -> PlaidNox Deep Hunt for every candidate
       -> attacker-controlled source and reachable entry point
       -> source-to-sink/control path
       -> missing or bypassable control
       -> adversarial falsification
       -> safe reproduction reasoning
       -> impact and remediation evidence
  -> recursive root-cause/variant sweep to a fixed point
  -> model-driven consolidation without losing fingerprints
  -> verified findings + finding dependencies
  -> policy decision and JSON/SARIF/Markdown report
```

DataDog SAIST can supply broad AI-native candidates through an adapter. It does
not own the PlaidNox verdict and it does not replace the custom Deep Hunt agent.
Tree-sitter Security IR and targeted semantic/dataflow adapters provide code
relationships and context; they do not decide that a vulnerability exists.

## Durable Context Fabric

The system persists expensive understanding rather than duplicating raw Git
storage:

1. **Code intelligence** — snapshots, file/blob hashes, stable symbols, content
   hashes, definitions/references, calls, routes, data stores, and boundaries.
2. **Security relationships** — attacker control, exposure, authentication,
   authorization, tenancy, validators, sanitizers, dangerous operations,
   sensitive data, and dependency reachability.
3. **Threat context** — versioned assets, actors, trust boundaries, data classes,
   security invariants, integrations, and business abuse paths with provenance.
4. **Security memory** — explicit or confirmed reusable context scoped to a
   tenant, application, codebase, framework, or vulnerability class.
5. **Finding memory** — stable fingerprints, exact symbol/path dependencies,
   assumptions, evidence, falsification, lifecycle, and fix verification.
6. **Security knowledge** — source-backed framework behavior, advisories,
   weakness research, and business-abuse techniques with retrieval history.

A new source snapshot creates a generic `ContextOverlay`, independent of an SCM.
Changed symbol content and relationship edges invalidate affected paths, controls,
tasks, and findings. Unaffected context is reused. Once accepted as the current
codebase state, the overlay is reconciled into a new immutable base.

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

Exit met: mutation tests prove that changed callees revalidate callers and
linked findings, unrelated changes omit those findings and code slices, and
per-segment model calls avoid repository-wide context.

Deferred Phase 2b: compiler/LSP semantic adapters and true language-specific
taint/dataflow are optional precision layers. The current call-flow expansion is
structural navigation, not taint proof; unresolved required flows remain explicit
evidence gaps or incomplete coverage.

### Phase 3 — PostgreSQL ORM persistence

Status: implemented and verified against the checked-in PostgreSQL migration.

- Establish SQLAlchemy models, scoped sessions, typed repositories, and unit of
  work boundaries for Code Scanning.
- Apply independently reviewable PostgreSQL migrations.
- Run Context Fabric, knowledge, hunt plans/tasks, findings, evidence, and
  exact symbol dependencies through PostgreSQL repositories in production.
- Add tenant isolation keys, optimistic concurrency, timestamps, retention
  state, indexes, transaction tests, and backup/restore verification.
- Keep SQLite only for isolated unit tests or an explicitly labelled local mode.

Exit: two scanner workers can safely process independent tasks against the same
PostgreSQL database, retry without duplicates, and recover after interruption.

### Phase 4 — complete AI hunt and evidence lifecycle

- Use obligation-owned structural discovery: one initial review per region,
  typed dispositions for every obligation, Context Broker expansion as the
  only continuation trigger, and no continuation without newly acquired
  evidence. Normal regions receive at most one delta continuation; a second is
  reserved for a trust-boundary region with a remaining sensitive effect.
- Merge equivalent root-cause evidence before Deep Hunt and compile a canonical
  evidence packet containing attacker origins, boundary, invariant, downstream
  trust branches, effects, gained capabilities, trace, and gaps.
- Ensure the planner owns every eligible source segment and reachable attack
  surface; incomplete coverage makes the scan incomplete.
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
