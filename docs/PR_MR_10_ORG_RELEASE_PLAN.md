# PlaidNox PR/MR Security — 10-Organization Release-to-QC Plan

## 1. Release goal

This plan turns the existing PR/MR platform foundation into a testable first release for approximately:

- 10 tenant organizations;
- 50–200 connected repositories;
- fewer than 500 PR/MR review events per day during the initial release;
- approximately 10–20 concurrent review jobs at burst;
- GitHub as the first production SCM integration;
- GitLab as the next provider after the GitHub flow reaches QC;
- PR/MR security review as the default product path;
- full white-box deep hunt as an optional/manual or risk-triggered path.

The first release is intentionally small in infrastructure while preserving the same tenant, repository, baseline, finding, policy, and review contracts needed to scale later.

The release is ready for QC only when a customer can:

1. install the GitHub App;
2. select a repository;
3. bootstrap a reusable Repository Security Index without a full white-box hunt;
4. define a merge policy in plain English;
5. open or update a PR;
6. have PlaidNox review the changed and affected security surface;
7. detect sensitive configuration/credential exposure without sending raw secrets to models;
8. independently verify candidate vulnerabilities;
9. compare findings against the base branch;
10. deterministically evaluate the compiled policy;
11. publish a HEAD-bound `PlaidNox Security` GitHub check;
12. block, warn, or pass according to policy;
13. update the repository baseline after merge;
14. survive retries, duplicated webhooks, model errors, worker restart, and stale PR heads without publishing an incorrect PASS.

## 2. Scope for the first release

### In scope

- GitHub App installation and repository selection;
- GitHub PR and default-branch webhook intake;
- tenant/org/repository registration;
- lightweight repository bootstrap;
- reusable Security IR / Context Fabric baseline;
- local sensitive configuration and credential evidence extraction;
- PR base/head diff analysis;
- incremental Security IR update;
- changed-symbol and affected-surface expansion;
- L0 deterministic review;
- JEV routing into L1/L2 analysis;
- contextual AI candidate discovery;
- independent Deep Hunt verification;
- baseline-relative finding classification;
- natural-language policy compilation into a strict AST;
- deterministic merge-policy evaluation;
- GitHub Check publication;
- incremental baseline update after merge;
- audit, metrics, failure-state visibility, and release testing.

### Explicitly out of scope for this release

- GitLab production integration;
- Bitbucket production integration;
- multi-region control plane;
- Kafka;
- Kubernetes/EKS requirement;
- scheduled full white-box review of every repository;
- full DAST/SCA/container/cloud product integration;
- automatic external credential login/liveness testing;
- permanent raw-source archival as a platform requirement;
- advanced IDE plugin;
- large enterprise policy inheritance UI beyond the minimum tenant/repository/branch model.

## 3. Existing foundation on this feature branch

The following pieces already exist and should be preserved rather than rebuilt:

- `src/plaidnox_sast/pr_review.py`
  - PR/MR provider-independent review request/result contracts;
  - review depth contracts;
  - baseline-relative finding states;
  - HEAD-aware result concepts.
- `src/plaidnox_sast/policy_ast.py`
  - typed compiled policy representation;
  - deterministic compiled-policy evaluation foundation.
- `src/plaidnox_sast/assets/prompts/operations/policy_compile/`
  - natural-language policy compiler prompt assets.
- `src/plaidnox_sast/assets/schemas/policy_compile.json`
  - strict policy compiler response schema.
- existing Code Scanning core
  - Tree-sitter Security IR;
  - AI-planned ripgrep discovery;
  - Context Fabric;
  - PostgreSQL persistence foundation;
  - JEV routing;
  - LiteLLM model calls;
  - Deep Hunt verification;
  - findings and evidence;
  - source/model-input auditing.

These are foundations only. The end-to-end PR/MR execution path is not complete until the work below is implemented and tested.

## 4. Target first-release infrastructure

Use a deliberately simple AWS deployment for the first 10 organizations.

```text
GitHub App
    |
    v
ALB / API Gateway
    |
    v
Webhook/API ECS Service
    |
    +----------------------+
    |                      |
    v                      v
SQS: pr-review         SQS: bootstrap
    |                      |
    +----------+-----------+
               |
               v
         ECS Worker Service
               |
      +--------+--------+----------------+
      |                 |                |
      v                 v                v
PostgreSQL/RDS       Redis          S3/Object Storage
source of truth    operational      redacted IR/context
                  cache/locks       and scan artifacts
               |
               v
        LiteLLM + JEV
```

### First-release AWS components

- ECS/Fargate or ECS-on-EC2 for API and workers;
- ALB or API Gateway for public webhook/API ingress;
- SQS queues;
- RDS PostgreSQL;
- ElastiCache Redis;
- S3;
- KMS;
- Secrets Manager;
- CloudWatch initially, with OpenTelemetry-compatible instrumentation in code.

### Initial queues

Keep only three queues initially:

1. `pr-review`
   - highest priority;
   - developer-facing blocking checks.
2. `bootstrap`
   - new repository indexing and baseline rebuilds.
3. `deep-review`
   - optional manual full white-box or unusually expensive review work.

Do not introduce Kafka or a complex distributed workflow service before real load requires it.

### Initial worker capacity

Starting target, configurable rather than hardcoded:

- PR workers: 5–10 concurrent jobs;
- bootstrap workers: 2–4 concurrent jobs;
- deep/manual workers: 1–2 concurrent jobs;
- default per-tenant concurrency cap: 3 active PR reviews.

Autoscale primarily from queue depth and oldest-message age. CPU alone is not a sufficient signal because workers can wait on model/provider calls.

## 5. Required domain/data model

Every persistent PR/MR record must be tenant scoped.

Minimum identifiers:

```text
tenant_id
scm_provider
scm_installation_id
repository_id
repository_external_id
base_revision
head_revision
review_external_id
scan_id
policy_version_id
baseline_snapshot_id
```

### Required PostgreSQL entities

Implement migrations and ORM repositories for at least:

- `scm_installations`;
- `scm_repositories`;
- `repository_baselines`;
- `review_requests`;
- `review_attempts`;
- `review_events`;
- `policy_documents`;
- `policy_versions`;
- `policy_exceptions`;
- `published_checks`;
- links from reviews to existing Code Scanning snapshots/findings/evidence/dependencies.

Avoid duplicating the Code Scanning Security IR tables. The SCM workstream should reference provider-neutral Codebase/CodeSnapshot records.

### Required Redis keys

Redis is not the source of truth. Use it for:

- current PR/MR HEAD revision;
- review lock;
- superseded/cancellation marker;
- per-tenant active-job counter;
- effective-policy cache;
- short-lived installation token cache;
- short-lived baseline lookup/cache.

Every key must include `tenant_id` and repository/review identity.

## 6. Execution state machine

Implement an explicit review state machine. Do not infer state from logs.

```text
RECEIVED
  -> VERIFIED_WEBHOOK
  -> NORMALIZED
  -> COALESCED
  -> BASELINE_RESOLVED
  -> SOURCE_READY
  -> DIFF_READY
  -> IR_UPDATED
  -> L0_COMPLETE
  -> ROUTED
  -> HUNTING
  -> VERIFYING
  -> BASELINE_CLASSIFIED
  -> POLICY_EVALUATED
  -> PUBLISHING
  -> COMPLETE
```

Terminal/non-success states:

```text
SUPERSEDED
INCOMPLETE
FAILED_RETRYABLE
FAILED_FINAL
CANCELLED
```

Rules:

- only the current HEAD can publish a final PASS/WARN/BLOCK;
- `SUPERSEDED` work must stop before expensive model stages where possible;
- an incomplete required security stage must never be converted into PASS;
- retry must be idempotent;
- every state transition must be persisted with timestamp and reason.

## 7. Build workstream A — SCM integration boundary

### A1. Provider-neutral SCM interface

Create a new provider boundary outside the Code Scanning core, for example:

```text
src/plaidnox_sast/scm/
    __init__.py
    base.py
    github.py
    models.py
```

Minimum provider interface:

```text
verify_webhook(...)
normalize_event(...)
get_repository(...)
get_base_head(...)
materialize_source(...)
get_diff(...)
publish_check(...)
publish_annotations(...)
```

The scanner must not know GitHub-specific fields.

### A2. GitHub App

Implement:

- App installation flow;
- installation/repository registration;
- short-lived installation token acquisition;
- minimum required permissions;
- webhook secret verification;
- event delivery ID capture for idempotency.

Initial events:

- `installation`;
- `installation_repositories`;
- `pull_request`:
  - opened;
  - synchronize;
  - reopened;
  - ready_for_review;
  - closed/merged;
- `push` for default-branch changes;
- `merge_group` before enabling merge queue support for customers.

### A3. Webhook ingest

Webhook handler requirements:

- verify signature before parsing action;
- persist delivery/event identity;
- reject replay/duplicate processing while keeping idempotent acknowledgement;
- normalize to internal event model;
- enqueue and return quickly;
- never run AI analysis inside the webhook request lifecycle.

## 8. Build workstream B — repository bootstrap

A newly connected repository does not require a full white-box hunt.

Implement a `RepositoryBootstrapPipeline` that:

1. materializes the default branch ephemerally;
2. applies source exclusion/file-size policy;
3. inventories languages/framework/manifests;
4. builds Tree-sitter Security IR;
5. persists file hashes, stable symbols, imports, calls and relationships;
6. creates lightweight repository context;
7. extracts sensitive-evidence metadata locally;
8. saves a baseline snapshot;
9. marks coverage/truncation explicitly;
10. destroys the ephemeral checkout after completion.

### Bootstrap must not

- install repository dependencies;
- execute repository scripts;
- automatically authenticate with discovered credentials;
- run the exhaustive full white-box candidate hunt by default.

### Bootstrap exit gate

A repository is `INDEX_READY` only when:

- source inventory completed or explicit gaps are recorded;
- Security IR persisted;
- baseline revision is immutable and known;
- sensitive evidence extraction completed;
- no raw credential value was persisted;
- context/index version is recorded.

## 9. Build workstream C — Sensitive Evidence IR

Implement the white-box sensitive-configuration methodology as a local deterministic subsystem.

Suggested modules:

```text
src/plaidnox_sast/sensitive.py
src/plaidnox_sast/sensitive_ir.py
src/plaidnox_sast/assets/sensitive/
    file_policy.json
    detectors.json
    placeholder_patterns.json
```

Detect at minimum:

- `.env` and environment variants;
- properties/yaml/json application configuration;
- `.npmrc`, `.pypirc`, `.netrc`;
- Terraform variable files;
- Docker Compose configuration;
- cloud access identifiers/credential material;
- API tokens;
- connection strings containing authentication material;
- JWT/signing keys;
- private key blocks;
- service-account credential material;
- webhook signing secrets.

### Secret handling invariant

Raw values may be read locally for white-box detection, but must be converted immediately into redacted structured evidence.

Persist only:

- path/line;
- variable/key name when safe;
- secret/credential class;
- provider hint;
- redacted preview;
- HMAC fingerprint;
- placeholder/likely-real state;
- environment evidence;
- consumer references;
- capability hint;
- confidence.

Never persist or send raw values to LiteLLM, JEV, telemetry, findings, Redis, S3, or reports.

## 10. Build workstream D — incremental PR change analysis

Implement a provider-neutral incremental review pipeline.

### D1. Base/head materialization

For each review:

- resolve immutable base SHA;
- resolve immutable head SHA;
- confirm current HEAD in Redis/PostgreSQL;
- materialize only the necessary repository state;
- record checkout/source acquisition errors explicitly.

### D2. Diff model

Produce structured change records:

- added/modified/deleted/renamed files;
- changed line ranges;
- changed symbols;
- newly added/deleted symbols;
- changed imports;
- changed call edges;
- changed configuration/sensitive-evidence records.

### D3. Incremental Security IR

Reuse unchanged baseline IR by file content hash and index version.

Rebuild only changed files and recompute affected graph edges.

### D4. Affected security surface

Starting from changed symbols, expand bounded context to:

- callers;
- callees;
- definitions/references;
- routes/entrypoints;
- wrappers/middleware;
- authentication controls;
- authorization/tenant decisions;
- readers/writers;
- data stores;
- sensitive effects;
- business workflow context;
- relevant environment/configuration;
- prior findings whose dependencies intersect the change.

Every expansion must report total/returned/truncated state. Silent truncation is not allowed.

## 11. Build workstream E — review depth and JEV routing

Use four conceptual review levels but implement L0–L2 for automatic PR/MR review.

### L0 — deterministic

Always run:

- diff/IR update;
- sensitive evidence detection;
- configuration changes;
- baseline dependency invalidation;
- policy-sensitive file/surface classification;
- cheap structural checks.

### L1 — contextual AI

Use when changed code has meaningful security impact but bounded context is enough.

Run affected-surface:

- forward hunt;
- sink/backward hunt;
- boundary/state hunt.

### L2 — deep security review

Use for:

- authentication;
- authorization/tenant decisions;
- identity/token logic;
- payment/admin/high-value workflows;
- signing/crypto/security controls;
- state machines/concurrency;
- cloud authority/security configuration;
- cross-file or environment-dependent behavior;
- high-impact candidate falsification.

### JEV questions for release

Keep release routing small and typed:

- `analysis_depth`: fast / standard / deep;
- `needs_cross_file`: yes/no;
- `needs_state_reconstruction`: yes/no;
- `needs_external_knowledge`: yes/no;
- `needs_environment_context`: yes/no.

JEV is routing only. It cannot confirm a vulnerability, close a coverage gap, or make the merge decision.

## 12. Build workstream F — AI hunt + independent verification

### F1. Candidate discovery

Against only the affected surface, run independent perspectives:

1. forward: attacker influence -> sensitive effect;
2. backward: sensitive effect -> callers/origins/controls;
3. boundary: auth/authz/tenant/state/business invariant changes.

Discovery output is a hypothesis, not a confirmed finding.

### F2. Verification

Every merge-relevant candidate must pass the independent Deep Hunt gates:

- design/security invariant;
- production reachability;
- attacker control;
- effective defense review;
- concrete new attacker capability;
- adversarial falsification;
- reproduction/proof reasoning appropriate to static review;
- remediation invariant.

Unknown required evidence => unsupported or incomplete, never silently safe.

### F3. Context requests

Before QC, context requests should support at least:

- definition;
- callers;
- callees;
- references;
- readers;
- writers;
- flow;
- imports;
- route;
- source window;
- search.

Responses must include pagination/truncation metadata where relevant.

## 13. Build workstream G — baseline comparison

After findings are verified, classify each against the base revision:

- `introduced`;
- `regressed`;
- `modified_existing`;
- `existing`;
- `resolved`.

Classification must use stable finding/root-cause identity plus dependencies, not title equality alone.

Release default behavior:

- introduced/regressed findings are policy eligible;
- materially modified existing findings are policy eligible;
- unchanged existing debt is visible but does not block unrelated PRs unless policy explicitly requests it.

## 14. Build workstream H — natural-language policy

### H1. Policy compiler runtime

The prompt/schema already exists. Implement the runtime method:

```text
plain-English policy
    -> LiteLLM structured compilation
    -> strict schema validation
    -> semantic checks
    -> versioned CompiledPolicy
```

No raw code should be needed to compile policy.

### H2. Ambiguity handling

Before accepting a policy:

- reject unknown policy fields/operators;
- reject contradictory or structurally impossible conditions;
- optionally use JEV for typed ambiguity/semantic-match checks;
- surface ambiguity at configuration time, not during a developer PR.

### H3. Deterministic evaluation

At PR time:

```text
ReviewFinding[] + CompiledPolicy + branch/context
    -> deterministic PolicyResult
```

The model/JEV must not be called to determine final PASS/BLOCK.

### H4. Minimum policy features for release

Support:

- target branch/glob;
- introduced/regressed/modified/existing state;
- severity;
- minimum confidence;
- verification state;
- security boundary;
- capability;
- environment;
- finding type;
- credential state;
- actions: allow/warn/block/require_security_approval;
- scoped exception with reason and expiry.

## 15. Build workstream I — GitHub check publication

Publish one canonical check name:

`PlaidNox Security`

States:

- queued/in progress;
- pass;
- warn;
- block;
- incomplete.

Requirements:

- bind check to exact HEAD SHA;
- reject publication if HEAD is no longer current;
- summary includes new/regressed/existing counts;
- only bounded actionable annotations;
- no secret value in title, annotation, summary, or details;
- retries update the same logical review/check rather than creating uncontrolled duplicates.

For the first release, prefer one check summary over high-volume PR comments.

## 16. Build workstream J — merge/baseline reconciliation

On successful merge/default-branch update:

1. confirm accepted revision;
2. construct/update provider-neutral CodeSnapshot;
3. reconcile accepted changed-file IR into the baseline;
4. update symbol/edge relationships;
5. update sensitive evidence metadata;
6. update finding lifecycle and dependency states;
7. mark the new immutable baseline revision;
8. retain previous baseline metadata for audit/rollback window;
9. destroy ephemeral source checkout.

Do not rerun full white-box analysis after every merge.

Trigger a bootstrap/application rebuild if baseline integrity cannot be safely incrementally maintained.

## 17. Build workstream K — orchestration and idempotency

### K1. Job identity

PR review idempotency key:

```text
tenant_id + provider + repository_id + review_id + head_sha
```

### K2. Push coalescing

When a newer HEAD arrives:

- persist it as current;
- mark older attempt `SUPERSEDED`;
- terminate/skip older expensive stages;
- forbid stale publication.

### K3. Retry classes

Typed retryable errors:

- transient SCM/API failure;
- provider timeout;
- SQS visibility/retry;
- LiteLLM/JEV transient failure;
- database transient error;
- source materialization transient error.

Non-retryable examples:

- invalid webhook signature;
- unavailable repository permission;
- malformed persistent policy;
- unsupported repository state requiring operator/customer action.

## 18. Build workstream L — observability and security controls

Before QC, instrument:

- webhook received/verified/rejected;
- queue wait time;
- bootstrap duration;
- diff/IR reuse rate;
- affected symbols/files count;
- review depth selected;
- JEV routing count/confidence/fallback;
- LiteLLM call count/tokens/latency/cache reuse;
- candidate count;
- verified/rejected findings;
- policy decision;
- GitHub publication latency;
- superseded scans;
- retry/failure counts;
- incomplete scans;
- per-tenant active concurrency;
- secret detector counts without secret values.

Security controls required before QC:

- tenant scope enforced at repository/data access;
- encryption in transit;
- KMS-backed encryption at rest;
- GitHub webhook signature validation;
- short-lived GitHub installation tokens;
- no token/credential logging;
- redaction gateway before all model/provider boundaries;
- bounded source checkout lifetime;
- no execution of target repository code;
- least-privilege GitHub App permissions.

## 19. CI pipeline required before QC

Implement a repository CI pipeline with these gates.

### CI Stage 1 — static correctness

- formatting;
- lint;
- type checks where configured;
- JSON schema validity;
- prompt manifest validity;
- migration ordering/parse checks.

### CI Stage 2 — unit tests

Cover:

- event normalization;
- idempotency keys;
- HEAD superseding;
- diff model;
- stable symbol identity;
- incremental invalidation;
- sensitive evidence redaction/fingerprinting;
- JEV fallback behavior;
- policy compilation schema validation;
- deterministic policy matching;
- baseline classification;
- stale-check prevention.

### CI Stage 3 — component tests

Run against temporary/local services:

- PostgreSQL;
- Redis;
- queue adapter/local fake;
- ephemeral Git fixtures.

Validate:

- bootstrap persistence;
- review state transitions;
- retries do not duplicate records;
- worker restart/resume;
- current HEAD consistency;
- baseline update.

### CI Stage 4 — security/privacy tests

Mandatory:

- known credential corpus does not escape local redaction boundary;
- model input audit contains no planted raw secret;
- logs contain no planted raw secret;
- S3 artifact fixture contains no planted raw secret;
- malicious repository prompt-injection text cannot alter system instructions;
- path traversal/symlink cases cannot escape repository root;
- oversized/excluded files remain excluded;
- webhook signature/replay tests.

### CI Stage 5 — integration/E2E tests

Use test Git repositories and mocked/fake GitHub API where appropriate.

Scenarios:

1. connect repo -> bootstrap -> index ready;
2. safe PR -> PASS;
3. introduced verified High -> BLOCK;
4. existing High unrelated to PR -> PASS/WARN per policy, not automatic block;
5. production credential introduced -> BLOCK;
6. placeholder credential -> no false blocking finding;
7. authz regression -> BLOCK;
8. finding fixed by PR -> RESOLVED;
9. multiple pushes -> only newest HEAD publishes;
10. AI/provider failure -> INCOMPLETE, not PASS;
11. worker dies mid-review -> retry/resume without duplicate finding/check;
12. merged PR -> baseline advances;
13. baseline missing/corrupt -> bootstrap/rebuild path;
14. policy changed without code rescan -> same findings re-evaluate under new policy.

### CI Stage 6 — evaluation suite

Maintain seeded vulnerable/clean fixtures across multiple languages/framework styles.

Track:

- verified recall on seeded vulnerabilities;
- false-positive rate;
- duplicate rate;
- candidate -> verified conversion;
- affected-context precision;
- baseline classification accuracy;
- secret detection precision/recall on supported detector corpus;
- policy evaluation correctness;
- tokens and model cost per PR.

A model/prompt/schema version change cannot silently reduce the agreed evaluation floor.

## 20. QC entry criteria

Do not hand the product to QC until all of the following are true.

### Functional gate

- GitHub App install works in a test organization;
- repository bootstrap completes;
- PR webhook drives a full review automatically;
- a safe PR receives PASS;
- a known blocking PR receives BLOCK;
- policy can be created from English and viewed as compiled interpretation;
- stale HEAD cannot publish;
- merged PR advances baseline;
- existing unrelated debt does not unexpectedly block.

### Security gate

- planted secrets remain absent from model requests, logs, DB finding text, Redis and S3 artifacts;
- webhook signature validation is enforced;
- tenant isolation tests pass;
- repository path/symlink escape tests pass;
- no target repository script/dependency execution occurs;
- installation credentials are encrypted and short-lived at use.

### Reliability gate

- duplicate webhooks are idempotent;
- worker restart is recoverable;
- transient model/database/SCM failures retry with bounded attempts;
- required-stage failure produces INCOMPLETE rather than PASS;
- obsolete HEAD work is superseded;
- queue backlog recovery is demonstrated.

### Test gate

- unit suite green;
- integration suite green;
- E2E suite green;
- privacy/redaction suite green;
- migrations tested from clean DB;
- seeded vulnerability/clean-fixture evaluation recorded;
- no unresolved P0/P1 release defect.

## 21. QC test matrix

QC should test at least the following dimensions.

### Repository shapes

- small single-service repo;
- medium multi-module repo;
- monorepo with multiple apps/services;
- repository with unsupported/binary content;
- repository with large generated/vendor directories;
- repository containing many config/environment files.

### PR shapes

- one-line safe change;
- 100+ file change;
- file rename;
- deleted security control;
- changed shared helper with many callers;
- auth middleware change;
- new route/entrypoint;
- new data writer;
- configuration-only change;
- secret-only change;
- rapid repeated pushes.

### Policy shapes

- default block High/Critical;
- block production credentials;
- branch-specific rules;
- auth/authz Medium requires approval;
- allow/warn-only repo;
- temporary scoped exception;
- ambiguous English policy rejected/flagged at configuration time.

### Failure injection

- GitHub 5xx/rate limit;
- database restart;
- Redis loss;
- SQS redelivery;
- LiteLLM timeout;
- JEV timeout/low confidence;
- malformed model JSON;
- worker kill;
- source checkout failure;
- stale base or head revision;
- permission revoked after install.

## 22. Initial release performance targets

These are engineering targets for the first small release, not permanent contractual SLAs.

For ordinary small/medium PRs:

- webhook acknowledgement: < 2 seconds;
- queue-to-start under normal load: < 10 seconds;
- L0 completion: target < 30 seconds;
- L1 review: target p50 < 2 minutes;
- L2 review: target p50 < 5 minutes;
- final GitHub check publication: immediately after policy decision;
- stale HEAD publication: 0 tolerated;
- raw-secret boundary violations: 0 tolerated;
- cross-tenant data exposure: 0 tolerated.

Record p50/p95 rather than hiding long-tail behavior.

## 23. Staging soak before customer demo/release

Before external use, run a staging soak using at least:

- 10 synthetic/test organizations;
- 5–20 repositories per organization where practical;
- burst of at least 50 queued PR review jobs;
- mixed L0/L1/L2 cases;
- repeated push/coalescing scenarios;
- intentional provider failures;
- database/worker restart during active jobs.

Observe:

- queue drain behavior;
- per-tenant fairness;
- duplicate/superseded work;
- model token/cost distribution;
- database growth;
- S3 artifact size;
- memory/CPU per worker;
- error/retry rates;
- end-to-end latency.

The purpose is not to simulate 10,000 repositories yet. It is to prove the contracts that make later scaling possible.

## 24. Release sequence

Implement in this order because later stages depend on earlier contracts.

### Milestone R1 — SCM + persistence skeleton

Build:

- SCM provider interface;
- GitHub App/webhook verification;
- SCM/review persistence models and migrations;
- SQS job contracts;
- explicit review state machine;
- idempotency/current-HEAD handling.

Exit:

- GitHub PR event creates exactly one durable review job bound to HEAD.

### Milestone R2 — bootstrap + sensitive IR

Build:

- repository materialization;
- lightweight bootstrap;
- baseline persistence;
- Sensitive Evidence IR;
- secret-safe artifacts.

Exit:

- newly connected repo becomes `INDEX_READY` without full white-box scan.

### Milestone R3 — incremental review core

Build:

- structured diff;
- incremental Security IR;
- affected-surface expansion;
- prior finding dependency invalidation;
- L0 result.

Exit:

- changed helper invalidates affected callers/findings; unrelated code is reused.

### Milestone R4 — JEV + AI review

Build:

- release JEV routing decisions;
- L1/L2 affected-surface hunt;
- Deep Hunt verification;
- missing-context resolution with truncation metadata.

Exit:

- seeded contextual vulnerability in a PR is verified while unrelated code is not fully rescanned.

### Milestone R5 — baseline classification + policy

Build:

- introduced/regressed/modified/existing/resolved classifier;
- policy compiler runtime;
- ambiguity validation;
- deterministic evaluator;
- exception model.

Exit:

- new High blocks while unrelated existing High does not under default policy.

### Milestone R6 — GitHub merge gate

Build:

- check publisher;
- bounded annotations;
- stale-HEAD prevention;
- retry/update behavior;
- baseline update after merge.

Exit:

- end-to-end GitHub test organization demonstrates PASS and BLOCK correctly.

### Milestone R7 — reliability + security hardening

Build/test:

- retries and backoff;
- worker recovery;
- queue visibility/poison handling;
- tenant concurrency caps;
- redaction tests;
- prompt injection tests;
- audit events;
- metrics dashboards;
- retention/cleanup for ephemeral artifacts.

Exit:

- no known P0/P1 reliability or secret-handling defect.

### Milestone R8 — QC handoff

Produce:

- deployment runbook;
- test-data/fixture catalog;
- expected policy outcomes;
- known limitations;
- release configuration;
- migration instructions;
- rollback procedure;
- QC matrix from this document;
- staging soak report.

Exit:

- all QC entry criteria pass and the release candidate is frozen except for defect fixes.

## 25. Definition of "ready for QC"

The feature is **not** ready for QC simply because prompts and domain classes exist.

It is ready for QC when the following real pipeline works repeatedly:

```text
GitHub PR webhook
  -> verified/normalized event
  -> idempotent queued review
  -> current HEAD check
  -> baseline lookup/bootstrap if needed
  -> base/head diff
  -> incremental Security IR
  -> sensitive evidence
  -> affected security surface
  -> L0
  -> JEV route
  -> L1/L2 hunt when required
  -> independent verification
  -> baseline-relative classification
  -> deterministic policy
  -> HEAD-bound GitHub check
  -> merge
  -> baseline reconciliation
```

and the security/reliability test suites prove that failure cannot be silently converted into a clean result.

## 26. Scale-later compatibility rules

Even though the first release targets only 10 organizations, implement these now:

- every persistent record is tenant scoped;
- provider-neutral scanner core remains free of GitHub-specific fields;
- job identity is deterministic/idempotent;
- source artifacts are content-addressable;
- Security IR is versioned;
- policy is versioned independently of scanner release;
- HEAD superseding is a first-class state;
- queues and workers are stateless/retryable;
- raw credential values never become durable product data;
- baseline/context reuse is the default;
- metrics are per tenant/repository/review/model stage.

Later scaling to 100/1,000 organizations should replace or expand scheduling/storage capacity without redesigning these contracts.
