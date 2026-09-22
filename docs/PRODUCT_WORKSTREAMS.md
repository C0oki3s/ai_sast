# PlaidNox security product workstreams

## Boundary rule

Code Scanning must reach its end-to-end exit condition before another scanner
family is added to its runtime. Every family below is an independent workstream
with its own adapters, workers, database schema, policy, versioning, tests, and
release gate. Products share only stable platform contracts:

- tenant, application, codebase, asset, and snapshot identity;
- evidence, finding, severity, lifecycle, ownership, and audit envelopes;
- policy decisions and report/export formats;
- object-storage references, telemetry, and cost attribution;
- an event contract for later correlation in VETA.

They do not share scanner-specific tables, queues, prompts, provider tokens, or
failure states. One scanner failing cannot silently make another scanner pass.

## Delivery order

1. Code Scanning (SAST and AI SAST).
2. SCM Integration.
3. Dependency Scanning (SCA) and SBOM.
4. Secrets Detection.
5. Outdated Software and automated upgrade intelligence.
6. IaC, container, VM, and Cloud Security.
7. License Risk.
8. DAST.
9. IDE Plugins.

This order establishes reliable source understanding and evidence contracts
before adding orchestration or more scanner families.

## 1. Code Scanning

Scope:

- broad AI-native source review across supported languages;
- PlaidNox proprietary prompts, context, taxonomy, and Deep Hunt methodology;
- organization-defined custom AI rules without hardcoded code paths;
- Context Fabric, business/threat context, knowledge RAG, and prompt caching;
- adversarial false-positive reduction for every candidate;
- evidence-bound remediation and AI-proposed fixes;
- JSON, SARIF, Markdown, and API-ready normalized findings.

Open-source foundations:

- DataDog SAIST as an optional broad AI candidate adapter;
- Tree-sitter for portable parsing;
- SCIP/compiler/LSP indexes where available for precise symbols/references;
- ripgrep for AI-directed discovery and navigation;
- a small persistent Tree-sitter Security IR for relationships and context selection.

PlaidNox owns task planning, context compilation, the recursive hunt loop,
falsification, finding schema, prompt assets, knowledge, and verdicts.

## 2. SCM Integration

Scope:

- GitHub, GitLab, Bitbucket, and Azure Repos adapters;
- app/install-token lifecycle, webhook verification, clone/snapshot acquisition;
- PR/MR diff and merge-base calculation;
- queueing, retries, cancellation, concurrency, checks/statuses, comments;
- protected default-branch configuration and policy acquisition;
- CI templates and audit linkage.

The SCM service invokes Code Scanning with an immutable source snapshot and
receives a result. Code Scanning never receives webhook or installation-token
logic. The earlier GitHub/PR prototype was removed from the Code Scanning
package; SCM starts later in its own package and database boundary.

### Product principle: PR/MR review is the primary product, not full white-box

A full exhaustive white-box hunt (recon, exhaustive discovery, verification,
variant sweep, capability chaining) across an entire repository on every
connect is not the default product. It does not need to be, because two
different things are being conflated when people say "scan the repo":

```text
Cheap Repository Baseline  !=  Full White-box Security Review
```

The default flow is:

1. **Repository Bootstrap** ("Security Indexing", never called "white-box
   scan") — a deterministic, cheap pass building a `RepositorySecurityIndex`:
   file inventory, language/framework detection, Tree-sitter Security IR,
   symbol/call/reference graph, route and entry-point discovery, auth/authz
   location discovery, sensitive-effect discovery, data-store relationships,
   config/environment inventory, credential *metadata* (fingerprint only,
   never a value), and a lightweight trust-boundary model. No AI vulnerability
   hunt runs here. This reuses Code Scanning's existing ripgrep/Tree-sitter
   Security IR machinery — it is the same recon layer, just persisted as a
   baseline instead of being thrown away after one hunt.
2. **PR/MR review** is where the expensive reasoning happens, and only over
   the surface a change actually touches. The exact pipeline, context layers,
   and review-depth routing are specified in full below in
   "PR/MR Contextual Review Plan v2" — the short version is *changed-file-
   first, context-rich, expansion-on-demand*, not a full impact-graph
   traversal before every AI review. Findings are never reported without
   independent Deep Hunt/verifier confirmation, matching the existing
   no-deterministic-verdicts rule in `IMPLEMENTATION_PLAN.md`.
3. **The baseline evolves with every merged PR** instead of being rebuilt from
   scratch: `Security Index A + accepted change B -> Security Index B`. This
   is the same incremental-model idea the Context Fabric was already designed
   for — the repository's security understanding compounds over time as real
   PRs touch real subsystems, without ever paying for one massive upfront
   audit.
4. **Full white-box remains available**, but as an optional/on-demand/premium
   capability, not a prerequisite for PR blocking. PR-only review is very good
   at preventing *new* vulnerabilities and has a structural blind spot for
   vulnerabilities that already existed before onboarding and that no PR ever
   touches (e.g. an unauthenticated `/v1/admin/export` nobody edits). Trigger
   full or scoped white-box selectively — on customer request or on risk
   signals such as: a large fraction of the repository changed at once, the
   auth provider changed, a new internet-facing service or payment workflow
   appeared, a major framework/dependency migration landed, or measured
   coverage/confidence on the baseline drops. For monorepos, scope re-analysis
   to the affected application/service (`/apps/payment`, `/services/auth`,
   ...) rather than the whole repository — each subtree keeps its own
   security model, coverage, revision, and risk state.

Review depth is itself routed, not fixed, reusing the JEV decision plane
already built for Code Scanning (see `IMPLEMENTATION_PLAN.md`'s JEV
decision-plane hardening section). The full L0-L3 routing contract,
superseding any earlier sketch of it, is specified in "PR/MR Contextual
Review Plan v2" -> "Review levels" below.

Baseline comparison classifies every PR finding relative to what is already
known on the target branch — `INTRODUCED`, `REGRESSED`, `MODIFIED_EXISTING`,
`EXISTING`, `RESOLVED` — and policy normally blocks only on
`INTRODUCED`/`REGRESSED`/`MODIFIED_EXISTING`, so the product stays usable on
large legacy applications instead of blocking every PR on pre-existing debt.
Policy itself stays an English-authored, AI-compiled, deterministically
evaluated artifact (English rule -> strict policy AST -> plain Python
evaluator against finding JSON) — no LLM decides pass/fail at merge time.

### PR/MR Contextual Review Plan v2 (benchmark-derived)

This subsection is the authoritative design for how PR/MR review is
implemented — it supersedes any conflicting detail elsewhere in this
section on pipeline shape, context layers, JEV questions, review levels, or
finding counters. The separate "Initial release scope: ~10 organizations"
section below it remains the deployment/infrastructure and release
checklist and is unaffected by this design change.

#### Benchmark-derived design change

The `C0oki3s/NSTCTF` PR benchmark showed that a useful PR reviewer can
identify a real authentication regression from one modified security-
critical file without first constructing a complete source-to-sink
dataflow graph.

Observed behavior:

- one file changed: `middleware/ValidateToken.js`;
- baseline behavior used `verifier.verify(token)`;
- PR changed it to `jwt.decode(token)`;
- the scanner understood that the middleware protected downstream routes;
- it produced a High finding for unsigned attacker-controlled JWT claims;
- it connected forged claims to the manager-only report path and trusted
  server-side effects;
- its finding UI explicitly stated that no traceable data flow had been
  modeled.

The correct default for PlaidNox PR/MR review is therefore:

> changed-file-first, context-rich, and expansion-on-demand.

Do not rebuild or traverse the whole affected graph before every AI review.

#### Revised pipeline

```text
SCM webhook
  -> verify + normalize
  -> coalesce to current HEAD
  -> load repository/application baseline
  -> compute base..head diff
  -> deterministic change relevance
  -> load cached application/security context
  -> deeply analyze changed files/symbols
  -> generate security hypotheses
  -> request exact unchanged context only when needed
  -> independent verification
  -> baseline-relative classification
  -> deterministic merge policy
  -> publish HEAD-bound check
  -> reconcile baseline after merge
```

#### Four context layers

**Layer 0 — PR delta.** Always available: changed files; changed line
ranges; changed symbols; added/deleted symbols; changed imports/calls;
changed config/sensitive evidence.

**Layer 1 — cached ApplicationContext.** Persist and reuse: application/
runtime type; entry points; components; auth/authz/security controls;
important routes/workflows; stores and sensitive effects; environment/
configuration metadata; identity provider; prior findings and dependencies;
context confidence/version.

**Layer 2 — changed-file local context.** For each changed file/symbol:
containing function/class; neighboring security logic; imports; same-file
definitions/references; local control flow; baseline security role.

**Layer 3 — on-demand expansion.** Only when a candidate or verifier needs
it: callers/callees; route registrations; middleware relationships;
authz/tenant/ownership checks; readers/writers; state transitions; explicit
flow slices; framework/provider semantics; environment evidence.

#### Deterministic change-relevance gate

Add a pre-AI `ChangeRelevance` stage. Suggested fields:

```text
runtime_changed
security_control_changed
config_changed
sensitive_material_changed
dependency_or_build_changed
test_only
docs_only
generated_only
changed_files
changed_symbols
known_security_roles
prior_finding_dependencies
minimum_review_depth
```

Fast exit: if only documentation/non-runtime assets changed and no
security/config/sensitive relationships are affected —

```text
diff
  -> relevance = non-security
  -> L0 complete
  -> policy
  -> PASS/WARN
```

— no generative review is required.

Mandatory escalation when changes intersect: authentication;
authorization/tenancy/ownership; identity/session/token handling;
routes/controllers/middleware; data readers/writers; file/network/process/
cloud effects; security configuration; signing/crypto; credentials/secrets;
admin/payment/high-value workflows; state transitions/concurrency; prior
finding dependencies. Use Security IR roles and baseline relationships, not
filenames alone.

#### Changed-file-first AI review

For each security-relevant changed file: (1) load the diff; (2) load the
complete changed symbol or bounded source context; (3) load that
symbol/file's baseline security role; (4) load compact ApplicationContext;
(5) load directly linked prior controls/findings; (6) ask the hunter
whether the change breaks a security invariant or creates a new attacker
capability.

The normal L1 model input should be changed code plus compact context, not
broad repository source.

#### Candidate schema should be lean

Discovery should produce hypotheses rather than final findings. Suggested
fields:

```text
candidate_id
changed_path
changed_symbol
changed_lines
behavior_before
behavior_after
security_role
suspected_broken_invariant
provisional_attacker_capability
context_facts_used
context_gaps
requested_expansion
```

Do not assign final CWE, severity, remediation, or merge action during
candidate discovery.

#### Evidence-on-demand

The verifier decides what extra context is needed.

*Example: JWT verification removal.* Changed code plus cached context may
already prove:

```text
attacker-controlled bearer/cookie token
  -> decode-only parsing
  -> no authenticity validation
  -> claims become req.user
  -> auth middleware is trusted by protected routes
```

The verifier may request only: the manager-only gate; representative
protected routes; downstream use of the identity claims. A full call
graph/dataflow reconstruction is unnecessary if those facts are sufficient.

*Example: stored second-order issue.* The verifier may require explicit
flow/state evidence: `writer -> store -> later reader -> sensitive effect`.

#### Formal dataflow is optional, not universally required

Do not require a source-to-sink graph for every PR finding. Control/
invariant regressions can be proven by:

```text
untrusted input
  -> security control removed/weakened
  -> trusted identity/state created
  -> downstream code trusts that state
```

Examples: JWT signature verification removed; authorization guard deleted;
tenant ownership binding removed; permission condition inverted; CSRF/
security flag disabled; signing/encryption requirement weakened.

When propagation across multiple functions/stores is essential to the
claim, explicit flow evidence must be requested. Missing required flow
remains an evidence gap, never proof of safety.

#### Evidence roles

Every verified finding should distinguish changed root cause from
contextual impact:

```text
ROOT_CAUSE_CHANGED_CODE
ATTACKER_ORIGIN
SECURITY_BOUNDARY
DEFENSE_REMOVED_OR_BYPASSED
DOWNSTREAM_TRUST
SENSITIVE_EFFECT
CONTEXT_ONLY
```

For the JWT regression:

```text
ROOT_CAUSE_CHANGED_CODE
  middleware/ValidateToken.js
  verifier.verify(token) -> jwt.decode(token)

ATTACKER_ORIGIN
  Authorization header / idToken cookie

SECURITY_BOUNDARY
  authentication middleware

DEFENSE_REMOVED_OR_BYPASSED
  Cognito JWT authenticity validation

DOWNSTREAM_TRUST
  req.user claims are treated as authenticated identity

SENSITIVE_EFFECT
  manager-only report generation and identity-selected operations
```

The primary affected file remains the changed file. Unchanged
files/routes can appear as contextual evidence.

#### Revised JEV role

Run JEV only after deterministic relevance classification. Recommended
questions:

```text
analysis_depth: FAST | STANDARD | DEEP
needs_cross_file: YES | NO
needs_control_relationships: YES | NO
needs_state_reconstruction: YES | NO
needs_explicit_flow: YES | NO
needs_external_semantics: YES | NO
needs_environment_context: YES | NO
```

JEV must not decide vulnerability validity, severity, CWE, merge outcome,
or whether missing evidence may be ignored.

#### Review levels

- **L0 — deterministic delta review.** Always run: diff; changed-file
  classification; incremental IR update; sensitive evidence; configuration
  changes; prior finding invalidation; cached context lookup.
- **L1 — changed-file contextual hunt.** Default AI mode for
  security-relevant code: changed code + compact ApplicationContext + local
  Security IR + relevant baseline relationships.
- **L2 — evidence expansion + deep verification.** Only when required:
  callers/callees; routes; controls; readers/writers; state reconstruction;
  explicit flow; external semantics; environment evidence.
- **L3 — full white-box.** Separate product path. Not required for normal
  PR/MR review.

#### Baseline classification

Verified findings remain classified as `INTRODUCED`, `REGRESSED`,
`MODIFIED_EXISTING`, `EXISTING`, `RESOLVED`. For PR review, direct
modification of the root-cause symbol is strong evidence for `INTRODUCED`
or `REGRESSED`. Existing unrelated debt must not block by default.

#### Counters and UI semantics

Track separately: Candidates generated; Evaluated; Verified; Rejected;
Unresolved; In triage; Blocking; Existing.

- Candidates generated: hypotheses created from changed code/context.
- Evaluated: verifier attempt completed.
- Verified: vulnerability supported.
- Rejected: falsified or required gates failed.
- Unresolved: evidence missing/incomplete.
- In triage: verified finding awaiting disposition.
- Blocking: verified finding matched blocking policy.
- Existing: baseline issue not introduced by this PR.

`0 Verified` is not equivalent to a complete clean result if unresolved
coverage remains.

#### Live timeline

Suggested stages: Preparing workspace; Repository ready; Application
context loaded; Changed files analyzed; Security relevance evaluated;
Reviewing changed security surface; Verifying candidates; Comparing
baseline; Evaluating policy; Publishing result.

When no baseline exists, show `Building initial repository security
index`. Show `Skipped` for stages that do not run.

#### Sensitive evidence in PR mode

Inspect changed/new sensitive files locally and reuse fingerprints for
unchanged sensitive material. If changed code newly consumes an unchanged
credential/config item, treat that relationship as affected.

Raw secret values must never enter model/JEV payloads, findings, logs,
Redis, S3, or reports.

#### Caching strategy

Persist/reuse: ApplicationContext; Security IR; file hashes; stable
symbols; security-control relationships; route/control associations; store
relationships; finding dependencies; sensitive-evidence fingerprints;
model-independent repository context. Raw source can remain ephemeral.

#### When broad expansion is justified

Use broad affected-surface reconstruction for cases such as: shared
security helper changed with many callers; auth/authz framework
replacement; routing/middleware registration changes; persistence/workflow
schema changes; new service/application; large architecture diff;
graph/context integrity mismatch; candidate has several unresolved hops;
baseline context confidence is too low. Prefer application/component-level
expansion before whole-repository reconstruction.

#### Required QC fixtures from this benchmark

- **Fixture A — documentation-only PR.** Expected: changed file analyzed;
  cached application context reused; zero candidates; AI hunt skipped;
  PASS unless policy independently requires otherwise.
- **Fixture B — JWT verification removal.** Baseline: verified
  authentication middleware protects sensitive routes. PR: cryptographic
  verify -> decode-only claims parsing. Expected: security-control change
  recognized; candidate generated from changed file; cached application
  context used for impact; full dataflow not required when
  security-boundary proof is complete; independent verifier supports
  authentication-bypass capability; changed middleware is the root-cause
  evidence; related unchanged routes are contextual evidence; default
  High/Critical policy blocks.
- **Fixture C — cross-file proof required.** Expected: L1 produces
  hypothesis; verifier requests exact callers/controls/flow; L2 loads only
  requested context; no verified finding if required evidence remains
  missing.
- **Fixture D — existing vulnerability outside PR.** Expected: issue may
  be visible from baseline; classified `EXISTING`; does not block under
  default new-risk policy.

#### Performance objective for the 10-org release

Optimize for warm-baseline PRs. Targets for ordinary small/medium PRs:

```text
baseline/context load     seconds
changed-file analysis     seconds to tens of seconds
L1 contextual review      ~1-2 minutes target p50
L2 only when needed       additional time
```

Measure: changed files vs files loaded; changed symbols vs symbols
expanded; ApplicationContext reuse rate; Security IR reuse rate; candidate
count; expansion requests per candidate; model calls/tokens per PR;
verification latency; total PR latency.

The objective is not to minimize reasoning quality. It is to avoid paying
for context that was already known or not needed for the candidate.

#### Implementation priority update

Before QC, prioritize in this order: (1) deterministic `ChangeRelevance`;
(2) cached `ApplicationContext` persistence/load; (3) changed-file L1
review contract; (4) lean candidate schema; (5) candidate-specific context
broker; (6) verifier evidence-role model; (7) optional explicit flow
requests; (8) baseline classification; (9) deterministic policy;
(10) SCM publication; (11) live timeline/counters; (12) performance and
privacy tests.

This v2 plan guides PR/MR implementation. The existing 10-organization
infrastructure/QC plan immediately below remains the deployment and
release checklist.

Two commercial surfaces follow directly from this split: a cheap, continuous
**PR/MR security** product (contextual AI review, secret detection, business
logic/auth review, merge policy, PASS/BLOCK) that does not require buying a
full pentest-style engagement, and a separate, more expensive **deep code
audit** product (whole-repository white-box, capability chaining, existing-
vulnerability discovery, variant sweep, full report) sold on demand or on a
schedule.

#### Implementation status (Wave 1)

A new `plaidnox_scm` package (`src/plaidnox_scm/`) implements the first
slice of the priority list above, kept separate from Code Scanning per
`docs/IMPLEMENTATION_PLAN.md`'s boundary rule (`plaidnox_scm` imports
`plaidnox_sast` as a library; `pipeline.py` gained no SCM concepts):

- **Implemented**: (1) deterministic `ChangeRelevance`
  (`plaidnox_scm/change_relevance.py`, SCM-agnostic diffing in
  `plaidnox_scm/diffing.py`), (2) cached `ApplicationContext`
  persistence/load (`plaidnox_scm/context_store.py`,
  `plaidnox_scm/models.py`, own `scm_application_contexts` table, own
  declarative `Base` — not foreign-keyed into Code Scanning's schema).
  `plaidnox_scm/review.py` wires these into a fast-exit entrypoint proving
  **Fixture A** (documentation-only PR: zero candidates, AI hunt skipped,
  cached context reused) and **Fixture B**'s relevance classification (the
  JWT `verifier.verify(token)` -> `jwt.decode(token)` regression correctly
  escalates to `DEEP`) end to end, exercised via `plaidnox-scm review`
  (`plaidnox_scm/cli.py`) and `tests/test_scm_*.py`.
  `ChangeRelevance`'s security/sensitive-material detection covers
  authentication, authorization/session/token handling, routes/middleware,
  security configuration, signing/crypto, and credentials/secrets via path
  and content heuristics; it does not yet semantically cover data
  readers/writers, file/network/process/cloud effects, admin/payment
  workflows, state/concurrency, or prior-finding dependencies (documented
  in `change_relevance.py`'s module docstring).
- **Not yet started** (explicit, not silent): (3) changed-file L1 AI review
  contract — `review_pull_request` returns an explicit
  `escalated_not_yet_wired` result for anything above FAST depth rather
  than calling a model; (4) lean candidate schema; (5) candidate-specific
  context broker; (6) verifier evidence-role model; (7) optional explicit
  flow requests; (8) baseline classification; (9) deterministic policy;
  (10) SCM publication (GitHub/GitLab webhooks, checks, inline comments);
  (11) live timeline/counters; (12) performance/privacy tests. The
  "PR/MR Finding Delivery, Triage, and Remediation Plan" below (canonical
  finding object, lifecycle, GitHub publication, triage commands, fix
  workflow, dashboard) is entirely unstarted.
- Real Layer-1 `ApplicationContext` computation is currently a cache shell
  only (`review.py`'s `_empty_application_context`) — an AI-assisted or
  static-analysis-driven builder is needed before item 3 can produce
  meaningful L1 review input.

#### Implementation status (Wave 2)

Wave 2 replaces the Wave 1 cache shell and explicit escalation placeholder
with a production-wired, provider-neutral review path while preserving the
package boundary (`plaidnox_scm` calls `plaidnox_sast` as a library and adds
no SCM behavior to `plaidnox_sast.pipeline`):

- **Layer-1 ApplicationContext computation is implemented.**
  `plaidnox_scm.application_context.SastApplicationContextBuilder` safely
  materializes the resolved base commit without changing the caller's
  checkout, builds Tree-sitter Security IR, and uses the PlaidNox repository
  context agent through the LiteLLM SDK. The durable cache is keyed by
  `(tenant_id, codebase_id)`, records the immutable base commit and tree hash,
  and invalidates when the base, context schema, or builder version changes.
  A docs-only fast exit reads an existing base-bound context but never creates
  a fabricated empty context or calls AI.
- **Priority items (3) and (4) are implemented.** Each changed file receives
  the base/head source, zero-context diff, compact cached ApplicationContext,
  and Tree-sitter Security IR for that file only. The externally versioned
  Markdown/Jinja prompt and strict JSON schema return lean hypotheses with
  before/after behavior, suspected invariant, provisional attacker capability,
  context facts/gaps, and exact expansion requests. L1 cannot assign final
  CWE/CVE/OWASP classification, severity, remediation, or merge action.
- **Independent verification is production-wired.** L1 hypotheses are adapted
  to the existing PlaidNox evidence contract, routed only after deterministic
  relevance, and verified by `PlaidNoxDeepHuntAgent` against an immutable head
  snapshot. The change-relevance minimum depth cannot be downgraded by routing.
  Deep Hunt owns final classification, severity, exploitability, proof, and
  remediation output. Its existing bounded Tree-sitter/ripgrep context requests
  provide the first L2 expansion path; the SCM-specific context broker in
  priority item (5) remains a separate follow-on.
- **Incomplete review is explicit.** Results separately count generated,
  evaluated, verified, rejected, and unresolved candidates. Zero verified does
  not pass when L1 coverage or verifier evidence remains unresolved. Deleted
  root-cause files remain unresolved until the baseline-deletion evidence
  adapter is implemented, instead of crashing or being treated as safe.
- **Production assets are externalized.** SCM prompts are Markdown templates;
  schemas, model tier, budgets, adapter defaults, context versions, and the
  PostgreSQL DDL are packaged assets. The CLI uses the LiteLLM SDK for context,
  L1, and Deep Hunt. PostgreSQL expects the versioned migration; `create_all`
  remains limited to the transitional local SQLite store.
- **Verified without model spend.** SCM tests use real temporary git
  repositories and injected model/verifier doubles. They prove base-snapshot
  context construction, base/version invalidation, tenant isolation, strict L1
  changed-line anchoring, the JWT regression through L1 and independent
  verification, minimum-depth enforcement, docs-only zero-AI behavior, and the
  `0 verified + unresolved = incomplete` rule.

Still deferred: the complete SCM-specific candidate context broker and
evidence-role persistence (items 5-7), baseline finding classification,
merge policy, GitHub/GitLab webhook and check publication, triage/remediation,
live timeline, dashboards, and release performance/privacy load tests.

#### Implementation status (Wave 3)

Wave 3 implements priority items (5)-(7) without broadening the SCM service
boundary or adding provider-specific publication code:

- **Candidate-specific context broker.** `plaidnox_scm.context_broker`
  resolves only the exact requests attached to one L1 hypothesis. Supported
  requests cover definitions, callers, callees, imports, route/application
  context, bounded source windows, sibling handlers, AI-produced ripgrep
  expressions, and adjacent Tree-sitter call-flow edges. Request count,
  records, source windows, and characters are bounded by versioned runtime
  assets. Repository paths are containment-checked and every source/search
  record passes through the shared secret-redaction gateway.
- **Verifier evidence roles.** `plaidnox_scm.evidence` creates a typed evidence
  ledger distinguishing `ROOT_CAUSE_CHANGED_CODE`, `ATTACKER_ORIGIN`,
  `SECURITY_BOUNDARY`, `DEFENSE_REMOVED_OR_BYPASSED`, `DOWNSTREAM_TRUST`,
  `SENSITIVE_EFFECT`, and `CONTEXT_ONLY`. The mapping from Deep Hunt evidence
  locations to PR evidence roles is externally versioned rather than embedded
  in orchestration code.
- **Explicit flow expansion.** A candidate can request an exact symbol-level
  flow slice. The broker returns only adjacent Tree-sitter call edges and
  bounded source evidence; it does not require or construct a universal full
  dataflow graph. Deep Hunt can still make its own bounded follow-up requests.
- **Fixture C is enforced.** If an exact requested definition, caller, control,
  route, window, search, or flow cannot be resolved, the candidate remains
  `unresolved` even when an independent model response otherwise supports the
  hypothesis. The final PR result therefore becomes `review_incomplete`, never
  a silent pass.
- **Context ordering is cache- and token-aware.** Candidate-specific expansion
  is placed before compact ApplicationContext in the Deep Hunt security packet,
  so the most relevant evidence survives the verifier's configured context
  bound. Whole-head Security IR is built only after L1 emits a candidate.

Tests use real temporary repositories to cover all broker request types,
missing cross-file proof, request/path boundaries, secret redaction, evidence
role mapping, and the supported-but-unresolved verifier case. No live model or
research call is made by the test suite.

The next implementation phase begins at priority item (8): baseline-relative
classification (`INTRODUCED`, `REGRESSED`, `MODIFIED_EXISTING`, `EXISTING`,
`RESOLVED`), followed by deterministic merge policy. Provider webhook/check
publication, triage/remediation, timeline, and dashboard work remain later SCM
phases.

### PR/MR Finding Delivery, Triage, and Remediation Plan

This subsection is the authoritative design for everything that happens
after "PR/MR Contextual Review Plan v2" above produces a verified finding:
publication, inline comments, dashboard rendering, developer triage
commands, and AI-assisted remediation. It supersedes any conflicting detail
elsewhere in this section on finding lifecycle, GitHub check/comment
behavior, or triage/remediation flow. The separate "Initial release scope:
~10 organizations" section below it remains the deployment/infrastructure
and release checklist and is unaffected by this design.

#### Goal

The target developer experience: the PR/MR scan reaches a verified
finding; PlaidNox publishes a HEAD-bound merge check; the finding is
anchored to the changed root-cause line when possible; the inline comment
contains a concise explanation and safe reproduction guidance; the
dashboard exposes the complete finding/evidence record; developers can
triage from the PR comment using controlled commands; triage immediately
updates the finding lifecycle and merge policy result; developers can
request an AI-generated fix that is constrained to the finding root cause;
the fix is independently revalidated before PlaidNox calls it resolved.

The scanner, GitHub publisher, dashboard, triage parser, and remediation
agent must not maintain separate security verdicts. They operate on one
canonical verified-finding record.

#### Canonical finding object

Introduce or extend a provider-neutral `VerifiedFinding`/`ReviewFinding`
model with the following logical fields:

```text
finding_id
fingerprint
root_cause_fingerprint
scan_id
review_id
tenant_id
repository_id
base_revision
head_revision

state
triage_state
policy_state
severity
confidence
category

summary
description
impact
remediation_invariant

root_cause_path
root_cause_symbol
root_cause_start_line
root_cause_end_line
root_cause_changed_in_pr

attacker_origin
security_boundary
defense_removed_or_bypassed
downstream_trust
sensitive_effects[]
capabilities[]

proof_plan
safe_reproduction_steps[]
regression_test_expectation

evidence[]
context_facts[]
evidence_gaps[]

baseline_relationship
introduced_by_revision
verified_at
verifier_model_execution_id
```

Do not store GitHub comment IDs or GitLab note IDs directly in the core
finding object. SCM publication records belong to a provider integration
table.

#### Finding lifecycle

Use an explicit state machine:

```text
CANDIDATE
  -> VERIFYING
  -> VERIFIED
       -> OPEN
       -> CONFIRMED
       -> ACCEPTED_RISK
       -> FALSE_POSITIVE
       -> FIX_PENDING
       -> FIX_VALIDATING
       -> RESOLVED

CANDIDATE/VERIFYING
  -> REJECTED
  -> UNRESOLVED
```

Important rules:

- `VERIFIED` means PlaidNox has enough evidence to support the
  vulnerability claim.
- `CONFIRMED` is human triage acknowledgement, not a second technical
  proof.
- `FALSE_POSITIVE` requires actor, timestamp, optional reason, and audit
  history.
- `ACCEPTED_RISK` requires actor, reason, scope, and preferably
  expiry/ticket.
- `RESOLVED` cannot be set only because somebody writes `!fixed`; it
  requires fix validation against a new revision or explicit authorized
  override.
- every state transition is append-only in audit history.

#### Evidence roles used for delivery

Every finding should render evidence by role instead of one
undifferentiated dataflow:

```text
ROOT_CAUSE_CHANGED_CODE
ATTACKER_ORIGIN
SECURITY_BOUNDARY
DEFENSE_REMOVED_OR_BYPASSED
DOWNSTREAM_TRUST
SENSITIVE_EFFECT
CONTEXT_ONLY
REMEDIATION_EVIDENCE
```

For a PR finding, the primary inline anchor is `ROOT_CAUSE_CHANGED_CODE`
when the root cause is on a changed line.

Unchanged files may be referenced in the description/dashboard as
contextual evidence but should not generate fake inline comments on
unrelated changed lines.

#### GitHub publication architecture

Create a provider-specific publisher outside Code Scanning core. Suggested
modules:

```text
src/plaidnox_sast/scm/
    base.py
    models.py
    github.py
    publication.py

src/plaidnox_sast/review_delivery/
    renderer.py
    service.py
    models.py
```

Provider-neutral interface:

```text
publish_review_started(review)
publish_review_progress(review, progress)
publish_finding(review, finding)
publish_review_summary(review, policy_result)
update_finding_publication(publication, finding)
resolve_finding_publication(publication, finding)
```

The GitHub implementation owns Checks API/review comments. The security
engine does not call GitHub directly.

#### GitHub Check behavior

Use one canonical check name: `PlaidNox Security`. Create/update the check
against the exact PR HEAD SHA. Suggested mapping:

```text
internal queued/running       -> GitHub in_progress
PASS                          -> success
WARN                          -> neutral
BLOCK                         -> failure
REQUIRE_SECURITY_APPROVAL     -> action_required or neutral + explicit summary
INCOMPLETE                    -> neutral/action_required; never success
FAILED_FINAL                  -> neutral/action_required; never success
SUPERSEDED                    -> cancelled / do not overwrite current HEAD check
```

Before every final publication: (1) read current PR HEAD; (2) compare with
`review.head_revision`; (3) if different, mark current attempt superseded;
(4) do not publish its PASS/BLOCK as current.

The check summary should show:

```text
PlaidNox Security

1 Blocking
0 Warnings
0 Existing affected findings

High — Protected routes accept unsigned attacker-controlled JWT claims
middleware/ValidateToken.js:53

View finding ->
```

The check is the merge-gating primitive. Inline comments are developer
guidance, not the source of merge policy truth.

#### Inline PR finding comment

**When to create an inline comment.** Create one when: the finding is
verified; root cause is attributable to the PR; the root-cause path is a
changed file; the selected root-cause line is present on the RIGHT/new
side of the diff; the publication has not already been created for this
finding fingerprint + HEAD. Otherwise publish the finding only in the
check summary/dashboard and optionally one top-level PR summary.

**Comment content.** Use a compact top section followed by expandable
detail where supported. Recommended rendering:

```text
HIGH  Protected routes accept unsigned, attacker-controlled JWT claims

The changed authentication middleware parses the bearer/cookie JWT without
validating authenticity before assigning its claims to the trusted request
identity. Downstream protected routes therefore consume attacker-controlled
identity claims.

Impact
An unauthenticated caller can forge privileged identity claims and reach
manager-only operations that trust req.user.

Steps to reproduce
1. Create a syntactically valid unsigned/invalidly signed test JWT containing
   the required privileged claim.
2. Send it to the affected protected route in the authorized test environment.
3. Confirm that the route accepts the forged identity instead of rejecting it.

View full finding | Fix with PlaidNox

Triage: !valid | !fp <reason> | !accepted_risk <reason> | !fixed
```

Keep the inline comment shorter than the dashboard finding. Do not paste
every contextual source file into GitHub.

**Safe reproduction.** The verifier can generate reproduction steps/code
for an authorized test target, but publishing logic must: avoid embedding
secrets/tokens copied from the repository; use placeholders for target
hosts and credentials; not automatically execute the proof against
external infrastructure; distinguish static proof from runtime-validated
proof; redact sensitive configuration before rendering.

#### Publication persistence

Add SCM-owned persistence tables/entities such as:

```text
review_publications
finding_publications
triage_events
remediation_requests
remediation_attempts
```

`finding_publications` minimum fields:

```text
id
tenant_id
finding_id
provider
repository_external_id
review_external_id
head_revision
publication_type        # inline_comment/check_annotation/summary
external_publication_id
path
line
state
content_hash
created_at
updated_at
```

Unique logical identity:

```text
provider + repository + review + head_revision + finding_id + publication_type
```

This makes publication retry-safe.

#### Dashboard finding page

The finding page should render the canonical finding rather than scrape
the GitHub comment.

**Description tab:** title; severity; lifecycle/triage state; baseline
relationship; concise vulnerability narrative; capability/impact;
remediation invariant; safe proof/reproduction; affected revision.

**Affected code/evidence tab:** root-cause changed snippet;
attacker-origin evidence; removed/bypassed control; downstream-trust
evidence; sensitive-effect evidence; exact file/line references.

**Flow tab:** render one of `Explicit flow modeled` or `Control/invariant
proof — no full source-to-sink flow required`. Do not imply that a missing
formal dataflow means weak evidence when the security-control regression
is directly proven.

**Activity tab:** append-only timeline — detected; verification
started/completed; published; triaged; policy changed; remediation
requested; patch generated; fix validation started/completed;
resolved/reopened.

#### Triage commands

Support initial GitHub commands:

```text
!valid [reason]
!fp [reason]
!accepted_risk <reason>
!fixed [reason]
```

Optional later: `!reopen`, `!snooze <duration> <reason>`, `!assign @user`.

**Command processing.** Create a `TriageCommandService`. Input: provider;
repository; review; comment/thread id; finding publication id; author
identity; comment body. Flow:

```text
SCM comment webhook
  -> verify webhook
  -> resolve whether comment belongs to a PlaidNox finding publication
  -> authorize actor
  -> parse first supported command
  -> validate required arguments
  -> acquire idempotency lock/event key
  -> append triage event
  -> transition finding lifecycle
  -> re-evaluate deterministic policy
  -> update inline comment/check/dashboard
```

**Authorization.** Do not allow any repository reader to suppress
findings. For release, configurable accepted actors should be at least:
repository admin/maintainer; configured security reviewer; organization
security admin. Read-only users may add ordinary notes but cannot change
triage state.

**`!valid`.** Effect: `OPEN -> CONFIRMED`. Does not change technical
verification or automatically change blocking policy unless policy
explicitly treats confirmed findings differently.

**`!fp <reason>`.** Effect: `OPEN/CONFIRMED -> FALSE_POSITIVE`. Persist
actor, reason, revision, finding fingerprint, context/prompt/model
versions. Use this as feedback/memory evidence, never as universal
authority for unrelated future findings.

**`!accepted_risk <reason>`.** Effect: `OPEN/CONFIRMED -> ACCEPTED_RISK`.
Require reason. Prefer optional expiry/ticket from dashboard for release
follow-on. Policy engine decides whether an accepted-risk finding is
non-blocking.

**`!fixed`.** Do **not** immediately mark resolved. Effect:
`OPEN/CONFIRMED/FIX_PENDING -> FIX_VALIDATING`. Then: (1) resolve latest
PR HEAD; (2) invalidate/rebuild finding dependencies intersecting the fix;
(3) rerun the minimum verification needed for this root cause; (4) if the
original capability can no longer be established, mark `RESOLVED`;
(5) otherwise keep/reopen the finding with validation evidence. This
prevents comment-based bypass of the merge gate.

**Ordinary triage notes.** Any comment in the finding thread that does not
begin with a recognized triage command can be stored as a triage note. Do
not feed arbitrary human comments directly into security verdict prompts.
Treat them as untrusted contextual evidence with author/provenance.

#### Fix with PlaidNox

Implement remediation as a separate workflow from detection. Suggested
modules:

```text
src/plaidnox_sast/remediation/
    models.py
    service.py
    prompt_context.py
    validator.py
```

**Trigger.** Dashboard/button/SCM link creates a `RemediationRequest`
bound to `finding_id`, `head_revision`, `root_cause_fingerprint`. If HEAD
has changed, require regeneration/rebase against current code.

**Context supplied to remediation model.** Only the minimum required:
finding root cause; remediation invariant; changed source symbol/file;
exact supporting controls/context; relevant tests/test framework if
present; project formatting/style context; explicit instruction not to
modify unrelated code. Do not simply paste the complete repository.

**Remediation prompt contract.** Require the agent to: (1) restate what
security behavior was confirmed; (2) propose the smallest code change
that restores the invariant; (3) add/update a regression test where
practical; (4) avoid adjacent refactors; (5) not weaken security
elsewhere; (6) return a structured patch plan and patch; (7) state any
unresolved assumptions.

**Patch delivery.** For the first release, prefer: `Generate patch -> show
diff -> user approves -> commit/push to PR branch`. Do not silently push
model-generated remediation. Later optional modes: create separate fix
branch; create suggested change; open IDE/developer-agent handoff.

**Fix validation.** A generated patch is not considered successful because
it applies or tests pass. Validation must: (1) rerun source parsing/IR for
changed files; (2) rerun the original finding verifier against the patched
revision; (3) confirm the broken security invariant is restored;
(4) rerun relevant dependent findings/controls; (5) run project regression
tests only in a separate authorized execution environment if that feature
is enabled; (6) keep state `FIX_PENDING/FIX_VALIDATING` until security
revalidation passes.

#### Optional IDE/agent handoff

Support later buttons such as `Open in Cursor`, `Open in Claude Code`,
`Copy remediation prompt`. These should be generated from a redacted
`RemediationHandoff` payload containing: finding ID/title;
repository/path/line; root-cause explanation; remediation invariant; test
expectation; exact allowed edit scope. Do not include platform secrets or
hidden scan context that should not leave PlaidNox.

#### GitHub webhook events required for delivery/triage

In addition to PR lifecycle webhooks, subscribe/handle the events needed
for: check publication/update; issue/PR conversation comments if
top-level triage is supported; pull request review comments for
inline-thread triage; PR synchronize events for fix validation/current
HEAD; PR close/merge for final lifecycle reconciliation.

Every incoming triage webhook goes through the same signature verification
and delivery-ID idempotency handling as scan webhooks.

#### Policy re-evaluation after triage

Never hardcode triage -> merge result:

```text
finding lifecycle transition
  -> load effective compiled policy
  -> deterministic policy evaluation
  -> publish updated check
```

Examples:

```text
FALSE_POSITIVE -> normally non-blocking
ACCEPTED_RISK -> policy determines blocking behavior
CONFIRMED -> may remain blocking
FIX_VALIDATING -> normally not clean yet
RESOLVED -> non-blocking for this finding
```

#### Inline comment update strategy

Do not create a new bot comment for every state change. Persist the
comment ID and update/reply in a bounded way. Recommended presentation:

```text
HIGH  Protected routes accept unsigned JWT claims
Status: Open

...finding summary...

Triage: !valid | !fp <reason> | !accepted_risk <reason> | !fixed
```

After triage:

```text
Status: Accepted risk
By: <actor>
Reason: temporary migration exception
```

Keep detailed audit history in PlaidNox dashboard rather than continuously
expanding the PR comment.

#### Finding rendering contract

Create one structured `FindingPresentation` from `VerifiedFinding`:

```text
FindingPresentation
  title
  severity
  status
  short_description
  impact_summary
  changed_code_location
  reproduction_summary
  remediation_summary
  dashboard_url
  triage_commands
```

Then render it separately for: GitHub inline comment; GitHub check
summary; dashboard; SARIF/JSON; GitLab note later. This prevents content
drift between surfaces.

#### Acceptance criteria for finding delivery

The delivery layer is QC-ready when the JWT benchmark can produce the
following behavior end to end: (1) one PR modifies only
`middleware/ValidateToken.js`; (2) the contextual reviewer verifies the
auth-boundary regression; (3) one canonical High finding is created;
(4) root cause is anchored to the changed `jwt.decode(token)` line;
(5) unchanged manager/report routes remain contextual evidence; (6) a
GitHub inline comment appears on the changed line; (7) the comment
contains title, severity, concise explanation, reproduction steps,
dashboard link, and triage commands; (8) the GitHub `PlaidNox Security`
check shows one blocking High finding; (9) the finding dashboard renders
complete evidence roles; (10) `!valid` changes human-triage state but not
technical verification; (11) unauthorized users cannot suppress the
finding; (12) `!fp reason` records actor/reason/audit and causes
deterministic policy re-evaluation; (13) `!accepted_risk reason` records
the exception and re-evaluates policy; (14) `!fixed` starts revalidation
and cannot directly force RESOLVED; (15) an approved fix restoring
cryptographic verification causes the verifier to close the original
capability and mark the finding RESOLVED; (16) the check updates without
duplicate comments/checks; (17) an obsolete PR HEAD can never overwrite
the current result.

#### Required tests before QC

**Unit:** finding lifecycle transitions; invalid transition rejection;
evidence-role renderer; inline-anchor selection; comment content
redaction; triage command parsing; triage actor authorization;
publication idempotency key; `!fixed` -> FIX_VALIDATING, never direct
RESOLVED; deterministic policy re-evaluation.

**Component:** GitHub comment/check publisher with fake API; duplicate
webhook delivery; existing publication update; stale HEAD publication
rejection; comment command -> DB state -> check update; remediation
request bound to exact HEAD/finding.

**E2E:** JWT regression -> inline High + blocking check; docs-only PR ->
no finding comment; finding located only in unchanged context ->
dashboard/check only, no fake inline anchor; `!fp` by authorized actor ->
audit + policy refresh; `!fp` by unauthorized actor -> ignored/rejected
with note; `!accepted_risk` without reason -> rejected; `!fixed` without
code change -> validation fails, finding stays open; security fix pushed
-> original finding revalidated and resolved; new commit after finding ->
prior publication marked stale/superseded and current HEAD rescanned.

**Privacy/security:** raw secrets never appear in GitHub comment/check;
hidden prompt/system content never appears in remediation handoff;
malicious repository text cannot inject triage commands/publication
templates; arbitrary PR commenters cannot mutate finding state; comment
body cannot inject HTML/script into dashboard rendering.

#### Implementation order

Build in this order:

- **D1 — canonical finding/presentation contracts**: lifecycle enums;
  evidence roles; `FindingPresentation`; migration additions.
- **D2 — GitHub check publisher**: create/update check on HEAD;
  deterministic PASS/WARN/BLOCK/INCOMPLETE mapping; stale HEAD guard.
- **D3 — inline publisher**: changed-line anchor resolver; one comment
  per finding/head; concise renderer; publication persistence/
  idempotency.
- **D4 — dashboard finding detail**: description/evidence/activity;
  control-proof vs explicit-flow representation.
- **D5 — triage webhook + parser**: commands; authorization; audit;
  policy refresh; publication update.
- **D6 — fix validation path**: `!fixed` -> validation job; dependency
  invalidation; minimum verifier rerun; resolve/reopen result.
- **D7 — Fix with PlaidNox**: remediation request; constrained prompt/
  context; diff preview; user approval; optional commit to PR branch;
  security revalidation.
- **D8 — IDE/agent handoff**: Cursor/Claude Code/copy-prompt integrations
  after core remediation is stable.

#### Release principle

The developer-facing experience should be simple:

```text
PR changed code
  -> PlaidNox finds a verified issue
  -> comment exactly where the root cause changed
  -> explain impact using repository context
  -> block according to deterministic policy
  -> let authorized humans triage in place
  -> generate a minimal fix on request
  -> independently prove the security behavior is actually fixed
```

The important invariant is that convenience features never become
alternate security-verdict paths. Detection, publication, triage, policy,
remediation, and fix validation all reference the same versioned
finding/evidence record.

### Initial release scope: ~10 organizations, deliberately small

The first release is sized as a demo/QC-oriented milestone, not the
1,000-org/10K-repo end state — the domain model (tenant/repository/PR/
baseline/finding/policy identity) is built to scale, but the large-scale
infrastructure is deliberately deferred until it is needed. Target sizing:

```text
Organizations           ~10
Repositories            ~50-200
Active PR/MRs/day       <500
Concurrent scans        ~10-20
SCM                     GitHub first, GitLab next adapter
Full white-box          optional/manual only
PR/MR review            primary product
```

Infrastructure for this scope stays boring on purpose:

```text
GitHub App -> Webhook API -> SQS -> ECS Worker Service (3-10 workers)
                                        |
                        +---------------+---------------+
                        v               v               v
                   PostgreSQL         Redis              S3
                (metadata, findings  (locks, HEAD      (Security IR /
                 policies)            state, cache)    scan artifacts)
```

Each ECS worker runs the same local pipeline Code Scanning already has: git
clone/worktree, ripgrep, Tree-sitter, Sensitive Evidence IR, Context Fabric,
JEV, LiteLLM. GitHub-only for the first release, but kept behind the same
`SCMProvider` abstraction (`get_diff`/`get_file`/`get_repository`/
`publish_check`) this section already scopes, so GitLab becomes another
adapter rather than a rewrite.

Deliberately **not** built for the 10-org release: Kafka; multi-region;
multiple Aurora read replicas; a full Kubernetes/EKS deployment; a full
Temporal cluster (plain SQS jobs are sufficient at this scale); per-language
worker fleets; per-customer dedicated infrastructure; automatic scheduled
full white-box scans; capability-chain exploration on every PR by default;
simultaneous GitHub+GitLab+Bitbucket support; a large policy-operator
surface; advanced dashboards. Each of these is an additive step on the scale
path (100 orgs/1K repos adds Temporal, a real scheduler, more ECS pools,
Postgres read scaling, GitLab; 1,000 orgs/10K repos adds a tenant-fair
distributed scheduler, large worker pools, a repo mirror/cache service,
split indexing/hunt fleets, partitioned Postgres, S3 lifecycle policy,
regional ingestion, and a model-quota manager) — the point of building the
domain contracts correctly now is that none of those steps require changing
them.

Non-negotiable reliability rules even at 10-org scale:

- **Idempotency**: `tenant + repository + PR + head SHA` uniquely identifies
  a PR review; a duplicate webhook delivery must never create a second scan.
- **HEAD superseding**: if SHA A is mid-scan and the developer pushes SHA B,
  mark A `SUPERSEDED`; only B may publish the final merge check.
- **Fail closed, not fail open**: an AI crash produces `INCOMPLETE`, never a
  silent `PASS` — policy decides what `INCOMPLETE` means, matching Code
  Scanning's existing `ai_scan_incomplete` invariant.
- **Tenant isolation from day one**: every record, job, S3 key, and cache key
  carries `tenant_id`/`repository_id`; enforced at the data-access boundary,
  not retrofitted later.
- **Per-tenant fair scheduling**: a configurable max-concurrent-scans-per-
  tenant (e.g. 3) prevents one customer's PR burst from starving the others;
  a weighted fair scheduler is a later scale-path addition, not needed yet.
- **No credential values in logs, prompts, or exceptions**, ever — same rule
  already enforced for Code Scanning's Sensitive Evidence IR.

Suggested implementation sequencing for this workstream, once Code Scanning's
own exit condition is met and this workstream is actually started (per this
file's Boundary rule and Delivery order — SCM Integration is item 2, after
Code Scanning):

- P0: GitHub webhook models + signature verification; PR/MR job + HEAD
  coalescing; repository bootstrap; baseline store/load; incremental Security
  IR; impact expansion; Sensitive Evidence IR; PR contextual hunter; baseline
  comparison; policy compiler runtime; deterministic policy evaluator;
  GitHub Check publisher.
- P1: JEV PR-routing refinements; GitLab adapter; capability-chain expansion
  in the PR context; manual full white-box trigger.
- P2: larger-scale scheduler (the 100-org/1,000-org scale path above).

Metrics to capture from the first release (feeds the scale-path decisions
above rather than guessing at them): PR scans, PRs blocked/warned, verified
findings, candidate-to-verified ratio, false-positive feedback, scan latency,
queue wait latency, model calls/PR, tokens/PR, tokens/verified finding,
FAST/STANDARD/DEEP routing mix, context-expansion rounds, baseline cache hit
rate, Security IR reuse rate, superseded-scan count, AI failures, incomplete
scans, credential detections, and policy decisions.

## 3. Dependency Scanning (SCA) and SBOM

Scope:

- complete manifest/lockfile and artifact inventory across ecosystems;
- direct/transitive dependency paths and vulnerable-function reachability;
- OS and language packages, vendored code, containers, and SBOM ingestion;
- OSV/CVE/advisory correlation, VEX, exploit maturity, EPSS, and fix versions;
- CycloneDX and SPDX generation/import/export;
- upgrade suggestions, breaking-change intelligence, and fix verification;
- later CI/SCM integration through the SCM service.

Open-source foundations to evaluate behind adapters:

- OSV-Scanner and OSV.dev for ecosystem advisories, lockfiles, call analysis,
  license data, and guided remediation;
- Syft for package cataloguing and CycloneDX/SPDX SBOM generation;
- Grype and Trivy as independent vulnerability matchers;
- deps.dev for package/dependency metadata;
- cdxgen for additional ecosystem SBOM coverage.

Multiple matchers retain their provenance; PlaidNox must not merge conflicting
package identity assumptions into one unexplained result. Reachability uses the
Code Intelligence graph through a versioned interface, while SCA retains its own
schema and verdict.

## 4. Secrets Detection

Scope:

- working-tree, history, pre-commit, CI, and artifact scanning;
- structured and entropy-based detection with provider-specific validation;
- secret liveness checks through allowlisted, non-destructive provider adapters;
- revocation/rotation guidance and occurrence grouping;
- pre-commit blocking that never sends secret values to an LLM.

Open-source foundations:

- Gitleaks for configurable Git/source rules and pre-commit/CI scanning;
- TruffleHog for verified-provider detectors and history scanning;
- detect-secrets for baseline-oriented developer workflows.

Raw values are encrypted only when a short-lived liveness worker requires them;
reports, prompts, logs, and normal persistence contain fingerprints and redacted
evidence only.

## 5. Outdated Software and upgrade intelligence

Scope:

- current/latest/secure/EOL/approved-baseline versions;
- release age, maintenance state, deprecations, breaking API changes, and risk;
- Renovate-style update planning and OpenRewrite-style source transformations;
- test/build results from isolated execution workers;
- AI explanation and repair only after deterministic version and build evidence.

Open-source foundations:

- Renovate for update discovery and policy-driven proposal generation;
- OpenRewrite for structured source/build migrations;
- ecosystem package managers and release APIs;
- endoflife.date data where licensing and provenance are acceptable.

This is separate from SCA: software can be outdated without a known CVE, and an
SCA remediation may not be the newest available version.

## 6. IaC, container, VM, and Cloud Security

Scope:

- Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, and configuration
  misconfiguration analysis;
- container image, host/VM, Kubernetes cluster, and cloud-account posture;
- CSPM asset inventory, relationships, exposure, identity, network, data, and
  attack-path graph queries;
- drift between IaC intent and deployed state;
- cloud-specific remediation with evidence and account/region provenance.

Open-source foundations:

- Trivy, Checkov, and KICS behind normalized IaC adapters;
- Prowler for AWS/Azure/GCP posture and compliance evidence;
- Steampipe and/or CloudQuery for asset inventory and graph/query ingestion;
- kube-bench and kube-hunter for Kubernetes-specific evidence;
- Syft/Grype/Trivy for container and VM package inventory.

Cloud credentials are short-lived and scoped to read-only collection. Cloud
workers and data use a separate trust boundary from source-code workers.

## 7. License Risk

Scope:

- declared and detected licenses, SPDX expressions, copyrights, and notices;
- direct/transitive policy, copyleft/network-copyleft obligations, exceptions,
  source-availability requirements, and unknown-license review;
- SBOM-linked attribution and notice bundle generation;
- policy by product, distribution model, organization, and deployment context.

Open-source foundations:

- OSS Review Toolkit for scanner/advisor/evaluator/report workflows;
- ScanCode Toolkit for license and copyright detection;
- FOSSology for deeper review and clearing workflows;
- OSV-Scanner/Trivy license signals as additional attributed evidence.

Legal conclusions require organization policy and human review; classifier
output remains evidence, not an automatic license conclusion.

## 8. DAST

Scope:

- API and browser discovery, authenticated sessions, OpenAPI/GraphQL inputs;
- passive and active checks, safe scan policies, request/response evidence;
- staging-target ownership validation, rate limits, test data, and egress policy;
- source correlation through stable endpoint identifiers after both products are
  mature.

Open-source foundations:

- OWASP ZAP Automation Framework for repeatable passive/active plans;
- Nuclei for signed/versioned templates and narrowly scoped checks;
- Schemathesis for property-based OpenAPI/GraphQL API testing;
- testssl.sh for TLS configuration evidence.

DAST requires explicit target authorization and an execution environment. It is
never embedded inside the read-only Code Scanning worker.

## 9. IDE Plugins

Scope:

- VS Code, JetBrains, and a generic Language Server Protocol client;
- local changed-file Code Scanning, secret pre-checks, and server result sync;
- evidence, suppression, remediation preview, and policy explanations;
- no long-lived provider or cloud credentials in the editor.

Build a shared LSP/backend protocol first, then thin editor clients. IDE release
cycles and telemetry remain independent from scanner releases.

## Cross-product PostgreSQL rule

Each workstream owns a separate table prefix or PostgreSQL schema. Shared asset
identity is referenced through stable IDs and events, not cross-product write
access. Initial namespaces:

```text
code_scanning_*
scm_*
sca_*
secrets_*
software_*
cloud_*
license_*
dast_*
ide_*
```

The Code Scanning migration must never create the deferred namespaces.
