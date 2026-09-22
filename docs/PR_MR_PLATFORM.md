# PlaidNox PR/MR Security Platform

## Purpose

PlaidNox PR/MR Security is the default continuous-review mode for large deployments. It is intentionally separate from the expensive full white-box deep-hunt workflow.

The design target is approximately:

- 1,000 tenant organizations
- 10,000 connected repositories
- bursty pull-request / merge-request traffic
- tenant-fair execution
- merge-blocking policy decisions
- incremental code/security understanding
- optional full white-box review when requested or risk-triggered

A repository must be understood before contextual PR/MR review, but it does not need an exhaustive whole-repository vulnerability hunt first. The initial operation is a lightweight, mostly deterministic bootstrap that builds a reusable Repository Security Index.

## Product modes

### PR/MR Security

Continuous and change-focused:

1. repository bootstrap / security indexing;
2. diff ingestion;
3. incremental Security IR update;
4. impact expansion around changed symbols;
5. secret / sensitive-configuration review;
6. contextual AI hunting on the affected surface;
7. independent verification;
8. capability expansion when a verified primitive creates a meaningful new security surface;
9. baseline comparison (new / regressed / existing);
10. deterministic policy evaluation;
11. PASS / WARN / BLOCK / REQUIRE_APPROVAL publication back to SCM.

### Full white-box deep hunt

Optional or risk-triggered:

- exhaustive repository/app reconnaissance;
- whole-surface vulnerability discovery;
- variant sweeping;
- attack-capability chaining;
- complete report generation.

PR/MR Security must not require a full white-box scan before it can block newly introduced risk.

## Repository bootstrap

The bootstrap is understanding, not a pentest.

Build and persist a redacted Repository Security Index containing:

- file/content hashes;
- languages and frameworks;
- symbols and stable symbol identities;
- imports and call/reference relationships;
- routes and entry points;
- authentication and authorization locations;
- sensitive effects;
- data stores and writer/reader relationships;
- trust-boundary hints;
- business/security context learned over time;
- environment/configuration metadata;
- sensitive-evidence metadata and credential fingerprints (never raw values);
- prior findings and finding dependencies;
- capability/security-context records;
- coverage state.

Raw source may be cloned/materialized ephemerally. Long-lived raw-source retention is not a requirement for the platform.

## PR/MR review algorithm

Given baseline revision B and proposed revision H:

1. compute B..H changes;
2. identify changed files and changed symbols;
3. update only affected Security IR nodes;
4. compute impact surface from changed symbols;
5. include relevant callers, callees, wrappers, middleware, auth/authz controls, store readers/writers, sensitive effects, trust boundaries, and selected configuration;
6. run deterministic secret/configuration checks;
7. use JEV to choose analysis depth and missing evidence classes;
8. run forward, sink-backward, and boundary/state hunting against the affected surface;
9. independently verify candidates;
10. derive attacker capabilities and inspect meaningful newly reachable security boundaries;
11. classify findings relative to the baseline;
12. apply policy deterministically;
13. publish one SCM check and a bounded set of actionable annotations;
14. after merge, update the baseline incrementally.

Review is diff-triggered but not diff-only.

## Finding relationship to baseline

Every PR/MR finding must be classified as one of:

- `introduced`: new in the proposed revision;
- `regressed`: previously fixed/suppressed behavior has returned;
- `modified_existing`: an existing finding is materially affected by the change;
- `existing`: unchanged pre-existing risk;
- `resolved`: baseline finding is removed by the change.

Default merge policy should generally evaluate introduced, regressed, and materially modified findings rather than blocking unrelated changes on historical debt.

## Review depth

Internal execution levels:

- L0 deterministic: diff, Security IR update, sensitive evidence, configuration, cheap rules;
- L1 contextual AI review: affected code/security surface;
- L2 deep review: stateful/auth/business logic, cross-file investigation, capability expansion, external semantics as needed;
- L3 full white-box: whole application/repository.

JEV routes work between L0/L1/L2 and decides which evidence class is missing. JEV must never make the final vulnerability or merge decision.

## Natural-language policy

Administrators configure policy in plain English, for example:

> Block pull requests targeting main or release branches when they introduce a verified High or Critical vulnerability. Always block real production credentials. Medium authentication or authorization findings require security approval.

The platform compiles this once into a strict typed policy document. The compiled document is validated and versioned. PR/MR evaluation is deterministic and does not invoke an LLM to decide whether a merge is allowed.

Policy dimensions may include:

- repository and branch scope;
- new/regressed/existing status;
- verification status;
- severity and confidence;
- security boundary;
- attacker capability;
- asset/workflow/environment;
- credential exposure state;
- coverage state;
- required approval type;
- exceptions with owner/reason/expiry/ticket.

Policy actions:

- allow;
- warn;
- block;
- require_security_approval;
- require_owner_approval;
- require_manual_review;
- notify.

Policy inheritance:

PlaidNox default -> tenant -> SCM organization/group -> repository class -> repository -> branch.

## 1,000-org / 10,000-repo infrastructure

### Control plane

- API Gateway or ALB for webhook/API ingress;
- webhook ingestion service with SCM signature verification;
- tenant/repository registry;
- GitHub App / GitLab integration token broker;
- policy service and policy compiler;
- scheduler/workflow coordinator (Temporal or equivalent);
- PostgreSQL/Aurora for tenant, repository, scan, policy, finding, and audit metadata;
- Redis for hot locks, dedupe, effective-policy cache, current HEAD, and short-lived workflow state;
- S3/object storage for redacted Security IR/context artifacts and immutable scan outputs;
- KMS-backed encryption for integration credentials and sensitive platform state.

### Event and worker plane

Prefer SQS/EventBridge-style queues initially over Kafka. Required properties are durability, retries, priority, cancellation, dedupe, and tenant fairness rather than very high stream throughput.

Suggested queues:

- P0 `pr_blocking`: active PR/MR checks;
- P1 `pr_deep`: deep expansions and expensive verification;
- P2 `baseline_sync`: accepted merges/default-branch updates;
- P3 `bootstrap_full`: initial indexing and baseline rebuilds;
- P4 `maintenance`: reconciliation, historical work, reporting.

Separate worker pools prevent scheduled/full work from starving developer-facing PR checks.

### Tenant fairness

Use weighted fair scheduling plus per-tenant concurrency/token limits. One organization with a large burst must not consume all worker/model capacity.

Recommended scheduling identity:

`tenant_id + scm_provider + repository_id + pull_request_id`

A newer HEAD supersedes older work for the same review. Obsolete workflows should be cancelled before expensive model stages.

### Baseline/cache design

Persist derived understanding, not necessarily raw code:

- content-addressed file metadata;
- Security IR keyed by file hash + parser/index version;
- stable symbol graph;
- finding dependencies;
- repository security context;
- sensitive-evidence fingerprints only;
- prompt/model-result caches keyed by sanitized context hash + workflow/prompt/model version.

Ephemeral workers materialize only the base/head source required for analysis and destroy the working directory after the scan.

### Scale behavior

Ten thousand connected repositories do not imply ten thousand concurrent AI scans. Idle repositories consume storage/index maintenance only. AI spend follows active changes.

Coalesce bursty pushes: if a PR receives several HEAD revisions while an earlier scan is running, only the latest relevant HEAD should reach expensive AI stages.

### SCM publication

GitHub:

- GitHub App;
- Checks API/status check named e.g. `PlaidNox Security`;
- branch protection/ruleset requires that check;
- one summary plus bounded inline annotations;
- merge-queue events supported.

GitLab:

- group/project integration and MR webhooks;
- pipeline/security job or external status mechanism;
- merge checks/approval policy consume the deterministic PlaidNox outcome.

## When to escalate to L3 / rebuild

A full or application-level rebuild may be triggered by deterministic and JEV-assisted signals such as:

- no usable baseline;
- parser/index major-version change;
- large percentage of application code changed;
- authentication provider/framework replacement;
- new internet-facing application/service;
- new payment/admin/high-value workflow;
- major cloud/IAM integration change;
- significant unresolved coverage degradation;
- graph integrity failure;
- customer-requested deep assessment.

Prefer application-level rebuilds in monorepos instead of whole-repository rebuilds where possible.

## Security invariants

- The AI can discover and verify findings; it cannot directly authorize a merge.
- Policy compilation can use AI/JEV, but stored policy evaluation is deterministic.
- Raw credentials are never persisted in findings or sent to external models/JEV.
- Unknown evidence remains unknown; it is never converted into a clean result.
- Historical findings should not normally block unrelated PRs unless policy explicitly says so.
- Every published status is bound to the current PR/MR HEAD revision.
