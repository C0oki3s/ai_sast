# PlaidNox PR/MR Security — Finding Delivery, Triage, and Remediation Plan

## 1. Goal

This document specifies the implementation required after PR/MR analysis produces a verified finding. The target developer experience is:

1. the PR/MR scan reaches a verified finding;
2. PlaidNox publishes a HEAD-bound merge check;
3. the finding is anchored to the changed root-cause line when possible;
4. the inline comment contains a concise explanation and safe reproduction guidance;
5. the dashboard exposes the complete finding/evidence record;
6. developers can triage from the PR comment using controlled commands;
7. triage immediately updates the finding lifecycle and merge policy result;
8. developers can request an AI-generated fix that is constrained to the finding root cause;
9. the fix is independently revalidated before PlaidNox calls it resolved.

The scanner, GitHub publisher, dashboard, triage parser, and remediation agent must not maintain separate security verdicts. They operate on one canonical verified-finding record.

## 2. Canonical finding object

Introduce or extend a provider-neutral `VerifiedFinding`/`ReviewFinding` model with the following logical fields.

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

Do not store GitHub comment IDs or GitLab note IDs directly in the core finding object. SCM publication records belong to a provider integration table.

## 3. Finding lifecycle

Use an explicit state machine.

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

- `VERIFIED` means PlaidNox has enough evidence to support the vulnerability claim.
- `CONFIRMED` is human triage acknowledgement, not a second technical proof.
- `FALSE_POSITIVE` requires actor, timestamp, optional reason, and audit history.
- `ACCEPTED_RISK` requires actor, reason, scope, and preferably expiry/ticket.
- `RESOLVED` cannot be set only because somebody writes `!fixed`; it requires fix validation against a new revision or explicit authorized override.
- every state transition is append-only in audit history.

## 4. Evidence roles used for delivery

Every finding should render evidence by role instead of one undifferentiated dataflow.

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

For a PR finding, the primary inline anchor is `ROOT_CAUSE_CHANGED_CODE` when the root cause is on a changed line.

Unchanged files may be referenced in the description/dashboard as contextual evidence but should not generate fake inline comments on unrelated changed lines.

## 5. GitHub publication architecture

Create a provider-specific publisher outside Code Scanning core.

Suggested modules:

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

The GitHub implementation owns Checks API/review comments. The security engine does not call GitHub directly.

## 6. GitHub Check behavior

Use one canonical check name:

```text
PlaidNox Security
```

Create/update the check against the exact PR HEAD SHA.

Suggested mapping:

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

Before every final publication:

1. read current PR HEAD;
2. compare with `review.head_revision`;
3. if different, mark current attempt superseded;
4. do not publish its PASS/BLOCK as current.

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

The check is the merge-gating primitive. Inline comments are developer guidance, not the source of merge policy truth.

## 7. Inline PR finding comment

### 7.1 When to create an inline comment

Create one when:

- the finding is verified;
- root cause is attributable to the PR;
- the root-cause path is a changed file;
- the selected root-cause line is present on the RIGHT/new side of the diff;
- the publication has not already been created for this finding fingerprint + HEAD.

Otherwise publish the finding only in the check summary/dashboard and optionally one top-level PR summary.

### 7.2 Comment content

Use a compact top section followed by expandable detail where supported.

Recommended rendering:

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

Keep the inline comment shorter than the dashboard finding. Do not paste every contextual source file into GitHub.

### 7.3 Safe reproduction

The verifier can generate reproduction steps/code for an authorized test target, but publishing logic must:

- avoid embedding secrets/tokens copied from the repository;
- use placeholders for target hosts and credentials;
- not automatically execute the proof against external infrastructure;
- distinguish static proof from runtime-validated proof;
- redact sensitive configuration before rendering.

## 8. Publication persistence

Add SCM-owned persistence tables/entities such as:

```text
review_publications
finding_publications
triage_events
remediation_requests
remediation_attempts
```

### `finding_publications`

Minimum fields:

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

## 9. Dashboard finding page

The finding page should render the canonical finding rather than scrape the GitHub comment.

Tabs/sections:

### Description

- title;
- severity;
- lifecycle/triage state;
- baseline relationship;
- concise vulnerability narrative;
- capability/impact;
- remediation invariant;
- safe proof/reproduction;
- affected revision.

### Affected code/evidence

- root-cause changed snippet;
- attacker-origin evidence;
- removed/bypassed control;
- downstream-trust evidence;
- sensitive-effect evidence;
- exact file/line references.

### Flow

Render one of:

```text
Explicit flow modeled
```

or:

```text
Control/invariant proof — no full source-to-sink flow required
```

Do not imply that a missing formal dataflow means weak evidence when the security-control regression is directly proven.

### Activity

Append-only timeline:

- detected;
- verification started/completed;
- published;
- triaged;
- policy changed;
- remediation requested;
- patch generated;
- fix validation started/completed;
- resolved/reopened.

## 10. Triage commands

Support initial GitHub commands:

```text
!valid [reason]
!fp [reason]
!accepted_risk <reason>
!fixed [reason]
```

Optional later:

```text
!reopen
!snooze <duration> <reason>
!assign @user
```

### 10.1 Command processing

Create a `TriageCommandService`.

Input:

```text
provider
repository
review
comment/thread id
finding publication id
author identity
comment body
```

Flow:

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

### 10.2 Authorization

Do not allow any repository reader to suppress findings.

For release, configurable accepted actors should be at least:

- repository admin/maintainer;
- configured security reviewer;
- organization security admin.

Read-only users may add ordinary notes but cannot change triage state.

### 10.3 `!valid`

Effect:

```text
OPEN -> CONFIRMED
```

Does not change technical verification or automatically change blocking policy unless policy explicitly treats confirmed findings differently.

### 10.4 `!fp <reason>`

Effect:

```text
OPEN/CONFIRMED -> FALSE_POSITIVE
```

Persist:

```text
actor
reason
revision
finding fingerprint
context/prompt/model versions
```

Use this as feedback/memory evidence, never as universal authority for unrelated future findings.

### 10.5 `!accepted_risk <reason>`

Effect:

```text
OPEN/CONFIRMED -> ACCEPTED_RISK
```

Require reason. Prefer optional expiry/ticket from dashboard for release follow-on.

Policy engine decides whether an accepted-risk finding is non-blocking.

### 10.6 `!fixed`

Do **not** immediately mark resolved.

Effect:

```text
OPEN/CONFIRMED/FIX_PENDING -> FIX_VALIDATING
```

Then:

1. resolve latest PR HEAD;
2. invalidate/rebuild finding dependencies intersecting the fix;
3. rerun the minimum verification needed for this root cause;
4. if the original capability can no longer be established, mark `RESOLVED`;
5. otherwise keep/reopen the finding with validation evidence.

This prevents comment-based bypass of the merge gate.

## 11. Ordinary triage notes

Any comment in the finding thread that does not begin with a recognized triage command can be stored as a triage note.

Do not feed arbitrary human comments directly into security verdict prompts. Treat them as untrusted contextual evidence with author/provenance.

## 12. Fix with PlaidNox

Implement remediation as a separate workflow from detection.

Suggested modules:

```text
src/plaidnox_sast/remediation/
    models.py
    service.py
    prompt_context.py
    validator.py
```

### 12.1 Trigger

Dashboard/button/SCM link creates:

```text
RemediationRequest
```

bound to:

```text
finding_id
head_revision
root_cause_fingerprint
```

If HEAD has changed, require regeneration/rebase against current code.

### 12.2 Context supplied to remediation model

Only the minimum required:

- finding root cause;
- remediation invariant;
- changed source symbol/file;
- exact supporting controls/context;
- relevant tests/test framework if present;
- project formatting/style context;
- explicit instruction not to modify unrelated code.

Do not simply paste the complete repository.

### 12.3 Remediation prompt contract

Require the agent to:

1. restate what security behavior was confirmed;
2. propose the smallest code change that restores the invariant;
3. add/update a regression test where practical;
4. avoid adjacent refactors;
5. not weaken security elsewhere;
6. return a structured patch plan and patch;
7. state any unresolved assumptions.

### 12.4 Patch delivery

For the first release, prefer:

```text
Generate patch -> show diff -> user approves -> commit/push to PR branch
```

Do not silently push model-generated remediation.

Later optional modes:

- create separate fix branch;
- create suggested change;
- open IDE/developer-agent handoff.

### 12.5 Fix validation

A generated patch is not considered successful because it applies or tests pass.

Validation must:

1. rerun source parsing/IR for changed files;
2. rerun the original finding verifier against the patched revision;
3. confirm the broken security invariant is restored;
4. rerun relevant dependent findings/controls;
5. run project regression tests only in a separate authorized execution environment if that feature is enabled;
6. keep state `FIX_PENDING/FIX_VALIDATING` until security revalidation passes.

## 13. Optional IDE/agent handoff

Support later buttons such as:

```text
Open in Cursor
Open in Claude Code
Copy remediation prompt
```

These should be generated from a redacted `RemediationHandoff` payload containing:

- finding ID/title;
- repository/path/line;
- root-cause explanation;
- remediation invariant;
- test expectation;
- exact allowed edit scope.

Do not include platform secrets or hidden scan context that should not leave PlaidNox.

## 14. GitHub webhook events required for delivery/triage

In addition to PR lifecycle webhooks, subscribe/handle the events needed for:

- check publication/update;
- issue/PR conversation comments if top-level triage is supported;
- pull request review comments for inline-thread triage;
- PR synchronize events for fix validation/current HEAD;
- PR close/merge for final lifecycle reconciliation.

Every incoming triage webhook goes through the same signature verification and delivery-ID idempotency handling as scan webhooks.

## 15. Policy re-evaluation after triage

Never hardcode triage -> merge result.

Flow:

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

## 16. Inline comment update strategy

Do not create a new bot comment for every state change.

Persist the comment ID and update/reply in a bounded way.

Recommended presentation:

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

Keep detailed audit history in PlaidNox dashboard rather than continuously expanding the PR comment.

## 17. Finding rendering contract

Create one structured `FindingPresentation` from `VerifiedFinding`.

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

Then render it separately for:

- GitHub inline comment;
- GitHub check summary;
- dashboard;
- SARIF/JSON;
- GitLab note later.

This prevents content drift between surfaces.

## 18. Acceptance criteria for finding delivery

The delivery layer is QC-ready when the JWT benchmark can produce the following behavior end to end:

1. one PR modifies only `middleware/ValidateToken.js`;
2. the contextual reviewer verifies the auth-boundary regression;
3. one canonical High finding is created;
4. root cause is anchored to the changed `jwt.decode(token)` line;
5. unchanged manager/report routes remain contextual evidence;
6. a GitHub inline comment appears on the changed line;
7. the comment contains title, severity, concise explanation, reproduction steps, dashboard link, and triage commands;
8. the GitHub `PlaidNox Security` check shows one blocking High finding;
9. the finding dashboard renders complete evidence roles;
10. `!valid` changes human-triage state but not technical verification;
11. unauthorized users cannot suppress the finding;
12. `!fp reason` records actor/reason/audit and causes deterministic policy re-evaluation;
13. `!accepted_risk reason` records the exception and re-evaluates policy;
14. `!fixed` starts revalidation and cannot directly force RESOLVED;
15. an approved fix restoring cryptographic verification causes the verifier to close the original capability and mark the finding RESOLVED;
16. the check updates without duplicate comments/checks;
17. an obsolete PR HEAD can never overwrite the current result.

## 19. Required tests before QC

### Unit

- finding lifecycle transitions;
- invalid transition rejection;
- evidence-role renderer;
- inline-anchor selection;
- comment content redaction;
- triage command parsing;
- triage actor authorization;
- publication idempotency key;
- `!fixed` -> FIX_VALIDATING, never direct RESOLVED;
- deterministic policy re-evaluation.

### Component

- GitHub comment/check publisher with fake API;
- duplicate webhook delivery;
- existing publication update;
- stale HEAD publication rejection;
- comment command -> DB state -> check update;
- remediation request bound to exact HEAD/finding.

### E2E

- JWT regression -> inline High + blocking check;
- docs-only PR -> no finding comment;
- finding located only in unchanged context -> dashboard/check only, no fake inline anchor;
- `!fp` by authorized actor -> audit + policy refresh;
- `!fp` by unauthorized actor -> ignored/rejected with note;
- `!accepted_risk` without reason -> rejected;
- `!fixed` without code change -> validation fails, finding stays open;
- security fix pushed -> original finding revalidated and resolved;
- new commit after finding -> prior publication marked stale/superseded and current HEAD rescanned.

### Privacy/security

- raw secrets never appear in GitHub comment/check;
- hidden prompt/system content never appears in remediation handoff;
- malicious repository text cannot inject triage commands/publication templates;
- arbitrary PR commenters cannot mutate finding state;
- comment body cannot inject HTML/script into dashboard rendering.

## 20. Implementation order

Build in this order:

### D1 — canonical finding/presentation contracts

- lifecycle enums;
- evidence roles;
- `FindingPresentation`;
- migration additions.

### D2 — GitHub check publisher

- create/update check on HEAD;
- deterministic PASS/WARN/BLOCK/INCOMPLETE mapping;
- stale HEAD guard.

### D3 — inline publisher

- changed-line anchor resolver;
- one comment per finding/head;
- concise renderer;
- publication persistence/idempotency.

### D4 — dashboard finding detail

- description/evidence/activity;
- control-proof vs explicit-flow representation.

### D5 — triage webhook + parser

- commands;
- authorization;
- audit;
- policy refresh;
- publication update.

### D6 — fix validation path

- `!fixed` -> validation job;
- dependency invalidation;
- minimum verifier rerun;
- resolve/reopen result.

### D7 — Fix with PlaidNox

- remediation request;
- constrained prompt/context;
- diff preview;
- user approval;
- optional commit to PR branch;
- security revalidation.

### D8 — IDE/agent handoff

- Cursor/Claude Code/copy-prompt integrations after core remediation is stable.

## 21. Release principle

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

The important invariant is that convenience features never become alternate security-verdict paths. Detection, publication, triage, policy, remediation, and fix validation all reference the same versioned finding/evidence record.
