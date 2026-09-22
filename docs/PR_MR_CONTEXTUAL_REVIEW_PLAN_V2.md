# PlaidNox PR/MR Security — Contextual Review Plan v2

## Benchmark-derived design change

The `C0oki3s/NSTCTF` PR benchmark showed that a useful PR reviewer can identify a real authentication regression from one modified security-critical file without first constructing a complete source-to-sink dataflow graph.

Observed behavior:

- one file changed: `middleware/ValidateToken.js`;
- baseline behavior used `verifier.verify(token)`;
- PR changed it to `jwt.decode(token)`;
- the scanner understood that the middleware protected downstream routes;
- it produced a High finding for unsigned attacker-controlled JWT claims;
- it connected forged claims to the manager-only report path and trusted server-side effects;
- its finding UI explicitly stated that no traceable data flow had been modeled.

The correct default for PlaidNox PR/MR review is therefore:

> changed-file-first, context-rich, and expansion-on-demand.

Do not rebuild or traverse the whole affected graph before every AI review.

## 1. Revised pipeline

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

## 2. Four context layers

### Layer 0 — PR delta

Always available:

- changed files;
- changed line ranges;
- changed symbols;
- added/deleted symbols;
- changed imports/calls;
- changed config/sensitive evidence.

### Layer 1 — cached ApplicationContext

Persist and reuse:

- application/runtime type;
- entry points;
- components;
- auth/authz/security controls;
- important routes/workflows;
- stores and sensitive effects;
- environment/configuration metadata;
- identity provider;
- prior findings and dependencies;
- context confidence/version.

### Layer 2 — changed-file local context

For each changed file/symbol:

- containing function/class;
- neighboring security logic;
- imports;
- same-file definitions/references;
- local control flow;
- baseline security role.

### Layer 3 — on-demand expansion

Only when a candidate or verifier needs it:

- callers/callees;
- route registrations;
- middleware relationships;
- authz/tenant/ownership checks;
- readers/writers;
- state transitions;
- explicit flow slices;
- framework/provider semantics;
- environment evidence.

## 3. Deterministic change-relevance gate

Add a pre-AI `ChangeRelevance` stage.

Suggested fields:

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

### Fast exit

If only documentation/non-runtime assets changed and no security/config/sensitive relationships are affected:

```text
diff
  -> relevance = non-security
  -> L0 complete
  -> policy
  -> PASS/WARN
```

No generative review is required.

### Mandatory escalation examples

Escalate when changes intersect:

- authentication;
- authorization/tenancy/ownership;
- identity/session/token handling;
- routes/controllers/middleware;
- data readers/writers;
- file/network/process/cloud effects;
- security configuration;
- signing/crypto;
- credentials/secrets;
- admin/payment/high-value workflows;
- state transitions/concurrency;
- prior finding dependencies.

Use Security IR roles and baseline relationships, not filenames alone.

## 4. Changed-file-first AI review

For each security-relevant changed file:

1. load the diff;
2. load the complete changed symbol or bounded source context;
3. load that symbol/file's baseline security role;
4. load compact ApplicationContext;
5. load directly linked prior controls/findings;
6. ask the hunter whether the change breaks a security invariant or creates a new attacker capability.

The normal L1 model input should be changed code plus compact context, not broad repository source.

## 5. Candidate schema should be lean

Discovery should produce hypotheses rather than final findings.

Suggested fields:

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

Do not assign final CWE, severity, remediation, or merge action during candidate discovery.

## 6. Evidence-on-demand

The verifier decides what extra context is needed.

### Example: JWT verification removal

Changed code plus cached context may already prove:

```text
attacker-controlled bearer/cookie token
  -> decode-only parsing
  -> no authenticity validation
  -> claims become req.user
  -> auth middleware is trusted by protected routes
```

The verifier may request only:

- the manager-only gate;
- representative protected routes;
- downstream use of the identity claims.

A full call graph/dataflow reconstruction is unnecessary if those facts are sufficient.

### Example: stored second-order issue

The verifier may require:

```text
writer -> store -> later reader -> sensitive effect
```

In that case explicit flow/state evidence is required.

## 7. Formal dataflow is optional, not universally required

Do not require a source-to-sink graph for every PR finding.

Control/invariant regressions can be proven by:

```text
untrusted input
  -> security control removed/weakened
  -> trusted identity/state created
  -> downstream code trusts that state
```

Examples:

- JWT signature verification removed;
- authorization guard deleted;
- tenant ownership binding removed;
- permission condition inverted;
- CSRF/security flag disabled;
- signing/encryption requirement weakened.

When propagation across multiple functions/stores is essential to the claim, explicit flow evidence must be requested. Missing required flow remains an evidence gap, never proof of safety.

## 8. Evidence roles

Every verified finding should distinguish changed root cause from contextual impact.

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

The primary affected file remains the changed file. Unchanged files/routes can appear as contextual evidence.

## 9. Revised JEV role

Run JEV only after deterministic relevance classification.

Recommended questions:

```text
analysis_depth: FAST | STANDARD | DEEP
needs_cross_file: YES | NO
needs_control_relationships: YES | NO
needs_state_reconstruction: YES | NO
needs_explicit_flow: YES | NO
needs_external_semantics: YES | NO
needs_environment_context: YES | NO
```

JEV must not decide vulnerability validity, severity, CWE, merge outcome, or whether missing evidence may be ignored.

## 10. Review levels

### L0 — deterministic delta review

Always run:

- diff;
- changed-file classification;
- incremental IR update;
- sensitive evidence;
- configuration changes;
- prior finding invalidation;
- cached context lookup.

### L1 — changed-file contextual hunt

Default AI mode for security-relevant code:

```text
changed code
+
compact ApplicationContext
+
local Security IR
+
relevant baseline relationships
```

### L2 — evidence expansion + deep verification

Only when required:

- callers/callees;
- routes;
- controls;
- readers/writers;
- state reconstruction;
- explicit flow;
- external semantics;
- environment evidence.

### L3 — full white-box

Separate product path. Not required for normal PR/MR review.

## 11. Baseline classification

Verified findings remain classified as:

```text
INTRODUCED
REGRESSED
MODIFIED_EXISTING
EXISTING
RESOLVED
```

For PR review, direct modification of the root-cause symbol is strong evidence for `INTRODUCED` or `REGRESSED`.

Existing unrelated debt must not block by default.

## 12. Counters and UI semantics

Track separately:

```text
Candidates generated
Evaluated
Verified
Rejected
Unresolved
In triage
Blocking
Existing
```

Definitions:

- Candidates generated: hypotheses created from changed code/context;
- Evaluated: verifier attempt completed;
- Verified: vulnerability supported;
- Rejected: falsified or required gates failed;
- Unresolved: evidence missing/incomplete;
- In triage: verified finding awaiting disposition;
- Blocking: verified finding matched blocking policy;
- Existing: baseline issue not introduced by this PR.

`0 Verified` is not equivalent to a complete clean result if unresolved coverage remains.

## 13. Live timeline

Suggested stages:

```text
Preparing workspace
Repository ready
Application context loaded
Changed files analyzed
Security relevance evaluated
Reviewing changed security surface
Verifying candidates
Comparing baseline
Evaluating policy
Publishing result
```

When no baseline exists, show:

```text
Building initial repository security index
```

Show `Skipped` for stages that do not run.

## 14. Sensitive evidence in PR mode

Inspect changed/new sensitive files locally and reuse fingerprints for unchanged sensitive material.

If changed code newly consumes an unchanged credential/config item, treat that relationship as affected.

Raw secret values must never enter model/JEV payloads, findings, logs, Redis, S3, or reports.

## 15. Caching strategy

Persist/reuse:

- ApplicationContext;
- Security IR;
- file hashes;
- stable symbols;
- security-control relationships;
- route/control associations;
- store relationships;
- finding dependencies;
- sensitive-evidence fingerprints;
- model-independent repository context.

Raw source can remain ephemeral.

## 16. When broad expansion is justified

Use broad affected-surface reconstruction for cases such as:

- shared security helper changed with many callers;
- auth/authz framework replacement;
- routing/middleware registration changes;
- persistence/workflow schema changes;
- new service/application;
- large architecture diff;
- graph/context integrity mismatch;
- candidate has several unresolved hops;
- baseline context confidence is too low.

Prefer application/component-level expansion before whole-repository reconstruction.

## 17. Required QC fixtures from this benchmark

### Fixture A — documentation-only PR

Expected:

- changed file analyzed;
- cached application context reused;
- zero candidates;
- AI hunt skipped;
- PASS unless policy independently requires otherwise.

### Fixture B — JWT verification removal

Baseline:

```text
verified authentication middleware protects sensitive routes
```

PR:

```text
cryptographic verify -> decode-only claims parsing
```

Expected:

- security-control change recognized;
- candidate generated from changed file;
- cached application context used for impact;
- full dataflow not required when security-boundary proof is complete;
- independent verifier supports authentication-bypass capability;
- changed middleware is the root-cause evidence;
- related unchanged routes are contextual evidence;
- default High/Critical policy blocks.

### Fixture C — cross-file proof required

Expected:

- L1 produces hypothesis;
- verifier requests exact callers/controls/flow;
- L2 loads only requested context;
- no verified finding if required evidence remains missing.

### Fixture D — existing vulnerability outside PR

Expected:

- issue may be visible from baseline;
- classified `EXISTING`;
- does not block under default new-risk policy.

## 18. Performance objective for the 10-org release

Optimize for warm-baseline PRs.

Targets for ordinary small/medium PRs:

```text
baseline/context load     seconds
changed-file analysis     seconds to tens of seconds
L1 contextual review      ~1–2 minutes target p50
L2 only when needed       additional time
```

Measure:

- changed files vs files loaded;
- changed symbols vs symbols expanded;
- ApplicationContext reuse rate;
- Security IR reuse rate;
- candidate count;
- expansion requests per candidate;
- model calls/tokens per PR;
- verification latency;
- total PR latency.

The objective is not to minimize reasoning quality. It is to avoid paying for context that was already known or not needed for the candidate.

## 19. Implementation priority update

Before QC, prioritize in this order:

1. deterministic `ChangeRelevance`;
2. cached `ApplicationContext` persistence/load;
3. changed-file L1 review contract;
4. lean candidate schema;
5. candidate-specific context broker;
6. verifier evidence-role model;
7. optional explicit flow requests;
8. baseline classification;
9. deterministic policy;
10. SCM publication;
11. live timeline/counters;
12. performance and privacy tests.

This v2 plan should guide PR/MR implementation while the existing 10-organization infrastructure/QC plan remains the deployment and release checklist.